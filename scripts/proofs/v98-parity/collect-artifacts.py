#!/usr/bin/env python3
"""Bind image bytes without starting a container or importing OpenClaw."""
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import subprocess
import sys
import tarfile

CONTRACT = json.loads(Path(__file__).with_name("contract.json").read_text())
PUBLISHER_FILES = (
    "README.md", "index.mjs", "openclaw.plugin.json", "package.json",
    "src/controller.mjs", "src/http.mjs", "src/runtime-pin-transition.mjs", "src/runtime.mjs",
)


def digest_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path, value):
    # The output directory belongs only to this one workflow run/attempt.
    with Path(path).open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def git(source, *args):
    return subprocess.check_output(["git", "-C", str(source), *args], text=True).strip()


def verify_source(source):
    if git(source, "rev-parse", "HEAD") != CONTRACT["sourceCommit"]:
        raise ValueError("qualified source commit changed")
    if git(source, "rev-parse", "HEAD^{tree}") != CONTRACT["sourceTree"]:
        raise ValueError("qualified source tree changed")
    if git(source, "status", "--porcelain=v1"):
        raise ValueError("qualified source checkout is dirty")
    return {
        "commit": CONTRACT["sourceCommit"], "tree": CONTRACT["sourceTree"],
        "dockerfileSha256": digest_file(source / "Dockerfile"),
        "lockSha256": digest_file(source / "pnpm-lock.yaml"),
        "packageSha256": digest_file(source / "package.json"),
    }


def clean_name(value):
    if "\x00" in value or value.startswith("/") or ".." in PurePosixPath(value).parts:
        raise ValueError("unsafe image archive path")
    return str(PurePosixPath(value))


def inventory_filesystem(archive):
    """Hash Docker's flattened filesystem. Never extract its paths on the host."""
    entries = {}
    special_bytes = {}
    total = 0
    with tarfile.open(archive, "r:") as stream:
        for member in stream:
            name = clean_name(member.name)
            if name in entries:
                raise ValueError("duplicate image filesystem path: " + name)
            row = {"path": "/" + name, "mode": oct(member.mode & 0o7777)}
            if member.isfile():
                total += member.size
                if total > 8 * 1024 ** 3:
                    raise ValueError("image expanded-file budget exceeded")
                digest = hashlib.sha256()
                keep = (
                    name == "app/dist/build-info.json"
                    or re.fullmatch(r"app/dist/openclaw-state-db-[A-Za-z0-9_-]{8}\.mjs", name)
                )
                captured = bytearray()
                with stream.extractfile(member) as contents:
                    for block in iter(lambda: contents.read(1024 * 1024), b""):
                        digest.update(block)
                        if keep:
                            captured.extend(block)
                            if len(captured) > 8 * 1024 ** 2:
                                raise ValueError("compiled entry metadata budget exceeded")
                row.update(type="file", bytes=member.size, sha256=digest.hexdigest())
                if keep:
                    special_bytes[name] = bytes(captured)
            elif member.isdir():
                row.update(type="directory")
            elif member.issym() or member.islnk():
                if "\x00" in member.linkname:
                    raise ValueError("invalid image link")
                row.update(type="symlink" if member.issym() else "hardlink", target=member.linkname)
            else:
                # Device nodes in a base filesystem are recorded, never recreated.
                row.update(type="special", tarType=member.type.decode("ascii", errors="replace"))
            entries[name] = row
    return entries, special_bytes, total


def resolve_file(entries, name):
    seen = set()
    for _ in range(64):
        if name in seen:
            raise ValueError("cyclic image link")
        seen.add(name)
        row = entries.get(name)
        if not row:
            raise ValueError("required image file missing: " + name)
        if row["type"] == "file":
            return row
        if row["type"] not in ("symlink", "hardlink"):
            raise ValueError("required image path is not a file: " + name)
        target = row["target"]
        joined = target if row["type"] == "hardlink" else posixpath.join(posixpath.dirname(name), target)
        name = posixpath.normpath("/" + joined).lstrip("/") if not target.startswith("/") else posixpath.normpath(target).lstrip("/")
    raise ValueError("image link depth exceeded")


def validate_saved_image(archive, image_id):
    """Join Docker save config and every layer to the inspected config identity."""
    with tarfile.open(archive, "r:gz") as stream:
        members = {}
        for member in stream:
            name = clean_name(member.name)
            if name in members:
                raise ValueError("duplicate saved-image path")
            members[name] = member

        def read_small(name):
            member = members.get(clean_name(name))
            if not member or not member.isfile() or member.size > 1024 * 1024:
                raise ValueError("saved-image identity file missing or oversized")
            return stream.extractfile(member).read()

        manifest = json.loads(read_small("manifest.json"))
        if not isinstance(manifest, list) or len(manifest) != 1:
            raise ValueError("expected exactly one saved image")
        config_bytes = read_small(manifest[0]["Config"])
        if "sha256:" + hashlib.sha256(config_bytes).hexdigest() != image_id:
            raise ValueError("saved-image config identity mismatch")
        config = json.loads(config_bytes)
        layers = manifest[0]["Layers"]
        diff_ids = config.get("rootfs", {}).get("diff_ids", [])
        if not layers or len(layers) != len(diff_ids):
            raise ValueError("saved-image layer closure incomplete")
        measured = []
        expanded = 0
        for name, expected in zip(layers, diff_ids):
            member = members.get(clean_name(name))
            if not member or not member.isfile():
                raise ValueError("saved-image layer missing")
            contents = stream.extractfile(member)
            compressed = contents.read(2) == b"\x1f\x8b"
            contents.seek(0)
            digest = hashlib.sha256()
            with gzip.GzipFile(fileobj=contents) if compressed else contents as payload:
                for block in iter(lambda: payload.read(1024 * 1024), b""):
                    expanded += len(block)
                    if expanded > 32 * 1024 ** 3:
                        raise ValueError("saved-image expanded-layer budget exceeded")
                    digest.update(block)
            actual = "sha256:" + digest.hexdigest()
            if actual != expected:
                raise ValueError("saved-image layer identity mismatch")
            measured.append({"archivePath": name, "diffId": actual})
        return measured


def validate_image(inspect, entries, special_bytes, source):
    if len(inspect) != 1:
        raise ValueError("expected exactly one image identity")
    image = inspect[0]
    if image.get("Os") != "linux" or image.get("Architecture") != "amd64":
        raise ValueError("wrong synthetic image platform")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image.get("Id", "")):
        raise ValueError("image config digest missing")
    if image.get("Config", {}).get("Labels", {}).get("org.opencontainers.image.revision") != CONTRACT["sourceCommit"]:
        raise ValueError("image source label mismatch")
    build = json.loads(special_bytes.get("app/dist/build-info.json", b"null"))
    if not isinstance(build, dict) or build.get("commit") != CONTRACT["sourceCommit"] or build.get("version") != CONTRACT["version"]:
        raise ValueError("compiled build-info source mismatch")
    if not build.get("buildId", "").startswith(CONTRACT["version"] + "-" + CONTRACT["sourceCommit"][:12] + "-"):
        raise ValueError("compiled build ID mismatch")
    doctor = [name for name, value in special_bytes.items()
              if name != "app/dist/build-info.json" and b"prepareOpenClawStateDatabaseSchema" in value]
    if len(doctor) != 1:
        raise ValueError("expected one compiled Doctor entry candidate")
    publisher = {}
    for name in PUBLISHER_FILES:
        expected = digest_file(source / "scripts/docker/runtime-plugins/mergeguez-pr-lifecycle" / name)
        row = resolve_file(entries, "app/runtime-plugins/mergeguez-pr-lifecycle/" + name)
        if row["sha256"] != expected:
            raise ValueError("packaged publisher bytes changed: " + name)
        publisher[name] = expected
    required = CONTRACT["artifactPreparation"]["requiredCompiledEntries"]
    compiled = {name: resolve_file(entries, name) for name in required["paths"]}
    return {
        "imageConfigId": image["Id"], "platform": CONTRACT["platform"],
        "buildInfo": build, "doctorEntryCandidate": entries[doctor[0]],
        "doctorExportLoadedOrExecuted": False,
        "nodeExecutable": resolve_file(entries, "usr/local/bin/node"),
        "publisherFiles": publisher,
        "registeredCompiledEntries": compiled,
        "compiledEntriesLoadedOrExecuted": False,
    }


def stage_retention(out, stage, *, image_limit=None, evidence_limit=None, file_limit=None):
    """Upload only a sealed image and bounded evidence; never a filesystem tar."""
    limits = CONTRACT["artifactPreparation"]
    image_limit = limits["imageArchiveLimitBytes"] if image_limit is None else image_limit
    evidence_limit = limits["evidenceLimitBytes"] if evidence_limit is None else evidence_limit
    file_limit = limits["evidenceFileLimitBytes"] if file_limit is None else file_limit
    stage.mkdir(mode=0o700)
    allowed = {
        "preflight.json", "docker-version.txt", "build.log", "image-id.txt",
        "image-inspect.json", "image-filesystem-manifest.json",
        "artifact-receipt.json", "collector-failure.json",
    }
    receipt = None
    receipt_path = out / "artifact-receipt.json"
    if receipt_path.is_file() and not receipt_path.is_symlink() and receipt_path.stat().st_size <= file_limit:
        try:
            receipt = json.loads(receipt_path.read_text())
        except (ValueError, UnicodeError):
            pass
    rows = []
    evidence_bytes = 0
    image_bytes = 0
    outputs = sorted(out.iterdir()) if out.is_dir() else []
    if len(outputs) > 32:
        raise ValueError("unexpected output count exceeds retention evidence budget")
    for path in outputs:
        row = {"name": path.name, "retained": False}
        if path.is_symlink() or not path.is_file():
            row["disposition"] = "non-regular output omitted; target not read"
            rows.append(row)
            continue
        size = path.stat().st_size
        digest = digest_file(path)
        row.update(bytes=size, sha256=digest)
        if path.name == "image.tar.gz":
            sealed = (
                isinstance(receipt, dict)
                and receipt.get("source", {}).get("commit") == CONTRACT["sourceCommit"]
                and receipt.get("source", {}).get("tree") == CONTRACT["sourceTree"]
                and receipt.get("imageArchiveSha256") == digest
                and receipt.get("imageArchiveBytes") == size
                and receipt.get("fixturePhases") == "NEVER_RUN"
                and not (out / "collector-failure.json").exists()
            )
            admitted = size <= image_limit and sealed
            row["disposition"] = "sealed image admitted" if admitted else "image omitted: unsealed, failed or over budget; bytes not retained"
        elif path.name not in allowed:
            admitted = False
            row["disposition"] = "redundant filesystem export or unknown payload omitted; bytes not retained"
        else:
            admitted = size <= file_limit and evidence_bytes + size <= evidence_limit
            row["disposition"] = "bounded evidence admitted" if admitted else "evidence omitted: per-file or aggregate budget; bytes not retained"
            if not admitted and path.name == "build.log":
                # Preserve bounded tail evidence, while identifying the omitted full log.
                tail_size = min(size, file_limit, max(0, evidence_limit - evidence_bytes))
                if tail_size:
                    with path.open("rb") as contents:
                        contents.seek(-tail_size, os.SEEK_END)
                        tail = contents.read(tail_size)
                    (stage / "build.log.tail").write_bytes(tail)
                    row.update(retainedTailBytes=len(tail), retainedTailSha256=hashlib.sha256(tail).hexdigest())
                    evidence_bytes += len(tail)
        if admitted:
            destination = stage / path.name
            try:
                shutil.copyfile(path, destination)
                if destination.stat().st_size != size or digest_file(destination) != digest:
                    raise ValueError("artifact output changed during retention staging")
            except Exception:
                # An always-run uploader must never retain a partial admitted file.
                if destination.exists():
                    destination.unlink()
                raise
            row["retained"] = True
            if path.name == "image.tar.gz":
                image_bytes += size
            else:
                evidence_bytes += size
        rows.append(row)
    write_json(stage / "retention-receipt.json", {
        "schema": "openclaw-v98-artifact-retention/v1", "sourceCommit": CONTRACT["sourceCommit"],
        "outputDirectoryPresent": out.is_dir(), "imageLimitBytes": image_limit,
        "evidenceLimitBytes": evidence_limit, "evidenceFileLimitBytes": file_limit,
        "retainedImageBytes": image_bytes, "retainedEvidenceBytes": evidence_bytes,
        "retentionReceiptBudgetBytes": 65536,
        "omittedPayloadCustodyClaimed": False, "fixtureExecuted": False, "files": rows,
    })
    if (stage / "retention-receipt.json").stat().st_size > 65536:
        raise ValueError("retention receipt budget exceeded")


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "retain":
        stage_retention(Path(sys.argv[2]).resolve(), Path(sys.argv[3]).resolve())
        return
    if len(sys.argv) != 4 or sys.argv[1] not in ("preflight", "seal"):
        raise ValueError("usage: collect-artifacts.py preflight|seal SOURCE OUTPUT; retain OUTPUT STAGE")
    mode, source, out = sys.argv[1], Path(sys.argv[2]).resolve(), Path(sys.argv[3]).resolve()
    source_identity = verify_source(source)
    if mode == "preflight":
        free = shutil.disk_usage(out).free
        write_json(out / "preflight.json", {
            "source": source_identity, "toolingSha": os.environ.get("GITHUB_SHA"),
            "runId": os.environ.get("GITHUB_RUN_ID"), "runAttempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "observedFreeDiskBytes": free, "fixtureExecuted": False,
        })
        if free < CONTRACT["artifactPreparation"]["minimumFreeDiskBytes"]:
            raise ValueError("artifact build disk admission refused")
        return
    image_archive = out / "image.tar.gz"
    if image_archive.stat().st_size > CONTRACT["artifactPreparation"]["imageArchiveLimitBytes"]:
        raise ValueError("image artifact archive budget exceeded")
    entries, special, total = inventory_filesystem(out / "filesystem.tar")
    image = validate_image(json.loads((out / "image-inspect.json").read_text()), entries, special, source)
    if (out / "image-id.txt").read_text().strip() != image["imageConfigId"]:
        raise ValueError("build output image identity mismatch")
    layers = validate_saved_image(image_archive, image["imageConfigId"])
    write_json(out / "image-filesystem-manifest.json", {
        "schema": "openclaw-image-filesystem-inventory/v1", "entries": sorted(entries.values(), key=lambda row: row["path"]),
        "regularFileBytes": total, "minimalImportClosureClaimed": False,
    })
    write_json(out / "artifact-receipt.json", {
        "schema": "openclaw-v98-prepared-image/v1", "recordedAtUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": source_identity, "toolingSha": os.environ.get("GITHUB_SHA"),
        "runId": os.environ.get("GITHUB_RUN_ID"), "runAttempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "image": image, "savedImageLayers": layers, "imageArchiveSha256": digest_file(image_archive),
        "imageArchiveBytes": image_archive.stat().st_size,
        "filesystemManifestSha256": digest_file(out / "image-filesystem-manifest.json"),
        "flattenedFilesystemTarSha256": digest_file(out / "filesystem.tar"),
        "publication": "Actions artifact only", "defaultEntrypointStarted": False,
        "fixturePhases": "NEVER_RUN", "runtimeAdmission": "BLOCKED pending exact closure and kernel policy review",
    })
    # Retain the image plus complete inventory; avoid uploading a second image copy.
    # This tar contains only task-owned image export bytes, never failed fixture data.
    (out / "filesystem.tar").unlink()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        if len(sys.argv) == 4 and Path(sys.argv[3]).is_dir():
            failure = Path(sys.argv[3]) / "collector-failure.json"
            if not failure.exists():
                write_json(failure, {"phase": sys.argv[1], "error": str(error), "fixtureExecuted": False})
        raise

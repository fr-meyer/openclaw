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
DOCTOR_FAMILY = re.compile(r"app/dist/openclaw-state-db-[A-Za-z0-9_-]+\.mjs")
DOCTOR_API = "prepareOpenClawStateDatabaseSchema"
MANIFEST_NAME = "image-filesystem-manifest.json.gz"
LAYOUT_NAME = "layout-assessment.json"
LAYOUT_LIMITS = CONTRACT["artifactPreparation"]["layoutMetadata"]


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
    captured_total = 0
    doctor_count = 0
    with tarfile.open(archive, "r:") as stream:
        for member in stream:
            name = clean_name(member.name)
            if len(name.encode()) > 4096 or len(entries) >= LAYOUT_LIMITS["maximumInventoryEntries"]:
                raise ValueError("image inventory path/count budget exceeded")
            if name in entries:
                raise ValueError("duplicate image filesystem path: " + name)
            row = {"path": "/" + name, "mode": oct(member.mode & 0o7777)}
            doctor = bool(DOCTOR_FAMILY.fullmatch(name))
            if doctor:
                doctor_count += 1
                if doctor_count > LAYOUT_LIMITS["maximumDoctorFamilyEntries"]:
                    raise ValueError("Doctor family count budget exceeded: " + str(doctor_count))
            if member.isfile():
                total += member.size
                if total > 8 * 1024 ** 3:
                    raise ValueError("image expanded-file budget exceeded")
                digest = hashlib.sha256()
                keep = name == "app/dist/build-info.json" or doctor
                if keep:
                    captured_total += member.size
                    if member.size > 8 * 1024 ** 2 or captured_total > LAYOUT_LIMITS["capturedModuleLimitBytes"]:
                        raise ValueError("compiled entry metadata budget exceeded: " + name)
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


def terminal_named_exports(value):
    """Read Rolldown's terminal named export table, without importing JavaScript.

    The pinned non-minified build emits one final `export { local as public }`
    table. Other syntax is unsupported and fails closed; this is not a JS parser
    or an assertion that a module can be loaded with its transitive dependencies.
    """
    text = value.decode("utf-8")
    table = re.search(r"(?:^|\n)export\s*\{([^{}]*)\}\s*;?\s*\Z", text)
    if not table or re.search(r"(?m)^export\b", text[:table.start()]):
        raise ValueError("unsupported compiled terminal export table")
    exports = []
    items = table.group(1).split(",")
    for index, item in enumerate(items):
        item = item.strip()
        if not item:
            if index == len(items) - 1:
                continue
            raise ValueError("empty compiled export specifier")
        specifier = re.fullmatch(r"([A-Za-z_$][A-Za-z0-9_$]{0,255})(?:\s+as\s+([A-Za-z_$][A-Za-z0-9_$]{0,255}))?", item)
        if not specifier:
            raise ValueError("unsupported compiled export specifier")
        name = specifier.group(2) or specifier.group(1)
        if name in exports:
            raise ValueError("duplicate compiled exported name")
        exports.append(name)
        if len(exports) > 256:
            raise ValueError("compiled exported-name budget exceeded")
    return exports


def assess_layout(entries, special):
    """Keep every selector outcome, even when Doctor selection prevents sealing."""
    family = []
    candidates = []
    for name in sorted(name for name in entries if DOCTOR_FAMILY.fullmatch(name)):
        row = entries[name]
        observed = {"path": "/" + name, "type": row["type"],
                    "sha256": row.get("sha256"), "bytes": row.get("bytes"),
                    "exportsRequiredApi": False}
        try:
            if row["type"] != "file" or name not in special:
                raise ValueError("Doctor family entry is not a captured regular file")
            if hashlib.sha256(special[name]).hexdigest() != row["sha256"]:
                raise ValueError("captured Doctor bytes do not match inventory")
            exported = terminal_named_exports(special[name])
            observed["exportedNames"] = exported
            observed["exportsRequiredApi"] = DOCTOR_API in exported
            if observed["exportsRequiredApi"]:
                candidates.append(name)
        except (ValueError, UnicodeError) as error:
            observed["error"] = str(error)
        family.append(observed)
    required = CONTRACT["artifactPreparation"]["requiredCompiledEntries"]
    compiled = []
    for name in required["paths"]:
        item = {"requestedPath": name}
        try:
            item.update(status="PRESENT", resolvedFile=resolve_file(entries, name))
        except ValueError as error:
            item.update(status="MISSING_OR_INVALID", error=str(error))
        compiled.append(item)
    failures = [row for row in compiled if row["status"] != "PRESENT"]
    return {
        "schema": "openclaw-v98-image-layout-assessment/v1",
        "sourceCommitExpected": CONTRACT["sourceCommit"],
        "admission": "NOT_ADMITTED; selector metadata only",
        "fixtureExecuted": False, "compiledEntriesLoadedOrExecuted": False,
        "minimalImportClosureClaimed": False,
        "doctor": {"requiredExport": DOCTOR_API, "selection": "exact terminal exported name",
                   "familyEntries": family, "candidateCount": len(candidates),
                   "candidatePaths": candidates,
                   "selectedPath": candidates[0] if len(candidates) == 1 else None,
                   "parseErrorCount": sum("error" in row for row in family)},
        "requiredCompiledEntries": {"expectedCount": len(compiled),
                                    "registeredCoreEntryCount": required["registeredCoreEntryCount"],
                                    "normalizationExportCount": required["normalizationExportCount"],
                                    "presentCount": len(compiled) - len(failures),
                                    "failureCount": len(failures), "entries": compiled},
    }


def write_layout_evidence(out, entries, special, total):
    assessment = assess_layout(entries, special)
    write_json(out / LAYOUT_NAME, assessment)
    manifest = {"schema": "openclaw-image-filesystem-inventory/v1",
                "entries": sorted(entries.values(), key=lambda row: row["path"]),
                "regularFileBytes": total, "minimalImportClosureClaimed": False,
                "admission": "NOT_ADMITTED; inventory only", "fixtureExecuted": False}
    path = out / MANIFEST_NAME
    raw = path.open("xb")
    try:
        expanded = 0
        with raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            for chunk in json.JSONEncoder(separators=(",", ":")).iterencode(manifest):
                value = chunk.encode()
                expanded += len(value)
                if expanded > LAYOUT_LIMITS["expandedManifestLimitBytes"]:
                    raise ValueError("expanded inventory metadata budget exceeded")
                compressed.write(value)
        if path.stat().st_size > CONTRACT["artifactPreparation"]["evidenceFileLimitBytes"]:
            raise ValueError("compressed inventory evidence budget exceeded")
    except Exception:
        # Never upload a partial or over-budget inventory as complete evidence.
        if path.exists():
            path.unlink()
        raise
    return assessment


def resolve_file(entries, name):
    seen = set()
    for _ in range(64):
        if name in seen:
            raise ValueError("cyclic image link")
        seen.add(name)
        parts = name.split("/")
        for count in range(1, len(parts)):
            parent = entries.get("/".join(parts[:count]))
            if parent and parent["type"] != "directory":
                raise ValueError("required image file has unsupported parent: " + name)
        row = entries.get(name)
        if not row:
            raise ValueError("required image file missing: " + name)
        if row["type"] == "file":
            return row
        if row["type"] not in ("symlink", "hardlink"):
            raise ValueError("required image path is not a file: " + name)
        target = row["target"]
        joined = target if row["type"] == "hardlink" else posixpath.join(posixpath.dirname(name), target)
        # Validate traversal before collapsing dot components. A lexical
        # normalization can hide traversal through a regular or missing parent.
        resolved = []
        for component in joined.split("/"):
            if not component:
                continue
            if resolved:
                prefix = "/".join(resolved)
                parent = entries.get(prefix)
                if parent and parent["type"] != "directory":
                    raise ValueError("required image file has unsupported parent: " + prefix)
                if not parent and not any(path.startswith(prefix + "/") for path in entries):
                    raise ValueError("required image file has missing parent: " + prefix)
            if component == ".":
                continue
            if component == "..":
                if resolved:
                    resolved.pop()
            else:
                resolved.append(component)
        name = "/".join(resolved)
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
    layout = assess_layout(entries, special_bytes)
    doctor = layout["doctor"]
    if doctor["parseErrorCount"] or doctor["candidateCount"] != 1:
        raise ValueError("expected one exact named Doctor export: candidates="
                         + str(doctor["candidateCount"]) + ", parseErrors="
                         + str(doctor["parseErrorCount"]) + "; see " + LAYOUT_NAME)
    missing = [row for row in layout["requiredCompiledEntries"]["entries"] if row["status"] != "PRESENT"]
    if missing:
        raise ValueError("required compiled entry checks failed: " + str(len(missing))
                         + "; " + missing[0]["error"] + "; see " + LAYOUT_NAME)
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
        "buildInfo": build, "doctorEntryCandidate": entries[doctor["selectedPath"]],
        "doctorRequiredExport": DOCTOR_API,
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
        "image-inspect.json", MANIFEST_NAME, LAYOUT_NAME,
        "artifact-receipt.json", "collector-failure.json",
    }
    required_evidence = {"preflight.json", "image-id.txt", "image-inspect.json",
                         "artifact-receipt.json", MANIFEST_NAME, LAYOUT_NAME}
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
    retained_hashes = {}
    # Core identity/layout evidence gets its budget before logs. Admit image last
    # so an omitted required manifest can never accompany a retained image.
    outputs = sorted(out.iterdir(), key=lambda path: (
        2 if path.name == "image.tar.gz" else 0 if path.name in required_evidence else 1,
        path.name)) if out.is_dir() else []
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
                and required_evidence <= retained_hashes.keys()
                and receipt.get("filesystemManifestPath") == MANIFEST_NAME
                and receipt.get("filesystemManifestEncoding") == "gzip-json"
                and receipt.get("filesystemManifestSha256") == retained_hashes.get(MANIFEST_NAME)
                and receipt.get("layoutAssessmentSha256") == retained_hashes.get(LAYOUT_NAME)
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
            retained_hashes[path.name] = digest
            if path.name == "image.tar.gz":
                image_bytes += size
            else:
                evidence_bytes += size
        rows.append(row)
    try:
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
    except Exception:
        if (stage / "image.tar.gz").exists():
            (stage / "image.tar.gz").unlink()
        raise


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
    # Write non-executable layout evidence before any image/selector admission.
    # A Doctor failure must preserve both candidates and all 79 path outcomes.
    write_layout_evidence(out, entries, special, total)
    image = validate_image(json.loads((out / "image-inspect.json").read_text()), entries, special, source)
    if (out / "image-id.txt").read_text().strip() != image["imageConfigId"]:
        raise ValueError("build output image identity mismatch")
    layers = validate_saved_image(image_archive, image["imageConfigId"])
    write_json(out / "artifact-receipt.json", {
        "schema": "openclaw-v98-prepared-image/v1", "recordedAtUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": source_identity, "toolingSha": os.environ.get("GITHUB_SHA"),
        "runId": os.environ.get("GITHUB_RUN_ID"), "runAttempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "image": image, "savedImageLayers": layers, "imageArchiveSha256": digest_file(image_archive),
        "imageArchiveBytes": image_archive.stat().st_size,
        "filesystemManifestPath": MANIFEST_NAME, "filesystemManifestEncoding": "gzip-json",
        "filesystemManifestSha256": digest_file(out / MANIFEST_NAME),
        "layoutAssessmentSha256": digest_file(out / LAYOUT_NAME),
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

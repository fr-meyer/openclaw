#!/usr/bin/env python3
"""Consume one exact Actions artifact using stdlib; never start/import its runtime."""
import argparse
import bisect
import datetime
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import sys
import tarfile
import types
import zipfile

SOURCE = "bc8b82b2cbbbb81f5abe6093e1bb3af4f1f70cdf"
TREE = "ba825f670dc5ba943f7893cb267225d1f68d3110"
COLLECTOR_SHA = "03b9a4627af452e6ad16361f3bcd9dbc3e55327661a11d500bc2c387089572d7"
CONTRACT_SHA = "56f06026d785dadda5bd42854dc80b8afe9780dcbaf0f41762f5e2c30ec3fb6d"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def json_bytes(value):
    def unique(pairs):
        result = {}
        for key, item in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = item
        return result

    def invalid_constant(_):
        raise ValueError("non-finite JSON number")

    return json.loads(value, object_pairs_hook=unique, parse_constant=invalid_constant)


def read_json(path, limit=8 * 1024 ** 2):
    require(path.is_file() and not path.is_symlink(), "non-regular JSON input")
    with path.open("rb") as stream:
        value = stream.read(limit + 1)
    require(len(value) <= limit, "JSON input budget exceeded")
    return json_bytes(value)


def load_collector():
    path = Path(__file__).with_name("collect-artifacts.py")
    code = path.read_bytes()
    contract_bytes = path.with_name("contract.json").read_bytes()
    require(hashlib.sha256(code).hexdigest() == COLLECTOR_SHA, "reviewed collector hash changed")
    require(hashlib.sha256(contract_bytes).hexdigest() == CONTRACT_SHA, "reviewed contract hash changed")
    module = types.ModuleType("reviewed_v98_collector")
    module.__file__ = str(path)
    # Compile the reviewed bytes directly; never accept cached .pyc substitutions.
    exec(compile(code, str(path), "exec"), module.__dict__)
    require(module.CONTRACT == json_bytes(contract_bytes), "contract changed during trusted collector load")
    return module


def positive(value):
    parsed = int(value)
    require(parsed > 0, "run/artifact identity must be positive")
    return parsed


def identity_fields(row, run_id, attempt, tooling):
    require(row.get("toolingSha") == tooling, "evidence tooling commit mismatch")
    require(str(row.get("runId")) == str(run_id), "evidence run id mismatch")
    require(str(row.get("runAttempt")) == str(attempt), "evidence run attempt mismatch")


def same_json(left, right):
    # Python considers False == 0 and True == 1; evidence types must agree too.
    return json.dumps(left, sort_keys=True, separators=(",", ":")) == json.dumps(right, sort_keys=True, separators=(",", ":"))


def read_manifest(path, collector):
    maximum = collector.LAYOUT_LIMITS["expandedManifestLimitBytes"]
    with gzip.open(path, "rb") as stream:
        value = stream.read(maximum + 1)
    require(len(value) <= maximum, "gzip manifest expanded budget exceeded")
    manifest = json_bytes(value)
    require(manifest.get("schema") == "openclaw-image-filesystem-inventory/v1", "inventory schema mismatch")
    require(manifest.get("minimalImportClosureClaimed") is False
            and manifest.get("fixtureExecuted") is False
            and manifest.get("admission") == "NOT_ADMITTED; inventory only", "inventory execution/admission claim changed")
    rows = manifest.get("entries")
    require(isinstance(rows, list) and len(rows) <= collector.LAYOUT_LIMITS["maximumInventoryEntries"], "inventory count budget exceeded")
    entries = {}
    regular_bytes = 0
    for row in rows:
        path = row.get("path", "")
        require(isinstance(path, str) and path.startswith("/") and len(path.encode()) <= 4097, "invalid inventory path")
        name = collector.clean_name(path[1:])
        require(path == "/" + name and name not in entries, "duplicate or noncanonical inventory path")
        require(row.get("type") in ("file", "directory", "symlink", "hardlink", "special"), "invalid inventory type")
        require(re.fullmatch(r"0o[0-7]{1,4}", row.get("mode", "")), "invalid inventory mode")
        if row["type"] == "file":
            require(type(row.get("bytes")) is int and row["bytes"] >= 0
                    and re.fullmatch(r"[a-f0-9]{64}", row.get("sha256", "")), "invalid inventory file identity")
            regular_bytes += row["bytes"]
        elif row["type"] in ("symlink", "hardlink"):
            require(isinstance(row.get("target"), str) and "\x00" not in row["target"], "invalid inventory link")
        entries[name] = row
    require(regular_bytes == manifest.get("regularFileBytes") and regular_bytes <= 8 * 1024 ** 3, "inventory byte total mismatch")
    return entries


class ArchiveReader:
    """Bound tar metadata reads and decompressed offsets; optionally hash linearly."""
    def __init__(self, stream, *, hashed=False):
        self.stream = stream
        self.position = 0
        self.hash = hashlib.sha256() if hashed else None

    def read(self, amount):
        require(0 <= amount <= 8 * 1024 ** 2, "tar metadata read budget exceeded")
        value = self.stream.read(amount)
        self.position += len(value)
        require(self.position <= 32 * 1024 ** 3, "expanded tar budget exceeded")
        if self.hash is not None:
            self.hash.update(value)
        return value

    def tell(self):
        return self.position

    def seekable(self):
        return True

    def seek(self, offset, whence=0):
        require(whence in (0, 1), "unsupported tar seek")
        target = offset + (self.position if whence == 1 else 0)
        require(0 <= target <= 32 * 1024 ** 3, "expanded tar seek budget exceeded")
        if self.hash is None:
            self.position = self.stream.seek(target)
        else:
            require(target >= self.position, "unsupported backward layer seek")
            while self.position < target:
                require(self.read(min(target - self.position, 1024 * 1024)), "truncated saved layer seek")
        return self.position


def saved_identity_files(archive, image_id, collector):
    """Read layer file identities; apply whiteouts/overwrites without extraction.

    Only content joins for required identity files are claimed. This does not
    reconstruct or qualify a runnable filesystem or a transitive import graph.
    """
    layers = []
    entries = {}
    special = {}
    expanded_files = 0
    with gzip.open(archive, "rb") as saved_payload, tarfile.open(fileobj=ArchiveReader(saved_payload), mode="r:") as saved:
        members = {}
        saved_bytes = 0
        for row in saved:
            name = collector.clean_name(row.name)
            require(name not in members and len(name.encode()) <= 4096, "duplicate/invalid saved image archive path")
            require(len(members) < 4096, "saved archive member count budget exceeded")
            require(row.sparse is None, "unsupported sparse saved image payload")
            if row.isfile():
                saved_bytes += row.size
                require(saved_bytes <= 32 * 1024 ** 3, "saved archive payload budget exceeded")
            members[name] = row
        def saved_json(name):
            row = members[collector.clean_name(name)]
            require(row.isfile() and row.size <= 1024 * 1024, "saved config/manifest metadata budget exceeded")
            with saved.extractfile(row) as value:
                return json_bytes(value.read())

        manifest = saved_json("manifest.json")
        require(isinstance(manifest, list) and len(manifest) == 1, "expected exactly one saved image")
        config_row = members[collector.clean_name(manifest[0]["Config"])]
        require(config_row.isfile() and config_row.size <= 1024 * 1024, "saved config budget exceeded")
        with saved.extractfile(config_row) as value:
            config_bytes = value.read()
        require("sha256:" + hashlib.sha256(config_bytes).hexdigest() == image_id, "saved image config identity mismatch")
        config = json_bytes(config_bytes)
        require(config.get("os") == "linux" and config.get("architecture") == "amd64"
                and config.get("config", {}).get("Labels", {}).get("org.opencontainers.image.revision") == SOURCE,
                "saved config platform/source mismatch")
        paths = manifest[0]["Layers"]
        diff_ids = config.get("rootfs", {}).get("diff_ids", [])
        require(isinstance(paths, list) and isinstance(diff_ids, list) and 0 < len(paths) == len(diff_ids) <= 256,
                "saved image layer closure incomplete or over budget")
        expanded_layers = 0
        for path, expected in zip(paths, diff_ids):
            require(re.fullmatch(r"sha256:[a-f0-9]{64}", expected), "invalid saved layer digest")
            layer_row = members[collector.clean_name(path)]
            require(layer_row.isfile() and layer_row.sparse is None, "saved layer missing or unsupported")
            changes = {}
            captured = {}
            removals = []
            capture_bytes = 0
            doctor_count = 0
            with saved.extractfile(layer_row) as payload:
                compressed = payload.read(2) == b"\x1f\x8b"
                payload.seek(0)
                with gzip.GzipFile(fileobj=payload) if compressed else payload as decoded:
                    reader = ArchiveReader(decoded, hashed=True)
                    with tarfile.open(fileobj=reader, mode="r:") as contents:
                        for member in contents:
                            require(member.sparse is None, "unsupported sparse saved layer payload")
                            name = collector.clean_name(member.name)
                            require(len(name.encode()) <= 4096 and len(changes) < collector.LAYOUT_LIMITS["maximumInventoryEntries"], "saved layer path/count budget exceeded")
                            require(name not in changes, "duplicate saved layer filesystem path")
                            doctor = bool(collector.DOCTOR_FAMILY.fullmatch(name))
                            doctor_count += int(doctor)
                            require(doctor_count <= collector.LAYOUT_LIMITS["maximumDoctorFamilyEntries"], "saved layer Doctor family count budget exceeded")
                            base = name.rsplit("/", 1)[-1]
                            parent = name.rsplit("/", 1)[0] if "/" in name else ""
                            if base.startswith(".wh."):
                                require(member.isfile() and member.size == 0, "unsupported saved layer whiteout")
                                if base == ".wh..wh..opq":
                                    removals.append((parent, True))
                                else:
                                    require(len(base) > 4, "invalid saved layer whiteout")
                                    target = (parent + "/" if parent else "") + base[4:]
                                    removals.append((target, False))
                                changes[name] = {"type": "whiteout"}
                                continue
                            row = {"path": "/" + name, "mode": oct(member.mode & 0o7777)}
                            if member.isfile():
                                expanded_files += member.size
                                require(expanded_files <= 32 * 1024 ** 3, "saved layer file budget exceeded")
                                keep = name == "app/dist/build-info.json" or doctor
                                require(not keep or member.size <= 8 * 1024 ** 2, "saved identity capture budget exceeded")
                                if keep:
                                    capture_bytes += member.size
                                    require(capture_bytes <= collector.LAYOUT_LIMITS["capturedModuleLimitBytes"], "saved layer identity capture aggregate exceeded")
                                value = bytearray()
                                hashed = hashlib.sha256()
                                measured = 0
                                with contents.extractfile(member) as file:
                                    for block in iter(lambda: file.read(1024 * 1024), b""):
                                        hashed.update(block)
                                        measured += len(block)
                                        if keep:
                                            value.extend(block)
                                require(measured == member.size, "saved layer file truncated")
                                row.update(type="file", bytes=measured, sha256=hashed.hexdigest())
                                if keep:
                                    captured[name] = bytes(value)
                            elif member.isdir():
                                row.update(type="directory")
                            elif member.issym() or member.islnk():
                                require("\x00" not in member.linkname and len(member.linkname.encode()) <= 4096, "invalid saved layer link")
                                row.update(type="symlink" if member.issym() else "hardlink", target=member.linkname)
                            else:
                                row.update(type="special")
                            changes[name] = row
                    while reader.read(1024 * 1024):
                        pass
                    expanded_layers += reader.position
                    require(expanded_layers <= 32 * 1024 ** 3, "saved image expanded-layer budget exceeded")
                    actual = "sha256:" + reader.hash.hexdigest()
                    require(actual == expected, "saved layer identity mismatch")
                    layers.append({"archivePath": path, "diffId": actual})
            for target, opaque in removals:
                prefix = target + "/" if target else ""
                for name in list(entries):
                    if (not opaque and name == target) or name.startswith(prefix):
                        entries.pop(name)
                        special.pop(name, None)
            # This bounded snapshot includes every possible live path in this
            # layer. Removed paths can cause extra scans, never skipped children.
            possible_names = sorted(entries.keys() | changes.keys())
            for name, row in changes.items():
                if row["type"] == "whiteout":
                    continue
                if row["type"] == "hardlink":
                    target_name = collector.clean_name(row["target"])
                    require(target_name != name and not target_name.startswith(name + "/"),
                            "hardlink target would be removed with destination")
                    target = entries.get(target_name)
                    require(target is not None and target["type"] == "file",
                            "hardlink target must be an existing direct regular file")
                    target = collector.resolve_file(entries, target_name)
                    row = {**target, "path": "/" + name, "mode": row["mode"]}
                # Replacing a directory by a file/link removes lower children.
                if row["type"] != "directory":
                    prefix = name + "/"
                    first = bisect.bisect_left(possible_names, prefix)
                    if first < len(possible_names) and possible_names[first].startswith(prefix):
                        for old in [key for key in entries if key.startswith(prefix)]:
                            entries.pop(old)
                            special.pop(old, None)
                entries[name] = row
                special.pop(name, None)
                if name in captured:
                    special[name] = captured[name]
            require(len(entries) <= collector.LAYOUT_LIMITS["maximumInventoryEntries"], "saved image inventory count budget exceeded")
            require(sum(bool(collector.DOCTOR_FAMILY.fullmatch(name)) for name in entries) <= collector.LAYOUT_LIMITS["maximumDoctorFamilyEntries"], "saved Doctor family count budget exceeded")
            require(sum(len(value) for value in special.values()) <= collector.LAYOUT_LIMITS["capturedModuleLimitBytes"], "saved identity capture aggregate exceeded")
    return entries, special, layers


def verify_retention(out, measured, limits):
    retention = read_json(out / "retention-receipt.json", 65536)
    require(retention.get("schema") == "openclaw-v98-artifact-retention/v1"
            and retention.get("sourceCommit") == SOURCE
            and retention.get("fixtureExecuted") is False
            and retention.get("omittedPayloadCustodyClaimed") is False, "retention identity/claim mismatch")
    for key in ("imageLimitBytes", "evidenceLimitBytes", "evidenceFileLimitBytes"):
        expected = limits["imageArchiveLimitBytes" if key == "imageLimitBytes" else key]
        require(retention.get(key) == expected, "retention limit changed")
    require(retention.get("retentionReceiptBudgetBytes") == 65536, "retention receipt budget changed")
    rows = retention.get("files")
    require(isinstance(rows, list) and len(rows) <= 32, "retention row budget exceeded")
    seen = set()
    expected = {"retention-receipt.json"}
    for row in rows:
        name = row.get("name")
        require(isinstance(name, str) and "/" not in name and name not in ("", ".", "..") and name not in seen, "invalid/duplicate retention row")
        seen.add(name)
        require(type(row.get("retained")) is bool, "invalid retention flag")
        if row["retained"]:
            require(name != "retention-receipt.json" and name in measured, "retained member absent")
            require((row.get("bytes"), row.get("sha256")) == measured[name], "retained member bytes/hash mismatch")
            expected.add(name)
        tail = "retainedTailBytes" in row or "retainedTailSha256" in row
        if tail:
            require(name == "build.log" and row["retained"] is False
                    and type(row.get("retainedTailBytes")) is int
                    and 0 < row["retainedTailBytes"] <= limits["evidenceFileLimitBytes"], "invalid retained log tail")
            require((row.get("retainedTailBytes"), row.get("retainedTailSha256")) == measured.get("build.log.tail"), "retained log tail mismatch")
            expected.add("build.log.tail")
    require(expected == set(measured), "unlisted or omitted ZIP member")
    image_bytes = measured.get("image.tar.gz", (0, ""))[0]
    evidence_bytes = sum(value[0] for key, value in measured.items() if key not in ("image.tar.gz", "retention-receipt.json"))
    require(retention.get("retainedImageBytes") == image_bytes
            and retention.get("retainedEvidenceBytes") == evidence_bytes, "retention byte totals mismatch")
    return retention


def verify_read_binding(binding, entries, saved, image_sha, image_id):
    """Join exact read rules to the saved layers, without extracting or executing."""
    collector = load_collector()
    require(binding.get("schema") == "openclaw-v98-exact-runtime-read-binding/v1"
            and binding.get("sourceCommit") == SOURCE and binding.get("sourceTree") == TREE
            and binding.get("imageSha256") == image_sha and binding.get("imageConfigId") == image_id
            and binding.get("completeImportClosureClaimed") is False
            and binding.get("runtimeExecuted") is False, "read binding source/image mismatch")
    seen = set()
    for row in binding["imageEntries"]:
        path = row.get("path", "")
        require(isinstance(path, str) and path.startswith("/"), "invalid selected read path")
        name = collector.clean_name(path[1:])
        require(path == "/" + name and path not in seen, "duplicate/noncanonical read rule")
        seen.add(path)
        expected = {key: row[key] for key in ("path", "type", "mode", "bytes", "sha256")}
        require(type(expected["bytes"]) is int and expected["bytes"] >= 0
                and isinstance(expected["sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", expected["sha256"])
                and isinstance(expected["mode"], str) and re.fullmatch(r"0o[0-7]{1,4}", expected["mode"]),
                "invalid selected regular file fields")
        require(expected["type"] == "file" and expected == entries.get(name)
                and expected == saved.get(name), "selected regular read identity differs from saved layers")
    require(0 < len(seen) <= 4096, "selected read count budget")
    namespace = set()
    for row in binding["namespaceEntries"]:
        path = row.get("path", "")
        require(isinstance(path, str) and path.startswith("/"), "invalid selected namespace path")
        name = collector.clean_name(path[1:])
        require(path == "/" + name and path not in namespace
                and row.get("type") in ("symlink", "directory"), "invalid selected namespace rule")
        namespace.add(path)
        require(row == entries.get(name) and row == saved.get(name), "selected namespace differs from saved layers")
    require(len(namespace) <= 4096, "selected namespace count budget")
    return len(seen)


def verify(archive, metadata_path, run_path, source, out, *, run_id, attempt, tooling, artifact_id, read_binding=None):
    require(re.fullmatch(r"[a-f0-9]{40}", tooling), "expected tooling commit must be exact")
    collector = load_collector()
    limits = collector.CONTRACT["artifactPreparation"]
    source_identity = collector.verify_source(source)
    require(source_identity["commit"] == SOURCE and source_identity["tree"] == TREE, "qualified source tuple mismatch")
    for path, expected in limits["requiredCompiledEntries"]["authorityPins"].items():
        require(digest(source / path) == expected, "compiled entry authority source changed")
    run = read_json(run_path)
    require(run.get("id") == run_id and run.get("run_attempt") == attempt
            and run.get("head_sha") == tooling and run.get("head_branch") == "candidate/v2026.9.8-runtime-qualification"
            and run.get("event") == "push" and run.get("path") == ".github/workflows/v98-parity-artifact-prepare.yml"
            and run.get("status") == "completed" and run.get("repository", {}).get("full_name") == "fr-meyer/openclaw", "exact workflow run identity mismatch")
    metadata = read_json(metadata_path)
    artifacts = metadata.get("artifacts")
    require(isinstance(artifacts, list) and metadata.get("total_count") == len(artifacts) == 1, "expected one run artifact")
    artifact = artifacts[0]
    require(artifact.get("id") == artifact_id and artifact.get("workflow_run", {}).get("id") == run_id
            and artifact.get("workflow_run", {}).get("head_sha") == tooling
            and artifact.get("name") == f"v98-parity-build-bc8b82b2-{run_id}-{attempt}"
            and artifact.get("expired") is False, "exact artifact identity mismatch")
    created = datetime.datetime.fromisoformat(artifact["created_at"].replace("Z", "+00:00"))
    expires = datetime.datetime.fromisoformat(artifact["expires_at"].replace("Z", "+00:00"))
    require(created.tzinfo is not None and expires.tzinfo is not None
            and abs((expires - created).total_seconds() - 7 * 86400) <= 60, "seven-day retention mismatch")
    require(archive.is_file() and not archive.is_symlink(), "non-regular artifact ZIP")
    archive_sha = digest(archive)
    require(archive.stat().st_size == artifact.get("size_in_bytes")
            and artifact.get("digest") == "sha256:" + archive_sha, "GitHub ZIP size/digest mismatch")
    allowed = {"preflight.json", "docker-version.txt", "build.log", "build.log.tail", "image-id.txt", "image-inspect.json",
               collector.MANIFEST_NAME, collector.LAYOUT_NAME, "artifact-receipt.json", "collector-failure.json", "image.tar.gz", "retention-receipt.json"}
    measured = {}
    with zipfile.ZipFile(archive) as zipped:
        infos = zipped.infolist()
        require(len(infos) <= len(allowed) and len({row.filename for row in infos}) == len(infos), "ZIP member count/duplicate mismatch")
        evidence_bytes = 0
        image_bytes = 0
        for row in infos:
            require(row.filename in allowed and not row.is_dir() and not row.flag_bits & 1
                    and stat.S_IFMT(row.external_attr >> 16) in (0, stat.S_IFREG)
                    and row.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), "unsafe or unsupported ZIP member")
            maximum = limits["imageArchiveLimitBytes"] if row.filename == "image.tar.gz" else 65536 if row.filename == "retention-receipt.json" else limits["evidenceFileLimitBytes"]
            require(0 <= row.file_size <= maximum, "ZIP member budget exceeded")
            if row.filename == "image.tar.gz":
                image_bytes += row.file_size
            elif row.filename != "retention-receipt.json":
                evidence_bytes += row.file_size
        require(image_bytes <= limits["imageArchiveLimitBytes"] and evidence_bytes <= limits["evidenceLimitBytes"], "ZIP aggregate budget exceeded")
        require(shutil.disk_usage(out.parent).free > image_bytes + evidence_bytes + 512 * 1024 ** 2, "artifact client disk admission refused")
        out.mkdir(mode=0o700)
        for row in infos:
            hashed = hashlib.sha256()
            size = 0
            with zipped.open(row) as payload, (out / row.filename).open("xb") as destination:
                for block in iter(lambda: payload.read(1024 * 1024), b""):
                    size += len(block)
                    require(size <= row.file_size, "ZIP payload exceeds declared size")
                    hashed.update(block)
                    destination.write(block)
            require(size == row.file_size, "ZIP payload truncated")
            measured[row.filename] = (size, hashed.hexdigest())
    require(digest(archive) == archive_sha, "artifact ZIP changed during verification")
    verify_retention(out, measured, limits)
    if "preflight.json" in measured:
        preflight = read_json(out / "preflight.json")
        require(preflight.get("source") == source_identity and preflight.get("fixtureExecuted") is False, "preflight source/claim mismatch")
        identity_fields(preflight, run_id, attempt, tooling)
    result = {"schema": "openclaw-v98-retained-artifact-validation/v2", "runId": run_id, "runAttempt": attempt,
              "toolingCommit": tooling, "source": source_identity, "artifactId": artifact_id,
              "zipSha256": archive_sha, "githubZipDigestVerified": True, "artifactExpiresAtUtc": artifact["expires_at"],
              "retainedFiles": sorted(measured), "runtimeExecuted": False, "fixturePhases": "NEVER_RUN",
              "completeImportWorkerClosureReviewed": False, "filesystemReconstructedForExecution": False}
    if "image.tar.gz" not in measured:
        if "collector-failure.json" in measured:
            failure = read_json(out / "collector-failure.json")
            require(failure.get("fixtureExecuted") is False, "failure evidence execution claim changed")
            result["collectorFailure"] = failure
        if collector.MANIFEST_NAME in measured:
            result["nonAdmittedInventoryEntryCount"] = len(read_manifest(out / collector.MANIFEST_NAME, collector))
        if collector.LAYOUT_NAME in measured:
            layout = read_json(out / collector.LAYOUT_NAME)
            require(layout.get("fixtureExecuted") is False and layout.get("minimalImportClosureClaimed") is False, "failure layout claim changed")
            result["nonAdmittedLayout"] = layout
        result["status"] = "FAILURE_EVIDENCE_ONLY; NO ADMITTED IMAGE"
        return result
    required = {"preflight.json", "image-id.txt", "image-inspect.json", "artifact-receipt.json", collector.MANIFEST_NAME, collector.LAYOUT_NAME}
    require(required <= measured.keys() and "collector-failure.json" not in measured, "sealed image required evidence missing or failed")
    require(run.get("conclusion") == "success", "image came from non-successful workflow")
    receipt = read_json(out / "artifact-receipt.json")
    require(receipt.get("schema") == "openclaw-v98-prepared-image/v1" and receipt.get("source") == source_identity, "sealed receipt source/schema mismatch")
    identity_fields(receipt, run_id, attempt, tooling)
    require(receipt.get("fixturePhases") == "NEVER_RUN" and receipt.get("defaultEntrypointStarted") is False, "sealed receipt execution claim changed")
    require((receipt.get("imageArchiveBytes"), receipt.get("imageArchiveSha256")) == measured["image.tar.gz"], "sealed image archive mismatch")
    require(receipt.get("filesystemManifestPath") == collector.MANIFEST_NAME and receipt.get("filesystemManifestEncoding") == "gzip-json"
            and receipt.get("filesystemManifestSha256") == measured[collector.MANIFEST_NAME][1]
            and receipt.get("layoutAssessmentSha256") == measured[collector.LAYOUT_NAME][1], "sealed layout/inventory binding mismatch")
    entries = read_manifest(out / collector.MANIFEST_NAME, collector)
    image = receipt["image"]
    require((out / "image-id.txt").read_text().strip() == image.get("imageConfigId"), "iid receipt identity mismatch")
    inspect = read_json(out / "image-inspect.json")
    saved, special, layers = saved_identity_files(out / "image.tar.gz", image["imageConfigId"], collector)
    require(layers == receipt.get("savedImageLayers"), "saved layer receipt mismatch")
    targets = {"app/dist/build-info.json", "usr/local/bin/node"}
    targets.update(limits["requiredCompiledEntries"]["paths"])
    targets.update("app/runtime-plugins/mergeguez-pr-lifecycle/" + name for name in collector.PUBLISHER_FILES)
    family = {name for name in saved if collector.DOCTOR_FAMILY.fullmatch(name)}
    require(family == {name for name in entries if collector.DOCTOR_FAMILY.fullmatch(name)}, "saved/inventory Doctor family mismatch")
    targets.update(family)
    for name in targets:
        recorded = collector.resolve_file(entries, name)
        actual = collector.resolve_file(saved, name)
        require((recorded["sha256"], recorded["bytes"]) == (actual["sha256"], actual["bytes"]), "saved identity file differs from inventory")
    if read_binding is not None:
        result["selectedReadFilesVerifiedAgainstSavedLayers"] = verify_read_binding(
            read_binding, entries, saved, measured["image.tar.gz"][1], image["imageConfigId"])
    actual_image = collector.validate_image(inspect, entries, special, source)
    require(same_json(actual_image, image), "recomputed compiled image identity differs from receipt")
    require(same_json(collector.assess_layout(entries, special), read_json(out / collector.LAYOUT_NAME)), "recomputed layout differs from retained assessment")
    result.update(status="PREPARED_IMAGE_IDENTITY_VERIFIED; RUNTIME_UNQUALIFIED", imageConfigId=image["imageConfigId"],
                  imageArchiveSha256=measured["image.tar.gz"][1], filesystemManifestSha256=measured[collector.MANIFEST_NAME][1],
                  layoutAssessmentSha256=measured[collector.LAYOUT_NAME][1], savedConfigAndAllLayerDigests="PASS",
                  requiredIdentityFilesVerifiedAgainstSavedLayers=len(targets), compiledEntriesVerified=79, publisherFilesVerified=8,
                  doctorRequiredExport=collector.DOCTOR_API, doctorEntry=image["doctorEntryCandidate"], buildInfo=image["buildInfo"],
                  doctorExportLoadedOrExecuted=False)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("archive", "metadata", "run-metadata", "source", "output"):
        parser.add_argument("--" + flag, required=True, type=Path)
    for flag in ("run-id", "run-attempt", "artifact-id"):
        parser.add_argument("--" + flag, required=True, type=positive)
    parser.add_argument("--tooling-commit", required=True)
    parser.add_argument("--read-binding", type=Path)
    args = parser.parse_args()
    result = verify(args.archive, args.metadata, args.run_metadata, args.source, args.output,
                    run_id=args.run_id, attempt=args.run_attempt, tooling=args.tooling_commit, artifact_id=args.artifact_id,
                    read_binding=read_json(args.read_binding) if args.read_binding else None)
    with (args.output / "validation.json").open("x") as target:
        json.dump(result, target, indent=2)
        target.write("\n")
    print(result["status"])
    return 0 if result["status"].startswith("PREPARED_IMAGE_IDENTITY_VERIFIED;") else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print("Artifact validation failed: " + str(error), file=sys.stderr)
        sys.exit(2)

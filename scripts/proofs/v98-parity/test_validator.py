"""Collector→retention→ZIP→client proof with inert tar bytes; no image execution."""
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

SPEC = importlib.util.spec_from_file_location("validator", Path(__file__).with_name("verify-artifact.py"))
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)
COLLECTOR = VALIDATOR.load_collector()
TOOLING = "a1cebb92d111fd6dfcb639625de1109f1a7708cf"
RUN = 1001
ARTIFACT = 2001


def source_checkout():
    explicit = os.environ.get("V98_QUALIFIED_SOURCE")
    candidates = [Path(explicit)] if explicit else [Path.cwd() / "source", Path(__file__).parents[4] / "openclaw-v98-final-composition"]
    for path in candidates:
        if (path / ".git").exists():
            COLLECTOR.verify_source(path)
            return path
    raise RuntimeError("Tests require the clean qualified source checkout; set V98_QUALIFIED_SOURCE")


def tar_bytes(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, value in files.items():
            member = tarfile.TarInfo(name)
            member.mode = 0o644
            member.size = len(value)
            archive.addfile(member, io.BytesIO(value))
    return stream.getvalue()


def pack_saved(layers, *, compressed=False, config_change=None):
    config = {"architecture": "amd64", "os": "linux",
              "config": {"Labels": {"org.opencontainers.image.revision": VALIDATOR.SOURCE}},
              "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(value).hexdigest() for value in layers]}}
    if config_change:
        config_change(config)
    encoded = json.dumps(config).encode()
    image_id = "sha256:" + hashlib.sha256(encoded).hexdigest()
    names = [f"layer-{index}.tar" for index in range(len(layers))]
    payloads = {"manifest.json": json.dumps([{"Config": "config.json", "Layers": names}]).encode(), "config.json": encoded}
    payloads.update({name: gzip.compress(value, mtime=0) if compressed else value for name, value in zip(names, layers)})
    return gzip.compress(tar_bytes(payloads), mtime=0), image_id


class ArtifactClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = source_checkout()

    def fixture(self, directory, *, compressed=False):
        root = Path(directory)
        out, stage = root / "producer", root / "retained"
        out.mkdir()
        files = {name: ("// inert representative file: " + name).encode()
                 for name in COLLECTOR.CONTRACT["artifactPreparation"]["requiredCompiledEntries"]["paths"]}
        files["usr/local/bin/node"] = b"inert representative Node bytes; never executable"
        files["app/dist/build-info.json"] = json.dumps({"commit": VALIDATOR.SOURCE, "version": "2026.9.8",
                                                      "buildId": "2026.9.8-bc8b82b2cbbb-synthetic-layout-test"}).encode()
        observed = json.loads(Path(__file__).with_name("observed-layout.json").read_text())
        for chunk in observed["chunks"]:
            files["app/dist/" + chunk["name"]] = (chunk["exportTable"] + "\n").encode()
        for name in COLLECTOR.PUBLISHER_FILES:
            files["app/runtime-plugins/mergeguez-pr-lifecycle/" + name] = (self.source / "scripts/docker/runtime-plugins/mergeguez-pr-lifecycle" / name).read_bytes()
        lower = {**files, "usr/local/bin/node": b"lower-layer obsolete Node bytes", "app/dist/obsolete-marker": b"removed"}
        layers = [tar_bytes(lower), tar_bytes({"usr/local/bin/node": files["usr/local/bin/node"], "app/dist/.wh.obsolete-marker": b""})]
        saved, image_id = pack_saved(layers, compressed=compressed)
        (out / "image.tar.gz").write_bytes(saved)
        (out / "filesystem.tar").write_bytes(tar_bytes(files))
        COLLECTOR.write_json(out / "image-inspect.json", [{"Id": image_id, "Os": "linux", "Architecture": "amd64",
                                                         "Config": {"Labels": {"org.opencontainers.image.revision": VALIDATOR.SOURCE}}}])
        (out / "image-id.txt").write_text(image_id + "\n")
        COLLECTOR.write_json(out / "preflight.json", {"source": COLLECTOR.verify_source(self.source), "toolingSha": TOOLING,
                                                     "runId": str(RUN), "runAttempt": "1", "fixtureExecuted": False})
        (out / "build.log").write_text("Synthetic archive metadata test; no build or runtime executed.\n")
        env = {"GITHUB_SHA": TOOLING, "GITHUB_RUN_ID": str(RUN), "GITHUB_RUN_ATTEMPT": "1"}
        with mock.patch.dict(os.environ, env), mock.patch.object(sys, "argv", ["collect-artifacts.py", "seal", str(self.source), str(out)]):
            COLLECTOR.main()
        COLLECTOR.stage_retention(out, stage)
        fixture = {"root": root, "stage": stage, "layers": layers, "compressed": compressed,
                   "archive": root / "artifact.zip", "metadata": root / "artifacts.json", "run": root / "run.json"}
        COLLECTOR.write_json(fixture["run"], {"id": RUN, "run_attempt": 1, "head_sha": TOOLING,
                                             "head_branch": "candidate/v2026.9.8-runtime-qualification", "event": "push",
                                             "path": ".github/workflows/v98-parity-artifact-prepare.yml", "status": "completed",
                                             "conclusion": "success", "repository": {"full_name": "fr-meyer/openclaw"}})
        payloads = {path.name: path.read_bytes() for path in stage.iterdir()}
        self.repack(fixture, payloads)
        return fixture

    def repack(self, fixture, payloads, *, update_retention=False):
        if update_retention:
            retention = json.loads(payloads["retention-receipt.json"])
            for row in retention["files"]:
                if row["name"] in payloads and row["retained"]:
                    value = payloads[row["name"]]
                    row.update(bytes=len(value), sha256=hashlib.sha256(value).hexdigest())
                elif row["retained"]:
                    row["retained"] = False
            retention["retainedImageBytes"] = len(payloads.get("image.tar.gz", b""))
            retention["retainedEvidenceBytes"] = sum(len(value) for name, value in payloads.items() if name not in ("image.tar.gz", "retention-receipt.json"))
            payloads["retention-receipt.json"] = json.dumps(retention).encode()
        with zipfile.ZipFile(fixture["archive"], "w", zipfile.ZIP_DEFLATED) as archive:
            for name, value in payloads.items():
                archive.writestr(name, value)
        metadata = {"total_count": 1, "artifacts": [{"id": ARTIFACT, "workflow_run": {"id": RUN, "head_sha": TOOLING},
                                                    "name": f"v98-parity-build-bc8b82b2-{RUN}-1", "expired": False,
                                                    "created_at": "2026-10-04T07:00:00Z", "expires_at": "2026-10-11T07:00:00Z",
                                                    "size_in_bytes": fixture["archive"].stat().st_size,
                                                    "digest": "sha256:" + VALIDATOR.digest(fixture["archive"])}]}
        fixture["metadata"].write_text(json.dumps(metadata))

    def payloads(self, fixture):
        with zipfile.ZipFile(fixture["archive"]) as archive:
            return {row.filename: archive.read(row) for row in archive.infolist()}

    def verify(self, fixture, output="client"):
        return VALIDATOR.verify(fixture["archive"], fixture["metadata"], fixture["run"], self.source, fixture["root"] / output,
                                run_id=RUN, attempt=1, tooling=TOOLING, artifact_id=ARTIFACT)

    def test_complete_collector_retention_client_join_with_raw_and_gzip_layers(self):
        for compressed in (False, True):
            with self.subTest(compressed=compressed), tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory, compressed=compressed)
                result = self.verify(fixture)
                self.assertEqual(result["status"], "PREPARED_IMAGE_IDENTITY_VERIFIED; RUNTIME_UNQUALIFIED")
                self.assertEqual(result["compiledEntriesVerified"], 79)
                self.assertEqual(result["publisherFilesVerified"], 8)
                self.assertEqual(result["requiredIdentityFilesVerifiedAgainstSavedLayers"], 91)
                self.assertEqual(result["doctorEntry"]["path"], "/app/dist/openclaw-state-db-CgJKJRub.mjs")
                self.assertEqual(result["fixturePhases"], "NEVER_RUN")
                self.assertFalse(result["runtimeExecuted"])
                self.assertEqual(result["source"], COLLECTOR.verify_source(self.source))

    def test_cli_is_ready_and_checks_cannot_be_disabled_by_python_optimization(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory, compressed=True)
            command = [sys.executable, "-B", str(Path(__file__).with_name("verify-artifact.py")),
                       "--archive", str(fixture["archive"]), "--metadata", str(fixture["metadata"]),
                       "--run-metadata", str(fixture["run"]), "--source", str(self.source),
                       "--output", str(fixture["root"] / "cli-client"), "--run-id", str(RUN),
                       "--run-attempt", "1", "--artifact-id", str(ARTIFACT), "--tooling-commit", TOOLING]
            process = subprocess.run(command, text=True, capture_output=True, timeout=30)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertTrue((fixture["root"] / "cli-client/validation.json").is_file())
            metadata = json.loads(fixture["metadata"].read_text())
            metadata["artifacts"][0]["digest"] = "sha256:" + "0" * 64
            fixture["metadata"].write_text(json.dumps(metadata))
            command[1:1] = ["-O"]
            command[command.index("--output") + 1] = str(fixture["root"] / "refused-client")
            process = subprocess.run(command, text=True, capture_output=True, timeout=30)
            self.assertEqual(process.returncode, 2)
            self.assertIn("ZIP size/digest mismatch", process.stderr)
            self.assertFalse((fixture["root"] / "refused-client").exists())

    def test_wrong_run_source_tooling_attempt_artifact_or_expiry_rejected(self):
        cases = ("run", "tooling", "attempt", "repository", "branch", "artifact", "expiry", "zip-digest", "source")
        for change in cases:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                run = json.loads(fixture["run"].read_text())
                metadata = json.loads(fixture["metadata"].read_text())
                if change == "run": run["id"] += 1
                elif change == "tooling": run["head_sha"] = "0" * 40
                elif change == "attempt": run["run_attempt"] = 2
                elif change == "repository": run["repository"]["full_name"] = "other/openclaw"
                elif change == "branch": run["head_branch"] = "main"
                elif change == "artifact": metadata["artifacts"][0]["id"] += 1
                elif change == "expiry": metadata["artifacts"][0]["expires_at"] = "2026-10-12T07:00:00Z"
                elif change == "zip-digest": metadata["artifacts"][0]["digest"] = "sha256:" + "0" * 64
                elif change == "source":
                    fixture["wrong-source"] = Path(__file__).parents[3]
                fixture["run"].write_text(json.dumps(run))
                fixture["metadata"].write_text(json.dumps(metadata))
                if change == "source":
                    with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                        VALIDATOR.verify(fixture["archive"], fixture["metadata"], fixture["run"], fixture["wrong-source"], fixture["root"] / "client", run_id=RUN, attempt=1, tooling=TOOLING, artifact_id=ARTIFACT)
                else:
                    with self.assertRaises(ValueError): self.verify(fixture)
                self.assertFalse((fixture["root"] / "client").exists())

    def test_metadata_duplicate_keys_unknown_paths_members_and_symlinks_refused(self):
        for change in ("duplicate-json", "unknown", "traversal", "duplicate-zip", "symlink"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                payloads = self.payloads(fixture)
                if change == "duplicate-json":
                    payloads["preflight.json"] = b'{"fixtureExecuted":false,"fixtureExecuted":true}'
                elif change in ("unknown", "traversal"):
                    payloads["filesystem.tar" if change == "unknown" else "../escape"] = b"forbidden"
                self.repack(fixture, payloads, update_retention=True)
                if change in ("duplicate-zip", "symlink"):
                    with zipfile.ZipFile(fixture["archive"], "a") as archive:
                        info = zipfile.ZipInfo("image-id.txt" if change == "duplicate-zip" else "docker-version.txt")
                        if change == "symlink": info.external_attr = 0o120777 << 16
                        archive.writestr(info, b"outside")
                    metadata = json.loads(fixture["metadata"].read_text())
                    metadata["artifacts"][0].update(size_in_bytes=fixture["archive"].stat().st_size, digest="sha256:" + VALIDATOR.digest(fixture["archive"]))
                    fixture["metadata"].write_text(json.dumps(metadata))
                with self.assertRaises(ValueError): self.verify(fixture)
                self.assertFalse((fixture["root"] / "escape").exists())

    def test_manifest_decompression_corruption_budget_and_duplicate_paths_refused(self):
        for change in ("corrupt", "budget", "duplicate", "bytes", "claim"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                payloads = self.payloads(fixture)
                manifest = json.loads(gzip.decompress(payloads[COLLECTOR.MANIFEST_NAME]))
                if change == "corrupt": payloads[COLLECTOR.MANIFEST_NAME] = b"not gzip"
                elif change == "budget": payloads[COLLECTOR.MANIFEST_NAME] = gzip.compress(b"x" * (COLLECTOR.LAYOUT_LIMITS["expandedManifestLimitBytes"] + 1))
                else:
                    if change == "duplicate": manifest["entries"].append(manifest["entries"][0])
                    elif change == "bytes": manifest["regularFileBytes"] += 1
                    else: manifest["fixtureExecuted"] = True
                    payloads[COLLECTOR.MANIFEST_NAME] = gzip.compress(json.dumps(manifest).encode(), mtime=0)
                receipt = json.loads(payloads["artifact-receipt.json"])
                receipt["filesystemManifestSha256"] = hashlib.sha256(payloads[COLLECTOR.MANIFEST_NAME]).hexdigest()
                payloads["artifact-receipt.json"] = json.dumps(receipt).encode()
                self.repack(fixture, payloads, update_retention=True)
                with self.assertRaises((ValueError, gzip.BadGzipFile)): self.verify(fixture)

    def test_retention_hash_totals_rows_and_required_evidence_refused(self):
        for change in ("hash", "totals", "row-duplicate", "unlisted", "missing-manifest", "failed-image"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                payloads = self.payloads(fixture)
                retention = json.loads(payloads["retention-receipt.json"])
                if change == "hash": retention["files"][0]["sha256"] = "0" * 64
                elif change == "totals": retention["retainedEvidenceBytes"] += 1
                elif change == "row-duplicate": retention["files"].append(retention["files"][0])
                elif change == "unlisted": retention["files"] = [row for row in retention["files"] if row["name"] != "build.log"]
                elif change == "missing-manifest": payloads.pop(COLLECTOR.MANIFEST_NAME)
                elif change == "failed-image": payloads["collector-failure.json"] = b'{"fixtureExecuted":false,"error":"refused"}'
                payloads["retention-receipt.json"] = json.dumps(retention).encode()
                if change == "failed-image":
                    retention["files"].append({"name": "collector-failure.json", "retained": True})
                    payloads["retention-receipt.json"] = json.dumps(retention).encode()
                self.repack(fixture, payloads, update_retention=change in ("missing-manifest", "failed-image"))
                with self.assertRaises(ValueError): self.verify(fixture)

    def test_manifest_forgery_cannot_borrow_saved_image_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            payloads = self.payloads(fixture)
            manifest = json.loads(gzip.decompress(payloads[COLLECTOR.MANIFEST_NAME]))
            target = next(row for row in manifest["entries"] if row["path"] == "/usr/local/bin/node")
            target["sha256"] = "0" * 64
            payloads[COLLECTOR.MANIFEST_NAME] = gzip.compress(json.dumps(manifest).encode(), mtime=0)
            receipt = json.loads(payloads["artifact-receipt.json"])
            receipt["filesystemManifestSha256"] = hashlib.sha256(payloads[COLLECTOR.MANIFEST_NAME]).hexdigest()
            receipt["image"]["nodeExecutable"] = target
            payloads["artifact-receipt.json"] = json.dumps(receipt).encode()
            self.repack(fixture, payloads, update_retention=True)
            with self.assertRaisesRegex(ValueError, "saved identity file differs"):
                self.verify(fixture)

    def test_config_platform_source_and_layer_digests_rechecked(self):
        for change in ("platform", "source", "layer"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory, compressed=True)
                def mutate(config):
                    if change == "platform": config["architecture"] = "arm64"
                    elif change == "source": config["config"]["Labels"]["org.opencontainers.image.revision"] = "0" * 40
                    else: config["rootfs"]["diff_ids"][0] = "sha256:" + "0" * 64
                saved, image_id = pack_saved(fixture["layers"], compressed=True, config_change=mutate)
                payloads = self.payloads(fixture)
                payloads["image.tar.gz"] = saved
                payloads["image-id.txt"] = (image_id + "\n").encode()
                inspect = json.loads(payloads["image-inspect.json"])
                inspect[0]["Id"] = image_id
                payloads["image-inspect.json"] = json.dumps(inspect).encode()
                receipt = json.loads(payloads["artifact-receipt.json"])
                receipt["image"].update(imageConfigId=image_id)
                receipt.update(imageArchiveBytes=len(saved), imageArchiveSha256=hashlib.sha256(saved).hexdigest())
                payloads["artifact-receipt.json"] = json.dumps(receipt).encode()
                self.repack(fixture, payloads, update_retention=True)
                with self.assertRaisesRegex(ValueError, "saved config platform/source|layer identity"):
                    self.verify(fixture)

    def test_failure_layout_evidence_is_consumable_without_admitting_image(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            payloads = self.payloads(fixture)
            payloads.pop("image.tar.gz")
            payloads.pop("artifact-receipt.json")
            payloads["collector-failure.json"] = b'{"phase":"seal","error":"zero named exports","fixtureExecuted":false}'
            retention = json.loads(payloads["retention-receipt.json"])
            retention["files"].append({"name": "collector-failure.json", "retained": True})
            payloads["retention-receipt.json"] = json.dumps(retention).encode()
            self.repack(fixture, payloads, update_retention=True)
            result = self.verify(fixture)
            self.assertEqual(result["status"], "FAILURE_EVIDENCE_ONLY; NO ADMITTED IMAGE")
            self.assertFalse(result["runtimeExecuted"])
            self.assertEqual(result["nonAdmittedLayout"]["doctor"]["candidateCount"], 1)
            self.assertGreater(result["nonAdmittedInventoryEntryCount"], 79)

    def test_evidence_member_budget_is_enforced_before_decoding(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            payloads = self.payloads(fixture)
            payloads["build.log"] = b"x" * (COLLECTOR.CONTRACT["artifactPreparation"]["evidenceFileLimitBytes"] + 1)
            self.repack(fixture, payloads, update_retention=True)
            with self.assertRaisesRegex(ValueError, "ZIP member budget"):
                self.verify(fixture)
            self.assertFalse((fixture["root"] / "client").exists())

    def test_image_layout_claim_types_and_existing_output_are_not_accepted(self):
        for change in ("image-claim", "layout-claim", "existing-output"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                fixture = self.fixture(directory)
                payloads = self.payloads(fixture)
                receipt = json.loads(payloads["artifact-receipt.json"])
                if change == "image-claim":
                    receipt["image"]["doctorExportLoadedOrExecuted"] = 0
                elif change == "layout-claim":
                    layout = json.loads(payloads[COLLECTOR.LAYOUT_NAME])
                    layout["fixtureExecuted"] = 0
                    payloads[COLLECTOR.LAYOUT_NAME] = json.dumps(layout).encode()
                    receipt["layoutAssessmentSha256"] = hashlib.sha256(payloads[COLLECTOR.LAYOUT_NAME]).hexdigest()
                else:
                    (fixture["root"] / "client").mkdir()
                    (fixture["root"] / "client/owned-marker").write_text("preserve")
                payloads["artifact-receipt.json"] = json.dumps(receipt).encode()
                self.repack(fixture, payloads, update_retention=True)
                with self.assertRaises((ValueError, FileExistsError)):
                    self.verify(fixture)
                if change == "existing-output":
                    self.assertEqual((fixture["root"] / "client/owned-marker").read_text(), "preserve")

    def test_saved_layer_traversal_duplicate_paths_and_links_refused(self):
        for change in ("traversal", "duplicate", "cycle", "pax-budget"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                stream = io.BytesIO()
                with tarfile.open(fileobj=stream, mode="w") as layer:
                    if change in ("traversal", "duplicate"):
                        names = ["../outside"] if change == "traversal" else ["app/file", "app/file"]
                        for name in names:
                            row = tarfile.TarInfo(name)
                            row.size = 1
                            layer.addfile(row, io.BytesIO(b"x"))
                    elif change == "cycle":
                        for name, target in (("app/a", "app/b"), ("app/b", "app/a")):
                            row = tarfile.TarInfo(name)
                            row.type = tarfile.LNKTYPE
                            row.linkname = target
                            layer.addfile(row)
                raw_layer = stream.getvalue()
                if change == "pax-budget":
                    row = tarfile.TarInfo("pax-metadata")
                    row.type = tarfile.XHDTYPE
                    row.size = 8 * 1024 ** 2 + 512
                    raw_layer = row.tobuf() + b"\0" * 512
                saved, image_id = pack_saved([raw_layer], compressed=True)
                path = Path(directory) / "saved.tar.gz"
                path.write_bytes(saved)
                if change == "pax-budget":
                    with self.assertRaisesRegex(ValueError, "tar metadata read budget"):
                        VALIDATOR.saved_identity_files(path, image_id, COLLECTOR)
                else:
                    with self.assertRaises(ValueError):
                        VALIDATOR.saved_identity_files(path, image_id, COLLECTOR)
                self.assertFalse((Path(directory) / "outside").exists())

    def test_saved_archive_count_and_declared_expansion_budgets_refuse_before_config(self):
        for change in ("count", "size"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                if change == "count":
                    raw = tar_bytes({f"empty-{number}": b"" for number in range(4097)})
                else:
                    row = tarfile.TarInfo("oversized")
                    row.size = 32 * 1024 ** 3 + 1
                    raw = row.tobuf() + b"\0" * 1024
                path = Path(directory) / "saved.tar.gz"
                path.write_bytes(gzip.compress(raw, mtime=0))
                with self.assertRaisesRegex(ValueError, "saved archive .* budget"):
                    VALIDATOR.saved_identity_files(path, "sha256:" + "a" * 64, COLLECTOR)

    def test_inventory_cannot_claim_files_beneath_a_file_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(directory)
            payloads = self.payloads(fixture)
            manifest = json.loads(gzip.decompress(payloads[COLLECTOR.MANIFEST_NAME]))
            manifest["entries"].append({"path": "/app", "mode": "0o644", "type": "file", "bytes": 1,
                                        "sha256": hashlib.sha256(b"x").hexdigest()})
            manifest["regularFileBytes"] += 1
            payloads[COLLECTOR.MANIFEST_NAME] = gzip.compress(json.dumps(manifest).encode(), mtime=0)
            receipt = json.loads(payloads["artifact-receipt.json"])
            receipt["filesystemManifestSha256"] = hashlib.sha256(payloads[COLLECTOR.MANIFEST_NAME]).hexdigest()
            payloads["artifact-receipt.json"] = json.dumps(receipt).encode()
            self.repack(fixture, payloads, update_retention=True)
            with self.assertRaisesRegex(ValueError, "unsupported parent"):
                self.verify(fixture)

    def test_saved_layers_apply_opaque_whiteout_and_freeze_hardlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            lower = tar_bytes({"app/dir/old": b"old", "app/target": b"original"})
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w") as middle:
                row = tarfile.TarInfo("app/alias")
                row.type = tarfile.LNKTYPE
                row.linkname = "app/target"
                middle.addfile(row)
                row = tarfile.TarInfo("app/target")
                value = b"same-layer replacement after hardlink"
                row.size = len(value)
                middle.addfile(row, io.BytesIO(value))
            upper = tar_bytes({"app/dir/.wh..wh..opq": b"", "app/dir/new": b"new", "app/target": b"replaced"})
            saved, image_id = pack_saved([lower, stream.getvalue(), upper], compressed=True)
            path = Path(directory) / "saved.tar.gz"
            path.write_bytes(saved)
            entries, _, _ = VALIDATOR.saved_identity_files(path, image_id, COLLECTOR)
            self.assertNotIn("app/dir/old", entries)
            self.assertEqual(entries["app/dir/new"]["sha256"], hashlib.sha256(b"new").hexdigest())
            self.assertEqual(entries["app/alias"]["sha256"], hashlib.sha256(b"original").hexdigest())
            self.assertEqual(entries["app/target"]["sha256"], hashlib.sha256(b"replaced").hexdigest())

    def test_intermediate_link_hop_cannot_skip_a_non_directory_parent(self):
        entries = {"requested": {"type": "symlink", "target": "bad/alias"},
                   "bad": {"type": "file", "bytes": 1, "sha256": hashlib.sha256(b"x").hexdigest()},
                   "bad/alias": {"type": "symlink", "target": "/safe/file"},
                   "safe/file": {"type": "file", "bytes": 1, "sha256": hashlib.sha256(b"y").hexdigest()}}
        with self.assertRaisesRegex(ValueError, "unsupported parent"):
            COLLECTOR.resolve_file(entries, "requested")
        for target in ("bad/../safe/file", "bad/./../safe/file", "missing/../safe/file"):
            entries["requested"]["target"] = target
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, "parent"):
                COLLECTOR.resolve_file(entries, "requested")

    def test_unproved_forward_or_symlink_hardlink_targets_fail_closed(self):
        for change in ("forward", "symlink"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                stream = io.BytesIO()
                with tarfile.open(fileobj=stream, mode="w") as layer:
                    if change == "symlink":
                        row = tarfile.TarInfo("app/regular")
                        row.size = 1
                        layer.addfile(row, io.BytesIO(b"x"))
                        row = tarfile.TarInfo("app/target")
                        row.type = tarfile.SYMTYPE
                        row.linkname = "regular"
                        layer.addfile(row)
                    row = tarfile.TarInfo("app/alias")
                    row.type = tarfile.LNKTYPE
                    row.linkname = "app/target"
                    layer.addfile(row)
                    if change == "forward":
                        row = tarfile.TarInfo("app/target")
                        row.size = 1
                        layer.addfile(row, io.BytesIO(b"x"))
                saved, image_id = pack_saved([stream.getvalue()], compressed=True)
                path = Path(directory) / "saved.tar.gz"
                path.write_bytes(saved)
                with self.assertRaisesRegex(ValueError, "existing direct regular"):
                    VALIDATOR.saved_identity_files(path, image_id, COLLECTOR)

    def test_hardlink_source_cannot_be_its_replaced_destination_or_subtree(self):
        for target, destination in (("app/target", "app/target"), ("app/dir/file", "app/dir")):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                lower = tar_bytes({target: b"lower bytes"})
                stream = io.BytesIO()
                with tarfile.open(fileobj=stream, mode="w") as upper:
                    row = tarfile.TarInfo(destination)
                    row.type = tarfile.LNKTYPE
                    row.linkname = target
                    upper.addfile(row)
                saved, image_id = pack_saved([lower, stream.getvalue()], compressed=True)
                path = Path(directory) / "saved.tar.gz"
                path.write_bytes(saved)
                with self.assertRaisesRegex(ValueError, "hardlink target.*removed"):
                    VALIDATOR.saved_identity_files(path, image_id, COLLECTOR)


if __name__ == "__main__":
    unittest.main()

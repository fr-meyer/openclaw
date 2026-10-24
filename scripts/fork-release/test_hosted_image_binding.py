"""Synthetic OCI closure/provenance checks through the actual image verifier."""

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

import hosted_privacy as privacy

ROOT = Path(__file__).resolve().parents[2]
SOURCE = "a" * 40
OTHER = "b" * 40
VERSION = "2026.10.6"
BUILT_AT = "2026-10-23T10:00:00Z"
GITHUB = {"workflowSha": "c" * 40, "runId": "42", "attempt": "1"}
GCP = {"kind": "gcp", "toolingSha": "c" * 40, "operationId": "d" * 32,
       "attempt": "1", "executionSha256": "e" * 64}
CONTEXT = {"kind": "git", "repository": "https://github.com/fr-meyer/openclaw",
           "sourceSha": SOURCE}
MANIFEST = {"repository": "fr-meyer/openclaw", "source": {"commit": SOURCE},
            "image": {"architecture": "amd64"}}
MEDIA = "application/vnd.oci.image.manifest.v1+json"
INDEX = "application/vnd.oci.image.index.v1+json"
PROVENANCE = "https://slsa.dev/provenance/v1"


def layout(root, change=None, legacy=False, source=SOURCE, payload=b"public", version_label=VERSION,
           include_sbom=True):
    def blob(value):
        raw = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True).encode()
        digest = hashlib.sha256(raw).hexdigest()
        target = root / "blobs" / "sha256" / digest
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        return {"digest": "sha256:" + digest, "size": len(raw)}

    config = blob({"architecture": "amd64", "os": "linux",
                   "config": {"Labels": {
                       "org.opencontainers.image.revision": source,
                       "org.opencontainers.image.version": version_label,
                       "org.opencontainers.image.created": BUILT_AT}}})
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as archive:
        member = tarfile.TarInfo("app/main.js")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    image = blob({"schemaVersion": 2, "mediaType": MEDIA,
                  "config": {"mediaType": "application/vnd.oci.image.config.v1+json", **config},
                  "layers": [{**blob(layer.getvalue()), "mediaType": privacy.TAR}]})
    git_source = {"uri": f"https://github.com/fr-meyer/openclaw.git#{source}",
                  "digest": {"sha1": source}}
    statement = {"_type": "https://in-toto.io/Statement/v1", "predicateType": PROVENANCE,
                 "subject": [{"digest": {"sha256": image["digest"][7:]}}],
                 "predicate": {} if legacy else {"buildDefinition": {
                     "externalParameters": {"configSource": {**copy.deepcopy(git_source),
                                                                "path": "Dockerfile"}},
                     "resolvedDependencies": [copy.deepcopy(git_source)]}}}
    if change:
        change(statement)
    attestation_layers = [{**blob(statement), "mediaType": "application/vnd.in-toto+json",
                           "annotations": {"in-toto.io/predicate-type": PROVENANCE}}]
    if include_sbom:
        attestation_layers.append({**blob({"predicateType": "https://spdx.dev/Document"}),
                                   "mediaType": "application/vnd.in-toto+json",
                                   "annotations": {"in-toto.io/predicate-type": "https://spdx.dev/Document"}})
    attestation = blob({"schemaVersion": 2, "mediaType": MEDIA,
                        "config": {**blob({}), "mediaType": privacy.CONFIG}, "layers": attestation_layers})
    index = blob({"schemaVersion": 2, "mediaType": INDEX, "manifests": [
        {**image, "mediaType": MEDIA, "platform": {"os": "linux", "architecture": "amd64"}},
        {**attestation, "mediaType": MEDIA,
         "platform": {"os": "unknown", "architecture": "unknown"},
         "annotations": {"vnd.docker.reference.type": "attestation-manifest",
                         "vnd.docker.reference.digest": image["digest"]}}]})
    (root / "oci-layout").write_text(json.dumps({"imageLayoutVersion": "1.0.0"}))
    (root / "index.json").write_text(json.dumps({"schemaVersion": 2, "manifests": [index]}))
    return {"schema": "openclaw.fork-release-image.v2", "version": VERSION,
            "builtAt": BUILT_AT, "indexDigest": index["digest"], "producer": GITHUB,
            "buildContext": {**CONTEXT, "sourceSha": source}}, image["digest"]


class HostedImageBindingTests(unittest.TestCase):
    def verify(self, root, receipt, manifest=MANIFEST):
        program = """
import {verifyImageLayout, hostedGitBuildContext} from './scripts/fork-release/image.mjs';
const input = JSON.parse(process.argv[1]);
try {
  const result = await verifyImageLayout(input);
  console.log(JSON.stringify({ok:true, imageDigest:result.imageDigest,
                             context:hostedGitBuildContext(input.manifest)}));
} catch (error) {
  console.log(JSON.stringify({ok:false, error:error.message}));
}
"""
        result = subprocess.run(["node", "--input-type=module", "-e", program,
                                 json.dumps({"manifest": manifest, "receipt": receipt,
                                             "ociDir": str(root)})],
                                cwd=ROOT, capture_output=True, text=True, timeout=20, check=True)
        return json.loads(result.stdout)

    def test_new_hosted_context_checks_real_oci_closure_and_git_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt, digest = layout(root)
            result = self.verify(root, receipt)
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["imageDigest"], digest)
            self.assertEqual(result["context"], CONTEXT)

    def test_wrong_source_repository_or_checksum_is_rejected(self):
        cases = [
            ("uri", f"https://github.com/other/openclaw.git#{SOURCE}"),
            ("digest", {"sha1": OTHER}),
            ("digest", {"sha1": SOURCE[:7]}),
        ]
        for key, value in cases:
            with self.subTest(key=key, value=value), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                def change(statement):
                    statement["predicate"]["buildDefinition"]["externalParameters"]["configSource"][key] = value
                receipt, _ = layout(root, change)
                result = self.verify(root, receipt)
                self.assertFalse(result["ok"])
                self.assertIn("pinned repository and commit", result["error"])

    def test_missing_or_wrong_material_is_rejected(self):
        for materials in ([], [{"uri": "https://github.com/other/openclaw.git#" + SOURCE,
                                "digest": {"sha1": SOURCE}}],
                          [{"uri": "https://github.com/fr-meyer/openclaw.git#" + SOURCE,
                            "digest": {"sha1": OTHER}}]):
            with self.subTest(materials=materials), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                def change(statement):
                    statement["predicate"]["buildDefinition"]["resolvedDependencies"] = materials
                receipt, _ = layout(root, change)
                result = self.verify(root, receipt)
                self.assertFalse(result["ok"])
                self.assertIn("pinned repository and commit", result["error"])

    def test_provenance_must_name_selected_image(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def change(statement):
                statement["subject"][0]["digest"]["sha256"] = "0" * 64
            receipt, _ = layout(root, change)
            result = self.verify(root, receipt)
            self.assertFalse(result["ok"])
            self.assertIn("selected image manifest", result["error"])

    def test_present_context_is_closed_and_exact(self):
        for context in (None, [], {}, {**CONTEXT, "extra": True},
                        {**CONTEXT, "kind": "local"}, {**CONTEXT, "sourceSha": OTHER},
                        {**CONTEXT, "sourceSha": SOURCE[:7]},
                        {**CONTEXT, "repository": "https://github.com/other/openclaw"}):
            with self.subTest(context=context), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                receipt, _ = layout(root)
                result = self.verify(root, {**receipt, "buildContext": context})
                self.assertFalse(result["ok"])
                self.assertIn("Hosted Git build context", result["error"])

    def test_legacy_hosted_receipt_retains_legacy_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt, _ = layout(root, legacy=True)
            del receipt["buildContext"]
            self.assertTrue(self.verify(root, receipt)["ok"])
            result = self.verify(root, {**receipt, "buildContext": CONTEXT})
            self.assertFalse(result["ok"])
            self.assertIn("pinned repository and commit", result["error"])

    def test_gcp_keeps_native_git_binding_without_hosted_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt, _ = layout(root)
            receipt["producer"] = GCP
            del receipt["buildContext"]
            self.assertTrue(self.verify(root, receipt)["ok"])
            result = self.verify(root, {**receipt, "buildContext": CONTEXT})
            self.assertFalse(result["ok"])
            self.assertIn("Hosted Git build context", result["error"])

    def test_oci_digest_mutation_remains_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt, _ = layout(root)
            index = root / "blobs" / "sha256" / receipt["indexDigest"][7:]
            raw = index.read_bytes()
            index.write_bytes(raw.replace(b'"schemaVersion": 2', b'"schemaVersion": 3'))
            result = self.verify(root, receipt)
            self.assertFalse(result["ok"])
            self.assertIn("OCI blob digest mismatch", result["error"])


class StaticDiagnosticTests(unittest.TestCase):
    """Actual CLI proof with inert source Git objects and no container execution."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.name", "Synthetic Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        (self.source / "package.json").write_text(json.dumps({"version": VERSION}))
        (self.source / "Dockerfile").write_text(
            'ARG OPENCLAW_NODE_BOOKWORM_IMAGE="docker.io/library/node:24.22.1-bookworm@sha256:' + "1" * 64 + '"\n'
            'ARG OPENCLAW_NODE_BOOKWORM_SLIM_IMAGE="docker.io/library/node:24.22.1-bookworm-slim@sha256:' + "2" * 64 + '"\n')
        (self.source / "packages/markdown-core").mkdir(parents=True)
        (self.source / "packages/markdown-core/package.json").write_text(json.dumps({
            "name": "@openclaw/markdown-core", "dependencies": {"markdown-it": "15.0.3"}}))
        (self.source / "extensions/codex").mkdir(parents=True)
        (self.source / "extensions/codex/package.json").write_text(json.dumps({
            "dependencies": {"@openai/codex": "0.160.0"}}))
        (self.source / "pnpm-lock.yaml").write_text(
            "snapshots:\n\n  markdown-it@15.0.3:\n    dependencies:\n      argparse: 3.0.3\n")
        (self.source / "first.test.ts").write_text("export const fixture = 1;\n")
        (self.source / "second.test.ts").write_text("export const fixture = 2;\n")
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "synthetic base")
        base, base_tree = self.git("rev-parse", "HEAD"), self.git("rev-parse", "HEAD^{tree}")
        base_blob = self.git("rev-parse", "HEAD:first.test.ts")
        self.git("tag", "-a", "v2026.10.6", "-m", "synthetic release")
        tag = self.git("rev-parse", "v2026.10.6")
        (self.source / "first.test.ts").write_text("export const fixture = 3;\n")
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "synthetic patch")
        self.sha, self.tree = self.git("rev-parse", "HEAD"), self.git("rev-parse", "HEAD^{tree}")
        self.manifest = self.root / "manifest.json"
        manifest = {"schema": "openclaw.fork-release.v1", "repository": "fr-meyer/openclaw",
                    "candidate": "v2026.10.6-source-only", "productionEligible": False,
                    "source": {"baseCommit": base, "baseTree": base_tree, "commit": self.sha,
                               "tree": self.tree, "patches": [{"commit": self.sha, "tree": self.tree}]},
                    "gates": {"patchLifecycle": ["first.test.ts"], "producerConsumer": ["second.test.ts"]},
                    "image": {"architecture": "amd64", "extensions": "codex,workboard"}}
        self.manifest.write_text(json.dumps(manifest))
        self.inventory = self.root / "inventory.json"
        self.inventory.write_text(json.dumps({"schema": "openclaw.fork-patch-inventory.v1",
            "repository": manifest["repository"], "candidate": manifest["candidate"],
            "manifestSha256": self.digest(self.manifest),
            "upstream": {"tag": "v2026.10.6", "tagObject": tag, "commit": base, "verificationSha256": "d" * 64},
            "patches": [{"id": "fixture", "originCommit": base, "disposition": "adapt",
                         "appliedCommit": self.sha, "rationale": "Synthetic static diagnostic boundary",
                         "evidenceSha256": None, "regressionTests": ["first.test.ts"], "dependsOn": [],
                         "regressionOwner": "fixture", "paths": [{"path": "first.test.ts", "boundary": "container",
                            "sourceCommit": base, "sourceTree": base_tree, "sourceBlob": base_blob,
                            "upstreamBlob": base_blob, "candidateBlob": self.git("rev-parse", "HEAD:first.test.ts")}]}]}))
        self.oci = self.root / "oci"
        self.oci.mkdir()
        self.origin = self.root / "original-build.json"
        self.privacy = self.root / "privacy.json"
        self.output = self.root / "static.json"
        self.marker = self.root / "container-command-invoked"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ("docker", "skopeo"):
            path = self.bin / name
            path.write_text('#!/bin/sh\nprintf invoked > "$STATIC_MARKER"\nexit 97\n')
            path.chmod(0o700)
        self.env = {**os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
                    "STATIC_MARKER": str(self.marker)}

    @staticmethod
    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.source), "-c", "core.hooksPath=/dev/null",
                                        "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
                                       stderr=subprocess.PIPE, text=True).strip()

    def inputs(self, **kwargs):
        image_receipt, image_digest = layout(self.oci, source=self.sha, **kwargs)
        scan = privacy.inspect_layout(self.oci, image_receipt["indexDigest"], self.sha, GITHUB["workflowSha"])
        self.assertTrue(scan["inspectionComplete"], scan)
        origin = {"schema": "openclaw.fork-release-build-origin.v1", "repository": "fr-meyer/openclaw",
                  "sourceSha": self.sha, "sourceTree": self.tree, "manifestSha256": self.digest(self.manifest),
                  "inventorySha256": self.digest(self.inventory), "architecture": "amd64", "version": VERSION,
                  "builtAt": BUILT_AT, "indexDigest": image_receipt["indexDigest"], "imageDigest": image_digest,
                  "configDigest": scan["configDigest"], "producer": GITHUB,
                  "buildContext": {**CONTEXT, "sourceSha": self.sha}}
        self.origin.write_text(json.dumps(origin))
        self.privacy.write_text(json.dumps(scan))
        return origin, scan

    def run_cli(self):
        result = subprocess.run(["node", str(ROOT / "scripts/fork-release/image.mjs"), "inspect-layout",
                                 str(self.manifest), str(self.inventory), str(self.source), str(self.oci),
                                 str(self.origin), str(self.privacy), GITHUB["workflowSha"],
                                 "2026-10-24T00:00:00Z", str(self.output)],
                                cwd=ROOT, env=self.env, capture_output=True, text=True, timeout=20)
        self.assertFalse(self.marker.exists(), "Static diagnostic executed a container transport")
        self.assertEqual(result.stderr, "")
        return result, json.loads(result.stdout)

    def test_actual_static_cli_passes_without_executing_or_sealing_image(self):
        origin, _ = self.inputs()
        result, report = self.run_cli()
        self.assertEqual(result.returncode, 0, report)
        self.assertEqual(report["status"], "passed")
        for key in ("sourceSha", "sourceTree", "indexDigest", "imageDigest", "configDigest", "builtAt"):
            self.assertEqual(report[key], origin[key])
        self.assertTrue(report["staticOnly"])
        self.assertFalse(report["nativeExecuted"])
        self.assertFalse(report["promotable"])
        self.assertFalse(report["productionAuthorized"])
        self.assertEqual(report["originalBuildSha256"], self.digest(self.origin))
        self.assertEqual(report["privacyReceiptSha256"], self.digest(self.privacy))
        self.assertEqual(json.loads(self.output.read_text()), report)
        verify = subprocess.run(["node", str(ROOT / "scripts/fork-release/image.mjs"), "verify",
                                 str(self.manifest), str(self.inventory), str(self.output), str(self.oci)],
                                cwd=ROOT, env=self.env, capture_output=True, text=True, timeout=20)
        self.assertNotEqual(verify.returncode, 0)
        self.assertIn("Wrong image receipt schema", verify.stderr)
        self.assertFalse(self.marker.exists())

    def test_complete_privacy_findings_do_not_skip_independent_static_checks(self):
        _, scan = self.inputs(payload=b"sk-" + b"a" * 40)
        self.assertEqual(scan["status"], "failed")
        self.assertGreater(scan["findingSummary"]["total"], 0)
        result, report = self.run_cli()
        self.assertEqual(result.returncode, 0, report)
        self.assertEqual(report["status"], "passed")
        self.assertFalse(report["promotable"])

    def test_static_verifier_failure_is_redacted(self):
        self.inputs(version_label="private-synthetic-label-not-for-output")
        result, report = self.run_cli()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["reason"], "static.verification_failed")
        self.assertNotIn("private-synthetic-label", result.stdout)

    def test_independent_attestation_requirement_is_checked_after_privacy(self):
        # Privacy's structural/source check does not replace the sealer's
        # independent requirement for both SLSA provenance and an SBOM.
        _, scan = self.inputs(include_sbom=False)
        self.assertTrue(scan["inspectionComplete"])
        result, report = self.run_cli()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["reason"], "static.verification_failed")

    def test_incomplete_wrong_identity_or_expanded_budget_scan_blocks_static(self):
        _, scan = self.inputs()
        for change in ({"inspectionComplete": False}, {"refusal": "unsupported_config"},
                       {"toolingSha": OTHER}, {"sourceSha": OTHER},
                       {"indexDigest": "sha256:" + "0" * 64},
                       {"limits": {**scan["limits"], "json_bytes": 2 ** 40}}):
            with self.subTest(change=change):
                self.privacy.write_text(json.dumps({**scan, **change}))
                if self.output.exists():
                    self.output.unlink()
                result, report = self.run_cli()
                self.assertEqual(result.returncode, 1)
                self.assertEqual(report["status"], "blocked")
                self.assertEqual(report["reason"], "static.privacy_structure_incomplete")

    def test_dirty_source_or_changed_origin_is_blocked_without_container_command(self):
        origin, _ = self.inputs()
        (self.source / "untracked").write_text("fixture")
        _, report = self.run_cli()
        self.assertEqual(report["reason"], "static.source_refused")
        self.output.unlink()
        (self.source / "untracked").unlink()
        self.origin.write_text(json.dumps({**origin, "sourceTree": "0" * 40}))
        _, report = self.run_cli()
        self.assertEqual(report["reason"], "static.input_refused")

    def test_exclusive_output_failure_preserves_existing_receipt_and_redacts_paths(self):
        self.inputs()
        self.output.write_text("existing")
        result, report = self.run_cli()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["reason"], "static.output_unavailable")
        self.assertEqual(self.output.read_text(), "existing")
        self.assertNotIn(str(self.root), result.stdout)

    def test_input_growth_after_initial_stat_cannot_expand_read_budget(self):
        self.inputs()
        preload = self.root / "grow-after-stat.mjs"
        metrics = self.root / "growth-metrics.json"
        # Deterministically grow the exact manifest immediately after its first
        # stat snapshot. Record consumed bytes, not an implementation-only flag:
        # the previous readFileSync(fd) consumed the entire enlarged file.
        preload.write_text("""
import fs from 'node:fs';
import {syncBuiltinESMExports} from 'node:module';
const target = process.env.STATIC_GROW_FILE;
const identity = fs.lstatSync(target);
const originalStat = fs.fstatSync;
const originalRead = fs.readSync;
const originalReadFile = fs.readFileSync;
const counters = {grew:false, readSyncBytes:0, readFileBytes:0};
const selected = (fd) => {
  const value = originalStat(fd);
  return value.dev === identity.dev && value.ino === identity.ino;
};
fs.fstatSync = function(fd, ...args) {
  const value = originalStat(fd, ...args);
  if (!counters.grew && value.dev === identity.dev && value.ino === identity.ino) {
    counters.grew = true;
    fs.appendFileSync(target, Buffer.alloc(2 * 1024 * 1024, 32));
  }
  return value;
};
fs.readSync = function(fd, ...args) {
  const result = originalRead(fd, ...args);
  if (selected(fd)) counters.readSyncBytes += result;
  return result;
};
fs.readFileSync = function(file, ...args) {
  const result = originalReadFile(file, ...args);
  if (typeof file === 'number' && selected(file))
    counters.readFileBytes += Buffer.byteLength(result);
  return result;
};
syncBuiltinESMExports();
process.on('exit', () => fs.writeFileSync(process.env.STATIC_GROW_METRICS,
  JSON.stringify({...counters, bytesRead:Math.max(counters.readSyncBytes, counters.readFileBytes)})));
""")
        self.env.update(STATIC_GROW_FILE=str(self.manifest), STATIC_GROW_METRICS=str(metrics),
                        NODE_OPTIONS="--import " + str(preload))
        result, report = self.run_cli()
        consumed = json.loads(metrics.read_text())
        self.assertTrue(consumed["grew"])
        self.assertGreater(self.manifest.stat().st_size, 1024 * 1024)
        self.assertLessEqual(consumed["bytesRead"], 1024 * 1024 + 1)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["reason"], "static.input_refused")
        self.assertNotIn(str(self.root), result.stdout)


class RetainedGcpQualificationTests(unittest.TestCase):
    """Real CLI owner, private execution, and OCI checks with inert native transports."""

    git = StaticDiagnosticTests.git
    digest = staticmethod(StaticDiagnosticTests.digest)
    inputs = StaticDiagnosticTests.inputs

    @staticmethod
    def private_json(path, value):
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def setUp(self):
        StaticDiagnosticTests.setUp(self)
        origin, _ = self.inputs()
        self.tooling = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
        self.build = self.root / "original-build"
        self.build.mkdir(mode=0o700)
        self.oci.rename(self.build / "oci")
        self.oci = self.build / "oci"
        self.private_json(self.build / "build-metadata.json", {"containerimage.digest": origin["indexDigest"]})
        for name, data in (("build.exit", "0\n"), ("build.log", "synthetic completed build\n")):
            (self.build / name).write_text(data)
            (self.build / name).chmod(0o600)
        self.execution = self.build / "execution.json"
        self.private_json(self.execution, {
            "schema": "openclaw.fork-gcp-image-execution.v1", "operationId": "d" * 32,
            "attempt": "1", "projectNumber": "123", "instanceId": "456", "toolingSha": "c" * 40,
            "sourceSha": self.sha, "sourceTree": self.tree,
            "manifestSha256": self.digest(self.manifest), "inventorySha256": self.digest(self.inventory),
            "indexDigest": origin["indexDigest"], "builtAt": BUILT_AT,
            "startedAt": "2026-10-23T10:01:00Z", "completedAt": "2026-10-23T10:02:00Z",
            "buildExitCode": 0, "buildMetadataSha256": self.digest(self.build / "build-metadata.json"),
            "buildLogSha256": self.digest(self.build / "build.log")})
        self.resources = self.build / "original-resources.json"
        self.private_json(self.resources, {"historicalBuildConfig": {"builderMemoryBytes": 8 * 1024 ** 3}})
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.base_path = self.state / "base-plan.json"
        self.base = {
            "schema": "openclaw.retained-gcp-input.v1", "manifestPath": str(self.manifest),
            "inventoryPath": str(self.inventory), "sourceDir": str(self.source), "ociDir": str(self.oci),
            "executionPath": str(self.execution), "originalToolingSha": "c" * 40,
            "executionSha256": self.digest(self.execution), "inspectionToolingSha": self.tooling}
        self.private_json(self.base_path, self.base)
        self.resource_path = self.state / "resource-admission.json"
        now = datetime.now(timezone.utc).replace(microsecond=0)
        self.resource = {
            "schema": "openclaw.fork-release-reinspection-resource-admission.v1",
            "sourceSha": self.sha, "indexDigest": origin["indexDigest"], "inspectionToolingSha": self.tooling,
            "checkedAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expiresAt": (now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"), "status": "passed",
            "checks": {"capacity": "passed", "ownership": "passed", "heavyWorkload": "clear"}}
        self.private_json(self.resource_path, self.resource)
        self.plan_path = self.state / "qualify-plan.json"
        self.output = self.state / "qualification"
        self.output.mkdir(mode=0o700)
        self.native_log = self.state / "native-calls.jsonl"
        # Only the isolated test pretends the installed inspection checkout is
        # clean; every source Git/preflight and byte verification remains real.
        # Docker/Skopeo are intercepted before invocation, not replaced by a
        # production qualification API that could fabricate native success.
        self.preload = self.state / "native-transport-spy.mjs"
        self.preload.write_text(r"""
import cp from 'node:child_process';
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import {syncBuiltinESMExports} from 'node:module';
const execute = cp.execFileSync;
const open = fs.openSync;
fs.openSync = function(path, ...args) {
  if (process.env.RETAINED_FAIL_ADMISSION === 'yes' && String(path).endsWith('/admission.json'))
    throw new Error('synthetic admission persistence failure');
  return open(path, ...args);
};
const NativeDate = Date;
let clockOffset = Number(process.env.RETAINED_CLOCK_OFFSET_MS || 0);
let elapsed = 0;
Object.defineProperty(performance, 'now', {value: () => elapsed});
globalThis.Date = class extends NativeDate {
  constructor(...args) { super(...(args.length ? args : [NativeDate.now() + clockOffset])); }
  static now() { return NativeDate.now() + clockOffset; }
};
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
Atomics.wait = function(_array, _index, _value, milliseconds) {
  elapsed += milliseconds;
  const mode = process.env.RETAINED_RESOURCE_RESPONSE || 'none';
  if (mode === 'none') return 'timed-out';
  const root = process.env.RETAINED_OUTPUT + '/resource-refresh';
  for (const name of fs.readdirSync(root).filter((value) => /^\d\d-request\.json$/.test(value))) {
    const prefix = root + '/' + name.slice(0, 2);
    if (fs.existsSync(prefix + '-response.json')) continue;
    const raw = fs.readFileSync(root + '/' + name), request = JSON.parse(raw);
    const now = new Date();
    const stamp = (date) => date.toISOString().replace(/\.\d{3}Z$/, 'Z');
    const resource = {schema:'openclaw.fork-release-reinspection-resource-admission.v1',
      sourceSha:request.sourceSha,indexDigest:request.indexDigest,inspectionToolingSha:request.inspectionToolingSha,
      checkedAt:stamp(now),expiresAt:stamp(new Date(now.getTime() + 300000)),status:'passed',
      checks:{capacity:'passed',ownership:'passed',heavyWorkload:'clear'}};
    if (mode === 'wrong-source') resource.sourceSha = 'f'.repeat(40);
    if (mode === 'stale') {
      resource.checkedAt = stamp(new Date(now.getTime() - 600000));
      resource.expiresAt = stamp(new Date(now.getTime() - 300000));
    }
    const bytes = JSON.stringify(resource);
    fs.writeFileSync(prefix + '-admission.json', bytes, {flag:'wx',mode:0o600});
    const response = {schema:'openclaw.retained-resource-response.v1',qualificationId:request.qualificationId,
      nonce:request.nonce,requestSha256:digest(raw),resourceAdmissionSha256:digest(bytes)};
    if (mode === 'wrong-hash') response.resourceAdmissionSha256 = 'f'.repeat(64);
    if (mode === 'replayed') response.nonce = 'f'.repeat(32);
    if (mode === 'wrong-request') response.requestSha256 = 'f'.repeat(64);
    fs.writeFileSync(prefix + '-response.json', JSON.stringify(response), {flag:'wx',mode:0o600});
  }
  return 'timed-out';
};
process.on('exit', () => fs.writeFileSync(process.env.RETAINED_WAIT_METRICS, JSON.stringify({elapsedMs:elapsed})));
cp.execFileSync = function(command, args, options) {
  if (command === 'git' && args[0] === '-C' &&
      fs.realpathSync(args[1]) === fs.realpathSync(process.env.RETAINED_TOOLING_ROOT) && args[2] === 'status') return '';
  if (command !== 'docker' && command !== 'skopeo') {
    const result = execute(command, args, options);
    if (command === 'python3' && args.some((value) => value.endsWith('/preflight.py')))
      clockOffset += Number(process.env.RETAINED_STATIC_ELAPSED_MS || 0);
    return result;
  }
  fs.appendFileSync(process.env.RETAINED_NATIVE_LOG, JSON.stringify({command,args}) + '\n');
  if (process.env.RETAINED_NATIVE_FAIL === 'yes') throw new Error('synthetic native transport refused');
  if (command === 'skopeo') { clockOffset += Number(process.env.RETAINED_IMPORT_ELAPSED_MS || 0); return ''; }
  if (args[0] === 'image' && args[1] === 'inspect')
    return (process.env.RETAINED_INSPECT_DIGEST || process.env.RETAINED_CONFIG_DIGEST) + '\n';
  if (args[0] === 'create') {
    const plugin = args.includes('/tmp/verify-image-plugins.mjs');
    if (plugin) clockOffset += Number(process.env.RETAINED_PLUGIN_CREATE_ELAPSED_MS || 0);
    return (plugin ? 'b' : 'a').repeat(64) + '\n';
  }
  if (args[0] === 'start') return args.at(-1) === 'b'.repeat(64) ? fs.readFileSync(process.env.RETAINED_NATIVE_PROOF,'utf8') : '';
  if (args[0] === 'inspect') return args.includes('{{.State.Running}} {{.State.ExitCode}} {{.State.OOMKilled}}') ? 'false 0 false' : 'false 0';
  if (args[0] === 'rm') return '';
  throw new Error('Unexpected synthetic native command');
};
syncBuiltinESMExports();
""")
        from test_hosted_export import runtime_fixture
        runtime = runtime_fixture(origin)
        runtime["expected"].update({
            "dockerfileSha256": self.digest(self.source / "Dockerfile"),
            "consumerManifestSha256": self.digest(self.source / "packages/markdown-core/package.json"),
            "lockfileSha256": self.digest(self.source / "pnpm-lock.yaml")})
        self.proof = self.state / "native-proof.json"
        self.private_json(self.proof, {"runtime": runtime, "plugins": [
            {"id": "codex", "package": "@openclaw/codex", "version": VERSION,
             "codexRuntime": {"cliVersion": "0.160.0", "packageVersion": "0.160.0",
                              "initializeVersion": "0.160.0", "initialized": True, "shutdown": "exited"}},
            {"id": "workboard", "package": "@openclaw/workboard", "version": VERSION,
             "workboardRuntime": {"worker": "sqlite", "roundTrip": True, "closed": True}}]})
        self.env.update(NODE_OPTIONS="--import " + str(self.preload), RETAINED_TOOLING_ROOT=str(ROOT),
                        RETAINED_NATIVE_LOG=str(self.native_log), RETAINED_NATIVE_PROOF=str(self.proof),
                        RETAINED_CONFIG_DIGEST=origin["configDigest"], RETAINED_OUTPUT=str(self.output),
                        RETAINED_WAIT_METRICS=str(self.state / "wait-metrics.json"))
        # There is deliberately no fabricated hosted producer environment.
        for key in tuple(self.env):
            if key.startswith("GITHUB_"):
                del self.env[key]
        self.set_privacy()

    def set_privacy(self, **changes):
        index = json.loads(self.execution.read_text())["indexDigest"]
        scan = privacy.inspect_layout(self.oci, index, self.sha, self.tooling)
        self.private_json(self.privacy, {**scan, **changes})
        self.plan = {**self.base, "schema": "openclaw.retained-gcp-qualification.v1",
                     "privacyPath": str(self.privacy), "privacySha256": self.digest(self.privacy),
                     "resourceAdmissionPath": str(self.resource_path),
                     "resourceAdmissionSha256": self.digest(self.resource_path),
                     "originalResourcesPath": str(self.resources), "originalResourcesSha256": self.digest(self.resources)}
        self.private_json(self.plan_path, self.plan)

    def run_owner(self, command="qualify-retained-gcp", plan=None, output=None):
        env = dict(self.env)
        if command == "qualify-retained-gcp":
            env["RETAINED_OUTPUT"] = str(output or self.output)
        result = subprocess.run(["node", str(ROOT / "scripts/fork-release/image.mjs"), command,
                                 str(plan or self.plan_path), str(output or self.output)],
                                cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
        self.assertFalse(self.marker.exists(), "A real native transport was invoked")
        self.assertEqual(result.stderr, "")
        self.assertNotIn(str(self.root), result.stdout)
        return result, json.loads(result.stdout)

    def test_original_capture_and_reinspection_preserve_producer_and_release_handoff(self):
        capture = self.state / "captured.json"
        result, context = self.run_owner("capture-retained-gcp-origin", self.base_path, capture)
        self.assertEqual(result.returncode, 0, context)
        self.assertFalse(self.native_log.exists())
        self.assertEqual(context["producer"]["toolingSha"], "c" * 40)
        self.assertEqual(context["executionSha256"], self.digest(self.execution))
        result, report = self.run_owner()
        self.assertEqual(result.returncode, 0, report)
        self.assertTrue(report["qualified"])
        receipt = self.output / "receipt.json"
        value = json.loads(receipt.read_text())
        self.assertEqual(value["builtAt"], BUILT_AT)
        self.assertEqual(value["producer"], context["producer"])
        self.assertEqual(value["reinspection"]["inspectionToolingSha"], self.tooling)
        self.assertNotEqual(value["producer"]["toolingSha"], self.tooling)
        calls = self.native_log.read_bytes()
        self.env["RETAINED_CLOCK_OFFSET_MS"] = "600000"
        verified, proof = self.run_owner("verify-retained-gcp", output=receipt)
        self.assertEqual(verified.returncode, 0, proof)
        self.assertEqual(self.native_log.read_bytes(), calls, "Verification re-executed native code")
        import release
        self.assertEqual(release.receipt_at(receipt, json.loads(self.manifest.read_text()),
                                           self.digest(self.manifest), self.digest(self.inventory)), value)
        with self.assertRaises(Exception):
            release.receipt_at(self.output / "native.json", json.loads(self.manifest.read_text()),
                               self.digest(self.manifest), self.digest(self.inventory))
        # Completed verification is historical: resource freshness is checked at
        # recorded guard times, not made into a new host admission claim.
        self.assertFalse(proof["productionAuthorized"])

    def test_explicit_loaded_transport_uses_index_without_skopeo_and_binds_mode(self):
        self.base["smokeTransport"] = "loaded"
        self.private_json(self.base_path, self.base)
        self.set_privacy()
        index = self.resource["indexDigest"]
        self.env["RETAINED_INSPECT_DIGEST"] = index
        result, report = self.run_owner()
        self.assertEqual(result.returncode, 0, report)
        calls = self.native_log.read_bytes()
        entries = [json.loads(line) for line in calls.splitlines()]
        self.assertFalse(any(entry["command"] == "skopeo" for entry in entries))
        inspected = next(entry for entry in entries if entry["args"][:2] == ["image", "inspect"])
        self.assertEqual(inspected["args"][-1], index)
        for entry in entries:
            if entry["args"][0] == "create":
                self.assertIn(index, entry["args"])
                platform = entry["args"].index("--platform")
                self.assertEqual(entry["args"][platform + 1], "linux/amd64")
        admission = json.loads((self.output / "admission.json").read_text())
        capture = json.loads((self.output / "native-execution.json").read_text())
        self.assertEqual(admission["smokeTransport"], "loaded")
        self.assertEqual(capture["smokeTransport"], "loaded")
        result, verified = self.run_owner("verify-retained-gcp", output=self.output / "receipt.json")
        self.assertEqual(result.returncode, 0, verified)
        self.assertEqual(self.native_log.read_bytes(), calls)
        del self.plan["smokeTransport"]
        self.private_json(self.plan_path, self.plan)
        result, _ = self.run_owner("verify-retained-gcp", output=self.output / "receipt.json")
        self.assertNotEqual(result.returncode, 0, "Loaded evidence was relabeled as default Skopeo")
        self.assertEqual(self.native_log.read_bytes(), calls)

    def test_loaded_transport_rejects_config_digest_as_index_before_native_start(self):
        self.base["smokeTransport"] = "loaded"
        self.set_privacy()
        result, report = self.run_owner()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["privacy"], "passed", report)
        self.assertEqual(report["static"], "passed", report)
        calls = [json.loads(line) for line in self.native_log.read_text().splitlines()]
        self.assertTrue(calls)
        self.assertFalse(any(entry["command"] == "skopeo" or entry["args"][0] in ("create", "start", "run")
                             for entry in calls))
        self.assertFalse((self.output / "receipt.json").exists())

    def test_optional_transport_rejects_every_value_except_loaded(self):
        for index, value in enumerate((None, False, "skopeo", "auto")):
            with self.subTest(value=value):
                self.base["smokeTransport"] = value
                self.set_privacy()
                target = self.state / ("transport-" + str(index))
                target.mkdir(mode=0o700)
                result, report = self.run_owner(output=target)
                self.assertEqual(result.returncode, 1)
                self.assertFalse(report["qualified"])
                self.assertFalse(self.native_log.exists())

    def test_findings_still_collect_static_without_native_or_admission(self):
        scan = json.loads(self.privacy.read_text())
        self.set_privacy(status="failed", findings=[{"rule": "synthetic"}],
                         findingSummary={**scan["findingSummary"], "total": 1})
        result, report = self.run_owner()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["static"], "passed", report)
        self.assertEqual(report["privacy"], "failed")
        self.assertEqual(report["native"], "blocked")
        self.assertTrue((self.output / "static.json").exists())
        self.assertFalse(self.native_log.exists())
        for name in ("native-attempt.json", "receipt.json", "admission.json"):
            self.assertFalse((self.output / name).exists(), name)

    def test_incomplete_privacy_blocks_static_and_native(self):
        self.set_privacy(inspectionComplete=False)
        result, report = self.run_owner()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["static"], "blocked")
        self.assertFalse(self.native_log.exists())
        self.assertFalse((self.output / "receipt.json").exists())

    def test_wrong_original_pin_or_log_is_refused_without_native(self):
        for mutation in ("tooling", "execution", "log", "source"):
            with self.subTest(mutation=mutation):
                value = dict(self.base)
                if mutation == "tooling": value["originalToolingSha"] = "f" * 40
                elif mutation == "execution": value["executionSha256"] = "f" * 64
                elif mutation == "log": (self.build / "build.log").write_text("changed")
                else: (self.source / "untracked").write_text("changed")
                self.private_json(self.base_path, value)
                result, report = self.run_owner("capture-retained-gcp-origin", self.base_path,
                                                self.state / (mutation + ".json"))
                self.assertEqual(result.returncode, 1, report)
                self.assertFalse(self.native_log.exists())
                (self.build / "build.log").write_text("synthetic completed build\n")
                if (self.source / "untracked").exists(): (self.source / "untracked").unlink()

    def test_stale_resource_after_static_blocks_native(self):
        self.resource.update(checkedAt="2026-10-23T10:01:00Z", expiresAt="2026-10-23T10:02:00Z")
        self.private_json(self.resource_path, self.resource)
        self.set_privacy()
        result, report = self.run_owner()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["static"], "passed", report)
        self.assertEqual(report["privacy"], "passed")
        self.assertFalse(self.native_log.exists())
        self.assertFalse((self.output / "native-attempt.json").exists())

    def test_native_failure_marks_uncertainty_and_cannot_rerun(self):
        self.env["RETAINED_NATIVE_FAIL"] = "yes"
        result, report = self.run_owner()
        self.assertEqual(result.returncode, 1)
        self.assertTrue((self.output / "native-attempt.json").exists(), report)
        calls = self.native_log.read_bytes()
        self.assertFalse((self.output / "receipt.json").exists())
        self.assertFalse((self.output / "admission.json").exists())
        result, report = self.run_owner()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.native_log.read_bytes(), calls)

    def test_import_expiry_consumes_fresh_owner_response_without_reimport_and_verifies_history(self):
        self.env.update(RETAINED_IMPORT_ELAPSED_MS="301000", RETAINED_RESOURCE_RESPONSE="fresh")
        result, report = self.run_owner()
        self.assertEqual(result.returncode, 0, report)
        calls = self.native_log.read_bytes()
        entries = [json.loads(line) for line in calls.splitlines()]
        self.assertEqual(sum(entry["command"] == "skopeo" for entry in entries), 1)
        admission = json.loads((self.output / "admission.json").read_text())
        self.assertEqual(len(admission["resourceRefreshes"]), 1)
        self.assertEqual([entry["refreshSequence"] for entry in admission["resourceChecks"]], [0, 1, 1])
        request = json.loads((self.output / "resource-refresh/01-request.json").read_text())
        self.assertEqual(request["boundary"], "workspace")
        self.assertEqual(request["originalOperationId"], "d" * 32)
        self.assertEqual(request["qualificationId"], admission["qualificationId"])
        capture = json.loads((self.output / "native-execution.json").read_text())
        self.assertEqual(capture["resourceAdmissionSha256"], admission["resourceRefreshes"][0]["resourceAdmissionSha256"])
        self.assertNotEqual(capture["resourceAdmissionSha256"], self.plan["resourceAdmissionSha256"])
        self.env["RETAINED_CLOCK_OFFSET_MS"] = "900000"
        result, verified = self.run_owner("verify-retained-gcp", output=self.output / "receipt.json")
        self.assertEqual(result.returncode, 0, verified)
        self.assertEqual(self.native_log.read_bytes(), calls)
        (self.output / "resource-refresh/01-response.json").write_text("{}")
        result, verified = self.run_owner("verify-retained-gcp", output=self.output / "receipt.json")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.native_log.read_bytes(), calls)

    def test_static_expiry_consumes_fresh_owner_response_before_single_import(self):
        self.env.update(RETAINED_STATIC_ELAPSED_MS="301000", RETAINED_RESOURCE_RESPONSE="fresh")
        result, report = self.run_owner()
        self.assertEqual(result.returncode, 0, report)
        request = json.loads((self.output / "resource-refresh/01-request.json").read_text())
        self.assertEqual(request["boundary"], "import")
        calls = [json.loads(line) for line in self.native_log.read_text().splitlines()]
        self.assertEqual(sum(entry["command"] == "skopeo" for entry in calls), 1)
        self.assertEqual(len(json.loads((self.output / "admission.json").read_text())["resourceRefreshes"]), 1)

    def test_wrong_stale_hash_or_replayed_refresh_never_starts_native(self):
        self.env["RETAINED_IMPORT_ELAPSED_MS"] = "301000"
        for index, mode in enumerate(("wrong-source", "stale", "wrong-hash", "replayed", "wrong-request")):
            with self.subTest(mode=mode):
                self.env["RETAINED_RESOURCE_RESPONSE"] = mode
                target = self.state / ("refresh-" + str(index))
                target.mkdir(mode=0o700)
                result, report = self.run_owner(output=target)
                self.assertEqual(result.returncode, 1, report)
                calls = [json.loads(line) for line in self.native_log.read_text().splitlines()]
                self.assertFalse(any(entry["command"] == "docker" and entry["args"][0] in ("start", "run")
                                     for entry in calls))
                self.assertEqual(sum(entry["command"] == "skopeo" for entry in calls), index + 1)
                self.assertFalse((target / "receipt.json").exists())
                self.assertFalse((target / "admission.json").exists())
    def test_import_outliving_admission_never_starts_native_and_cleans_owned_container(self):
        self.env["RETAINED_IMPORT_ELAPSED_MS"] = "301000"
        result, report = self.run_owner()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["static"], "passed", report)
        calls = [json.loads(line) for line in self.native_log.read_text().splitlines()]
        self.assertEqual(calls[0]["command"], "skopeo")
        self.assertFalse(any(entry["command"] == "docker" and entry["args"][0] in ("start", "run")
                             for entry in calls), "Native execution occurred after admission expiry")
        self.assertEqual(calls[-1], {"command": "docker", "args": ["rm", "--force", "a" * 64]})
        self.assertFalse((self.output / "receipt.json").exists())
        self.assertFalse((self.output / "admission.json").exists())
        self.assertEqual(json.loads((self.state / "wait-metrics.json").read_text())["elapsedMs"], 60000)

    def test_failed_admission_persistence_cannot_publish_consumable_native_facts(self):
        self.env["RETAINED_FAIL_ADMISSION"] = "yes"
        result, report = self.run_owner()
        self.assertEqual(result.returncode, 1)
        facts = json.loads((self.output / "native.json").read_text())
        self.assertEqual(facts["schema"], "openclaw.retained-native-facts.v1")
        self.assertFalse(facts["promotable"])
        self.assertFalse((self.output / "receipt.json").exists())
        self.assertFalse((self.output / "admission.json").exists())

    def test_plugin_create_outliving_admission_never_starts_plugin_and_cleans_owned_container(self):
        self.env["RETAINED_PLUGIN_CREATE_ELAPSED_MS"] = "301000"
        result, report = self.run_owner()
        self.assertEqual(result.returncode, 1)
        calls = [json.loads(line) for line in self.native_log.read_text().splitlines()]
        starts = [entry["args"][-1] for entry in calls if entry["command"] == "docker" and entry["args"][0] == "start"]
        self.assertEqual(starts, ["a" * 64])
        self.assertEqual(calls[-1], {"command": "docker", "args": ["rm", "--force", "b" * 64]})
        self.assertFalse((self.output / "receipt.json").exists())

    def test_resource_pin_identity_lifetime_and_unknown_checks_fail_closed(self):
        for index, change in enumerate(({"sourceSha": OTHER}, {"indexDigest": "sha256:" + "f" * 64},
                                        {"inspectionToolingSha": OTHER},
                                        {"expiresAt": "2099-01-01T00:00:00Z"},
                                        {"checks": {**self.resource["checks"], "extra": "passed"}})):
            with self.subTest(change=change):
                self.private_json(self.resource_path, {**self.resource, **change})
                self.set_privacy()
                target = self.state / ("resource-case-" + str(index))
                target.mkdir(mode=0o700)
                result, report = self.run_owner(output=target)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(report["privacy"], "passed", report)
                self.assertEqual(report["static"], "passed", report)
                self.assertFalse(self.native_log.exists())


    def test_verification_rejects_changed_evidence_and_missing_commit_record(self):
        result, report = self.run_owner()
        self.assertEqual(result.returncode, 0, report)
        calls = self.native_log.read_bytes()
        for name in ("admission.json", "native-attempt.json", "native-execution.json", "native.json", "static.json"):
            with self.subTest(name=name):
                path = self.output / name
                original = path.read_bytes()
                path.write_text("{}")
                result, report = self.run_owner("verify-retained-gcp", output=self.output / "receipt.json")
                self.assertEqual(result.returncode, 1, report)
                path.write_bytes(original)
        self.assertEqual(self.native_log.read_bytes(), calls)

    def test_verification_rejects_orphans_and_unbound_root_metadata_changes(self):
        result, report = self.run_owner()
        self.assertEqual(result.returncode, 0, report)
        calls = self.native_log.read_bytes()
        for relative in ("unexpected-file", "blobs/sha256/" + "f" * 64, "index.json", "oci-layout"):
            with self.subTest(relative=relative):
                path = self.oci / relative
                original = path.read_bytes() if path.exists() else None
                if original is None:
                    path.write_text("unexpected")
                else:
                    value = json.loads(original)
                    value["unboundMetadata"] = "public changed metadata"
                    path.write_text(json.dumps(value))
                result, report = self.run_owner("verify-retained-gcp", output=self.output / "receipt.json")
                self.assertEqual(result.returncode, 1, report)
                if original is None:
                    path.unlink()
                else:
                    path.write_bytes(original)
        self.assertEqual(self.native_log.read_bytes(), calls)


if __name__ == "__main__":
    unittest.main()

"""Synthetic OCI closure/provenance checks through the actual image verifier."""

import copy
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


if __name__ == "__main__":
    unittest.main()

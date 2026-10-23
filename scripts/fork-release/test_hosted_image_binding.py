"""Synthetic OCI closure/provenance checks through the actual image verifier."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


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


def layout(root, change=None, legacy=False):
    def blob(value):
        raw = json.dumps(value, sort_keys=True).encode()
        digest = hashlib.sha256(raw).hexdigest()
        target = root / "blobs" / "sha256" / digest
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        return {"digest": "sha256:" + digest, "size": len(raw)}

    config = blob({"architecture": "amd64", "os": "linux",
                   "config": {"Labels": {
                       "org.opencontainers.image.revision": SOURCE,
                       "org.opencontainers.image.version": VERSION,
                       "org.opencontainers.image.created": BUILT_AT}}})
    image = blob({"schemaVersion": 2, "mediaType": MEDIA,
                  "config": {"mediaType": "application/vnd.oci.image.config.v1+json", **config},
                  "layers": []})
    git_source = {"uri": f"https://github.com/fr-meyer/openclaw.git#{SOURCE}",
                  "digest": {"sha1": SOURCE}}
    statement = {"_type": "https://in-toto.io/Statement/v1", "predicateType": PROVENANCE,
                 "subject": [{"digest": {"sha256": image["digest"][7:]}}],
                 "predicate": {} if legacy else {"buildDefinition": {
                     "externalParameters": {"configSource": {**copy.deepcopy(git_source),
                                                                "path": "Dockerfile"}},
                     "resolvedDependencies": [copy.deepcopy(git_source)]}}}
    if change:
        change(statement)
    attestation = blob({"schemaVersion": 2, "mediaType": MEDIA,
                        "config": blob({}), "layers": [
                            {**blob(statement), "mediaType": "application/vnd.in-toto+json",
                             "annotations": {"in-toto.io/predicate-type": PROVENANCE}},
                            {**blob({"predicateType": "https://spdx.dev/Document"}),
                             "mediaType": "application/vnd.in-toto+json",
                             "annotations": {"in-toto.io/predicate-type": "https://spdx.dev/Document"}}]})
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
            "buildContext": CONTEXT}, image["digest"]


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


if __name__ == "__main__":
    unittest.main()

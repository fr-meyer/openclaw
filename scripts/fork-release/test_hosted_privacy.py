"""Synthetic OCI fixtures only; no application images, databases or credentials."""

import dataclasses
import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

import hosted_privacy as privacy


SOURCE = "a" * 40
TOOLING = "b" * 40


def archive(entries):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w", format=tarfile.PAX_FORMAT) as output:
        for name, data in entries:
            member = tarfile.TarInfo(name)
            if isinstance(data, tuple):
                member.type, member.linkname = data
                output.addfile(member)
            else:
                member.size = len(data)
                output.addfile(member, io.BytesIO(data))
    return result.getvalue()


class Layout:
    def __init__(self, directory, layers=None, config=None, provenance=None):
        self.directory = Path(directory)
        (self.directory / "blobs" / "sha256").mkdir(parents=True)
        (self.directory / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
        config = config or {"os": "linux", "architecture": "amd64", "config": {
            "Env": ["NODE_ENV=production"],
            "Labels": {"org.opencontainers.image.revision": SOURCE}},
            "history": [{"created_by": "COPY /app/dist /app/dist"}]}
        self.config = config
        self.layers = layers or [(privacy.GZIP, gzip.compress(archive([("app/main.js", b"console.log('public');")])))]
        runtime = self.blob({"schemaVersion": 2, "mediaType": privacy.MANIFEST,
                             "config": self.blob(config, privacy.CONFIG),
                             "layers": [self.blob(data, media) for media, data in self.layers]}, privacy.MANIFEST)
        runtime["platform"] = {"os": "linux", "architecture": "amd64"}
        self.runtime = runtime
        source = {"uri": "https://github.com/fr-meyer/openclaw.git#" + SOURCE, "digest": {"sha1": SOURCE}}
        statement = {"predicateType": privacy.PROVENANCE,
                     "subject": [{"digest": {"sha256": runtime["digest"][7:]}}],
                     "predicate": {"buildDefinition": {"externalParameters": {"configSource": source},
                                                        "resolvedDependencies": [source]}}}
        if provenance:
            provenance(statement)
        attested = self.blob({"schemaVersion": 2, "mediaType": privacy.MANIFEST,
                              "config": self.blob({}, privacy.CONFIG),
                              "layers": [self.blob(statement, privacy.ATTESTATION)]}, privacy.MANIFEST)
        attested.update({"platform": {"os": "unknown", "architecture": "unknown"}, "annotations": {
            "vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": runtime["digest"]}})
        self.index = self.blob({"schemaVersion": 2, "mediaType": privacy.INDEX,
                               "manifests": [runtime, attested]}, privacy.INDEX)
        (self.directory / "index.json").write_text(json.dumps({"schemaVersion": 2, "manifests": [self.index]}))

    def blob(self, data, media):
        data = data if isinstance(data, bytes) else json.dumps(data).encode()
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        (self.directory / "blobs" / "sha256" / digest[7:]).write_bytes(data)
        return {"mediaType": media, "digest": digest, "size": len(data)}

    def inspect(self, **kwargs):
        return privacy.inspect_layout(self.directory, self.index["digest"], SOURCE, TOOLING, **kwargs)


class PrivacyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def layout(self, **kwargs):
        return Layout(self.temp.name, **kwargs)

    def files(self, entries, compressed=True, **kwargs):
        data = archive(entries)
        return self.layout(layers=[(privacy.GZIP if compressed else privacy.TAR,
                                   gzip.compress(data) if compressed else data)], **kwargs)

    def test_public_image_passes_and_binds_identities(self):
        fixture = self.layout()
        receipt = fixture.inspect()
        self.assertEqual(receipt["status"], "passed", receipt)
        self.assertTrue(receipt["inspectionComplete"])
        self.assertEqual(receipt["schema"], "openclaw.hosted-privacy.v1")
        self.assertEqual(receipt["indexDigest"], fixture.index["digest"])
        self.assertEqual(receipt["sourceSha"], SOURCE)
        self.assertEqual(receipt["toolingSha"], TOOLING)
        self.assertEqual(receipt["counts"]["files"], 1)
        self.assertTrue(receipt["heuristicOnly"])

    def test_uncompressed_layer_and_normal_container_symlinks(self):
        result = self.files([("usr/bin/tool", b"public"),
                             ("bin/tool", (tarfile.SYMTYPE, "/usr/bin/tool")),
                             ("bin/other", (tarfile.SYMTYPE, "../usr/bin/tool")),
                             ("usr/bin/hard", (tarfile.LNKTYPE, "usr/bin/tool"))], compressed=False).inspect()
        self.assertEqual(result["status"], "passed", result)

    def test_private_runtime_paths(self):
        for name in ("app/.env", "app/.env.production", "home/node/.openclaw/config.json",
                     "root/.aws/credentials", "tmp/cookies.txt", "data/openclaw-agent.sqlite-wal"):
            with self.subTest(path=name), tempfile.TemporaryDirectory() as directory:
                result = Layout(directory, layers=[(privacy.TAR, archive([(name, b"synthetic")]))]).inspect()
                self.assertEqual(result["status"], "failed")
                self.assertTrue(result["inspectionComplete"])
                self.assertIn("private_runtime_path", [item["rule"] for item in result["findings"]])
                self.assertNotIn(name, json.dumps(result))

    def test_credentials_split_across_chunks_and_db_header(self):
        payload = b"x" * (privacy.CHUNK - 10) + b"-----BEGIN PRIVATE KEY-----\n" + b"A" * 64 + b"\n-----END PRIVATE KEY-----"
        result = self.files([("app/data", payload), ("tmp/unknown", b"SQLite format 3\0synthetic")]).inspect()
        self.assertEqual({item["rule"] for item in result["findings"]}, {"private_key", "sqlite_database_payload"})
        self.assertNotIn("BEGIN PRIVATE KEY", json.dumps(result))

    def test_public_pem_parser_literal_and_arbitrary_metadata_pass(self):
        def provenance(statement):
            statement["predicate"]["metadata"] = {"token": "public parser category"}
        result = self.files([("app/parser.js", b"const marker = '-----BEGIN PRIVATE KEY-----';"),
                             ("app/docs/example.md", b"-----BEGIN PRIVATE KEY-----\n<insert your private key>")],
                            provenance=provenance).inspect()
        self.assertEqual(result["status"], "passed", result)

    def test_encrypted_pem_body_and_small_stream_chunks(self):
        payload = (b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"
                   b"DEK-Info: AES-256-CBC,00000000\n\n" + b"A" * 64 + b"\n")
        result = self.files([("app/material", payload)]).inspect()
        self.assertEqual([item["rule"] for item in result["findings"]], ["private_key"])

    def test_deleted_and_overwritten_layer_is_still_inspected(self):
        older = archive([("app/leak", b"ghp_" + b"X" * 36)])
        later = archive([("app/leak", b"clean"), ("app/.wh.leak", b"")])
        result = self.layout(layers=[(privacy.TAR, older), (privacy.TAR, later)]).inspect()
        self.assertEqual(result["counts"]["layers"], 2)
        self.assertEqual(result["status"], "failed")
        self.assertIn("github_token", [item["rule"] for item in result["findings"]])

    def test_config_env_history_and_provenance_scanned(self):
        config = {"os": "linux", "architecture": "amd64", "config": {
            "Labels": {"org.opencontainers.image.revision": SOURCE}, "Env": ["OPENAI_API_KEY=fixture-secret"]},
            "history": [{"created_by": "RUN ghp_" + "Z" * 36}]}
        def provenance(statement):
            statement["predicate"]["buildDefinition"]["externalParameters"]["build-arg:PASSWORD"] = "synthetic"
        result = self.layout(config=config, provenance=provenance).inspect()
        self.assertEqual({item["rule"] for item in result["findings"]},
                         {"sensitive_environment_value", "github_token", "sensitive_metadata_value"})
        self.assertNotIn("fixture-secret", json.dumps(result))

    def test_wrong_source_and_index_refused(self):
        fixture = self.layout()
        result = privacy.inspect_layout(fixture.directory, fixture.index["digest"], "c" * 40, TOOLING)
        self.assertEqual(result["refusal"], "config_source_mismatch")
        result = privacy.inspect_layout(fixture.directory, "sha256:" + "c" * 64, SOURCE, TOOLING)
        self.assertEqual(result["refusal"], "index_binding_mismatch")

    def test_wrong_provenance_refused(self):
        def mutate(statement):
            statement["predicate"]["buildDefinition"]["externalParameters"]["configSource"]["uri"] = "https://example.invalid/private"
        result = self.layout(provenance=mutate).inspect()
        self.assertEqual(result["refusal"], "provenance_source_mismatch")

    def test_unsupported_format_and_bad_gzip_refused(self):
        for media, data in ((privacy.TAR + "+zstd", b"not supported"), (privacy.GZIP, b"broken gzip"),
                            (privacy.TAR, b"broken tar"), (privacy.GZIP, gzip.compress(archive([("app/ok", b"ok")]))[:-4])):
            with self.subTest(media=media, size=len(data)), tempfile.TemporaryDirectory() as directory:
                result = Layout(directory, layers=[(media, data)]).inspect()
                self.assertEqual(result["status"], "failed")
                self.assertFalse(result["inspectionComplete"])

    def test_hidden_second_tar_refused(self):
        data = archive([("app/first", b"ok")]) + archive([("app/.env", b"hidden")])
        result = self.layout(layers=[(privacy.TAR, data)]).inspect()
        self.assertEqual(result["refusal"], "trailing_archive_data")

    def test_oversized_pax_and_gnu_headers_rejected_before_allocation(self):
        for member_type, rule in ((tarfile.XHDTYPE, "tar_metadata_limit"),
                                  (tarfile.GNUTYPE_LONGNAME, "archive_path_limit")):
            with self.subTest(type=member_type), tempfile.TemporaryDirectory() as directory:
                header = tarfile.TarInfo("header")
                header.type, header.size = member_type, 10 * 1024**3
                data = header.tobuf(format=tarfile.GNU_FORMAT) + bytes(1024)
                result = Layout(directory, layers=[(privacy.TAR, data)]).inspect()
                self.assertEqual(result["refusal"], rule)

    def test_unreferenced_export_files_fail_closed_without_reading(self):
        fixture = self.layout()
        extra = fixture.directory / "private-runtime.env"
        extra.write_bytes(b"never scanned or exported")
        self.assertEqual(fixture.inspect()["refusal"], "unexpected_export_entry")
        extra.unlink()
        fixture.blob(b"unreferenced", privacy.TAR)
        self.assertEqual(fixture.inspect()["refusal"], "unexpected_export_entry")

    def test_member_decompression_count_and_json_limits(self):
        fixture = self.files([("app/one", b"x" * 1024), ("app/two", b"fine")])
        for limits, rule in ((dataclasses.replace(privacy.Limits(), member_bytes=100), "member_size_limit"),
                             (dataclasses.replace(privacy.Limits(), expanded_layer_bytes=100), "expanded_layer_limit"),
                             (dataclasses.replace(privacy.Limits(), members=1), "member_count_limit"),
                             (dataclasses.replace(privacy.Limits(), json_bytes=20), "input_size_limit")):
            with self.subTest(rule=rule):
                result = fixture.inspect(limits=limits)
                self.assertEqual(result["refusal"], rule)
                self.assertFalse(result["inspectionComplete"])

    def test_archive_path_and_link_escape_refused(self):
        for name, value in (("../outside", b"bad"), ("/absolute", b"bad"),
                            ("app/link", (tarfile.SYMTYPE, "../../outside")),
                            ("app/hard", (tarfile.LNKTYPE, "../outside"))):
            with self.subTest(path=name), tempfile.TemporaryDirectory() as directory:
                result = Layout(directory, layers=[(privacy.TAR, archive([(name, value)]))]).inspect()
                self.assertEqual(result["status"], "failed")
                self.assertFalse(result["inspectionComplete"])

    def test_changed_blob_and_symlink_are_refused(self):
        fixture = self.layout()
        path = fixture.directory / "blobs" / "sha256" / fixture.index["digest"][7:]
        original = path.read_bytes()
        path.write_bytes(original.replace(b"schemaVersion", b"schemaVersiom"))
        self.assertEqual(fixture.inspect()["refusal"], "blob_digest_mismatch")
        path.unlink()
        target = fixture.directory / "synthetic-blob"
        target.write_bytes(original)
        path.symlink_to(target)
        self.assertEqual(fixture.inspect()["status"], "failed")

    def test_cli_sanitized_receipt_and_no_overwrite(self):
        fixture = self.files([("app/.env", b"synthetic-only-secret")])
        with tempfile.TemporaryDirectory() as evidence:
            output = Path(evidence) / "receipt.json"
            command = [sys.executable, str(Path(privacy.__file__)), "--oci-dir", str(fixture.directory),
                       "--expected-index-digest", fixture.index["digest"], "--source-sha", SOURCE,
                       "--tooling-sha", TOOLING, "--output", str(output)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertNotIn("synthetic-only-secret", result.stdout + result.stderr + output.read_text())
            before = output.read_bytes()
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(output.read_bytes(), before)
            self.assertIn("receipt_write_failed", result.stdout)


if __name__ == "__main__":
    unittest.main()

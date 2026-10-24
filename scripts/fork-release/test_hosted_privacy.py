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
from unittest.mock import patch

import hosted_privacy as privacy


SOURCE = "a" * 40
TOOLING = "b" * 40
# Assemble synthetic PEM markers without committing a literal key marker.
PRIVATE_KEY_LABEL = b"PRIVATE KEY"


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


def inspect_with_short_member_reads(fixture, maximum):
    extractfile = tarfile.TarFile.extractfile
    class ShortReads:
        def __init__(self, stream):
            self.stream = stream
        def read(self, size):
            return self.stream.read(min(size, maximum))
    def short_member(archive_file, member):
        return ShortReads(extractfile(archive_file, member))
    with patch.object(tarfile.TarFile, "extractfile", short_member):
        return fixture.inspect()


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
        payload = b"x" * (privacy.CHUNK - 10) + (b'-----BEGIN ' + PRIVATE_KEY_LABEL + b'-----\n') + b"A" * 64 + b"\n-----END PRIVATE KEY-----"
        result = self.files([("app/data", payload), ("tmp/unknown", b"SQLite format 3\0synthetic")]).inspect()
        self.assertEqual({item["rule"] for item in result["findings"]}, {"private_key", "sqlite_database_payload"})
        self.assertNotIn(("BEGIN " + PRIVATE_KEY_LABEL.decode("ascii")), json.dumps(result))

    def test_public_pem_parser_literal_and_arbitrary_metadata_pass(self):
        def provenance(statement):
            statement["predicate"]["metadata"] = {"token": "public parser category"}
        result = self.files([("app/parser.js", (b"const marker = '-----BEGIN " + PRIVATE_KEY_LABEL + b"-----';")),
                             ("app/docs/example.md", (b'-----BEGIN ' + PRIVATE_KEY_LABEL + b'-----\n<insert your private key>'))],
                            provenance=provenance).inspect()
        self.assertEqual(result["status"], "passed", result)

    def test_encrypted_pem_body_and_small_stream_chunks(self):
        payload = ((b'-----BEGIN RSA ' + PRIVATE_KEY_LABEL + b'-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00000000\n\n') + b"A" * 64 + b"\n")
        result = self.files([("app/material", payload)]).inspect()
        self.assertEqual([item["rule"] for item in result["findings"]], ["private_key"])

    def test_public_identifiers_are_not_service_tokens_in_files_or_json(self):
        identifiers = [b"task-this-is-a-normal-public-identifier-with-long-suffix",
                       b"mask-protected-function-name-that-is-not-a-secret",
                       b"prefix_sk-" + b"P" * 30]
        config = {"os": "linux", "architecture": "amd64", "config": {
            "Labels": {"org.opencontainers.image.revision": SOURCE}, "Env": []},
            "history": [{"created_by": value.decode()} for value in identifiers]}
        result = self.files([("app/public-identifiers", b"\n".join(identifiers))],
                            config=config).inspect()
        self.assertEqual(result["status"], "passed", result)

    def test_identifier_boundary_survives_stream_overlap_and_short_reads(self):
        # Put the internal sk- exactly at the first retained byte, around the
        # read boundary, and in short reads that still retain the real file start.
        for chunk_size in (privacy.CHUNK, 17):
            offsets = (privacy.CHUNK - privacy.OVERLAP - 1,
                       privacy.CHUNK - privacy.OVERLAP,
                       privacy.CHUNK - privacy.OVERLAP + 1,
                       privacy.CHUNK - 1, privacy.CHUNK, privacy.CHUNK + 1) if chunk_size == privacy.CHUNK else (0, 16, 17)
            for offset in offsets:
                with self.subTest(chunk=chunk_size, offset=offset), tempfile.TemporaryDirectory() as directory:
                    payload = b"x" * offset + b"task-" + b"P" * 300 + b" " + b"x" * privacy.CHUNK
                    # For full reads, align sk- itself at the chosen boundary.
                    if chunk_size == privacy.CHUNK:
                        payload = b"x" * (offset - 2) + b"task-" + b"P" * 300 + b" " + b"x" * privacy.CHUNK
                    fixture = Layout(directory, layers=[(privacy.TAR, archive([("app/public", payload)]))])
                    result = inspect_with_short_member_reads(fixture, chunk_size)
                    self.assertEqual(result["status"], "passed", result)

    def test_service_tokens_keep_real_delimiters_and_stream_crossings(self):
        token = b"sk-" + b"S" * 30
        cases = [token, b'{"key":"' + token + b'"}', b"API_KEY=" + token,
                 b"Authorization: Bearer " + token,
                 b"https://example.invalid/?key=" + token,
                 b"https://example.invalid/path/" + token,
                 b"\x00\xff" + token + b"\x00", b"\xc3\xa9" + token,
                 b"sk-proj-" + b"P" * 30, b"sk-svcacct-" + b"A" * 30,
                 b" " * (privacy.CHUNK - 2) + token,
                 b" " * (privacy.CHUNK - privacy.OVERLAP) + b"sk-svcacct-" + b"A" * 255 +
                 b" " * privacy.CHUNK,
                 b"x" * (privacy.CHUNK - privacy.OVERLAP - 2) + b"task-" + b"P" * 300 +
                 b" " * 300 + token,
                 b"x" * (privacy.CHUNK - privacy.OVERLAP - 2) + b"task-" + b"P" * 300 +
                 b" " * 300 + b"xoxb-" + b"X" * 30]
        for index, payload in enumerate(cases):
            with self.subTest(case=index), tempfile.TemporaryDirectory() as directory:
                fixture = Layout(directory, layers=[(privacy.TAR, archive([("app/data", payload)]))])
                result = inspect_with_short_member_reads(fixture, 17) if index == 0 else fixture.inspect()
                self.assertIn("service_token", [item["rule"] for item in result["findings"]], result)
                self.assertTrue(result["inspectionComplete"], result)

    def test_service_token_json_values_keep_their_real_start_boundary(self):
        token = "sk-" + "S" * 30
        config = {"os": "linux", "architecture": "amd64", "config": {
            "Labels": {"org.opencontainers.image.revision": SOURCE, "public-label": token},
            "Env": ["OPENAI_API_KEY=" + token]}}
        result = self.layout(config=config).inspect()
        self.assertIn("service_token", [item["rule"] for item in result["findings"]], result)

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
        token = b"sk-" + b"S" * 30
        fixture = self.files([("app/.env", b"synthetic-only-secret"),
                             ("app/private-token-sentinel", token),
                             ("app/other-token-sentinel", b"ghp_" + b"G" * 30)])
        with tempfile.TemporaryDirectory() as evidence:
            output = Path(evidence) / "receipt.json"
            command = [sys.executable, str(Path(privacy.__file__)), "--oci-dir", str(fixture.directory),
                       "--expected-index-digest", fixture.index["digest"], "--source-sha", SOURCE,
                       "--tooling-sha", TOOLING, "--output", str(output)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1, result.stderr)
            emitted = result.stdout + result.stderr + output.read_text()
            for value in ("synthetic-only-secret", "app/.env", "app/private-token-sentinel",
                          "app/other-token-sentinel", token.decode(), "ghp_" + "G" * 30):
                self.assertNotIn(value, emitted)
            summary = json.loads(result.stdout)
            self.assertEqual(summary["findings"], 3)
            self.assertEqual(summary["findingCounts"], {
                "private_runtime_path": 1, "service_token": 1, "github_token": 1})
            self.assertEqual(summary["findingLocations"], json.loads(output.read_text())["findings"])
            for finding in summary["findingLocations"]:
                self.assertEqual(set(finding), {"rule", "locationSha256", "blobDigest"})
                self.assertRegex(finding["locationSha256"], r"^[a-f0-9]{64}$")
                self.assertRegex(finding["blobDigest"], r"^sha256:[a-f0-9]{64}$")
            before = output.read_bytes()
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(output.read_bytes(), before)
            self.assertIn("receipt_write_failed", result.stdout)

    def test_cli_diagnostics_remain_bounded_at_the_original_finding_limit(self):
        limit = privacy.Limits().findings
        self.assertEqual(limit, 64)
        fixture = self.files([(f"app/sentinel-{index}", b"sk-" + b"S" * 30)
                              for index in range(limit + 1)])
        with tempfile.TemporaryDirectory() as evidence:
            output = Path(evidence) / "receipt.json"
            result = subprocess.run([sys.executable, str(Path(privacy.__file__)),
                "--oci-dir", str(fixture.directory), "--expected-index-digest", fixture.index["digest"],
                "--source-sha", SOURCE, "--tooling-sha", TOOLING, "--output", str(output)],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1, result.stderr)
            summary = json.loads(result.stdout)
            self.assertEqual(summary["refusal"], "findings_limit")
            self.assertFalse(summary["inspectionComplete"])
            self.assertEqual(summary["findings"], limit)
            self.assertEqual(summary["findingCounts"], {"service_token": limit})
            self.assertEqual(len(summary["findingLocations"]), limit)
            self.assertNotIn("app/sentinel-", result.stdout + result.stderr + output.read_text())
            self.assertNotIn("sk-" + "S" * 30, result.stdout + result.stderr + output.read_text())


if __name__ == "__main__":
    unittest.main()

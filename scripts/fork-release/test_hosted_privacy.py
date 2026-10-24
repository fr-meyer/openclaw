"""Synthetic OCI fixtures only; no application images, databases or credentials."""

import dataclasses
import copy
from contextlib import contextmanager
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
EMPTY_CONFIG_MEDIA = "application/vnd.oci.empty.v1+json"
ATTESTATION_ARTIFACT = "application/vnd.docker.attestation.manifest.v1+json"
# Assemble synthetic PEM markers without committing a literal key marker.
PRIVATE_KEY_LABEL = b"PRIVATE KEY"


def cli_diagnostics(stdout):
    records = [json.loads(line) for line in stdout.splitlines()]
    details = [item for record in records if record.get("recordType") == "finding_details"
               for item in record["items"]]
    locations = [item for record in records if record.get("recordType") == "location_index"
                 for item in record["items"]]
    return records[0], details, locations


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
    def __init__(self, directory, layers=None, config=None, provenance=None,
                 artifact=False, attestation=None, runtime_manifest=None):
        self.directory = Path(directory)
        (self.directory / "blobs" / "sha256").mkdir(parents=True)
        (self.directory / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')
        config = config or {"os": "linux", "architecture": "amd64", "config": {
            "Env": ["NODE_ENV=production"],
            "Labels": {"org.opencontainers.image.revision": SOURCE}},
            "history": [{"created_by": "COPY /app/dist /app/dist"}]}
        self.config = config
        self.layers = layers or [(privacy.GZIP, gzip.compress(archive([("app/main.js", b"console.log('public');")])))]
        runnable = {"schemaVersion": 2, "mediaType": privacy.MANIFEST,
                    "config": self.blob(config, privacy.CONFIG),
                    "layers": [self.blob(data, media) for media, data in self.layers]}
        if runtime_manifest:
            runtime_manifest(runnable)
        runtime = self.blob(runnable, privacy.MANIFEST)
        runtime["platform"] = {"os": "linux", "architecture": "amd64"}
        self.runtime = runtime
        source = {"uri": "https://github.com/fr-meyer/openclaw.git#" + SOURCE, "digest": {"sha1": SOURCE}}
        statement = {"predicateType": privacy.PROVENANCE,
                     "subject": [{"digest": {"sha256": runtime["digest"][7:]}}],
                     "predicate": {"buildDefinition": {"externalParameters": {"configSource": source},
                                                        "resolvedDependencies": [source]}}}
        if provenance:
            provenance(statement)
        attested_manifest = {"schemaVersion": 2, "mediaType": privacy.MANIFEST,
                             "config": self.blob({}, EMPTY_CONFIG_MEDIA if artifact else privacy.CONFIG),
                             "layers": [self.blob(statement, privacy.ATTESTATION)]}
        if artifact:
            attested_manifest.update({"artifactType": ATTESTATION_ARTIFACT,
                                      "subject": {key: runtime[key] for key in ("mediaType", "digest", "size")}})
            attested_manifest["config"]["data"] = "e30="
        if attestation:
            attestation(attested_manifest)
        attested = self.blob(attested_manifest, privacy.MANIFEST)
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

    def comparison_plan(self, path, payload, **changes):
        entry = {"id": "public-sample", "path": path, "memberSha256": privacy.sha256(payload),
                 "memberBytes": len(payload), "rules": ["service_token"],
                 "evidence": {"reference": "https://example.org/public/source.js", "sha256": privacy.sha256(payload)}}
        entry.update(changes)
        return {"schema": "openclaw.public-member-comparisons.v1", "sourceSha": SOURCE, "entries": [entry]}

    def compare(self, fixture, plan):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "public.json"
            path.write_text(json.dumps(plan))
            return fixture.inspect(public_comparisons=path)

    def assert_diagnostic_only(self, baseline, compared):
        actual = dict(compared)
        actual.pop("publicMemberComparisons")
        self.assertEqual(actual, baseline)

    @contextmanager
    def trusted_comparison(self, plan):
        with tempfile.TemporaryDirectory() as directory:
            data = json.dumps(plan).encode()
            path = Path(directory) / "public.json"
            path.write_bytes(data)
            # Synthetic proof only: production constants remain the exact
            # reviewed source85/60-entry plan and three permitted rules.
            trusted = {**privacy.PUBLIC_MEMBER_QUALIFICATION, "sourceSha": SOURCE, "planSha256": privacy.sha256(data)}
            with patch.object(privacy, "PUBLIC_MEMBER_QUALIFICATION", trusted):
                yield path, data

    def test_explicit_public_qualification_requires_complete_exact_bytes_for_each_rule(self):
        payload = b"sk-" + b"S" * 30 + b" ghp_" + b"G" * 30 + b" https://user:pass@example.invalid/"
        plan = self.comparison_plan("app/example", payload, rules=["service_token", "github_token", "credential_url"])
        fixture = self.files([("app/example", payload)])
        with self.trusted_comparison(plan) as (path, data):
            diagnostic = fixture.inspect(public_comparisons=path)
            result = fixture.inspect(public_comparisons=path, qualify_public_members=True)
            privacy.require_public_member_qualification(result, data)
        self.assertEqual(diagnostic["status"], "failed")
        self.assertEqual(diagnostic["findingSummary"]["total"], 3)
        self.assertNotIn("publicMemberQualification", diagnostic)
        self.assertEqual(result["status"], "passed", result)
        self.assertTrue(result["inspectionComplete"])
        self.assertEqual(result["findingSummary"]["total"], 0)
        qualification = result["publicMemberQualification"]
        self.assertEqual(qualification["status"], "satisfied")
        self.assertEqual({record["rule"] for record in qualification["records"]}, set(plan["entries"][0]["rules"]))
        for record in qualification["records"]:
            self.assertEqual(record["memberOccurrences"], 1)
            self.assertEqual(record["sourceSha"], SOURCE)
            self.assertEqual(record["planSha256"], privacy.sha256(data))
            self.assertEqual(record["memberSha256"], privacy.sha256(payload))
        self.assertNotIn("app/example", json.dumps(qualification))
        self.assertNotIn(payload.decode(), json.dumps(qualification))

    def test_public_qualification_refuses_missing_or_untrusted_plan_source_rule_and_mode(self):
        payload = b"sk-" + b"S" * 30
        fixture = self.files([("app/example", payload)])
        self.assertEqual(fixture.inspect(qualify_public_members=True)["refusal"], "public_member_qualification_plan_required")
        self.assertEqual(fixture.inspect(qualify_public_members=1)["refusal"], "invalid_public_member_qualification_mode")
        plan = self.comparison_plan("app/example", payload)
        with self.trusted_comparison(plan) as (path, _):
            for field, value in (("sourceSha", "c" * 40), ("planSha256", "0" * 64)):
                with self.subTest(field=field), patch.object(privacy, "PUBLIC_MEMBER_QUALIFICATION",
                    {**privacy.PUBLIC_MEMBER_QUALIFICATION, field: value}):
                    result = fixture.inspect(public_comparisons=path, qualify_public_members=True)
                    self.assertFalse(result["inspectionComplete"])
                    self.assertEqual(result["refusal"], "untrusted_public_member_qualification_plan")
            path.write_bytes(path.read_bytes() + b" ")
            self.assertEqual(fixture.inspect(public_comparisons=path, qualify_public_members=True)["refusal"],
                             "untrusted_public_member_qualification_plan")
        plan["entries"][0]["rules"] = ["aws_access_key"]
        with self.trusted_comparison(plan) as (path, _):
            self.assertEqual(fixture.inspect(public_comparisons=path, qualify_public_members=True)["refusal"],
                             "untrusted_public_member_qualification_plan")

    def test_qualification_missing_changed_clean_or_nonregular_occurrences_fail_after_full_scan(self):
        payload = b"sk-" + b"S" * 30
        plan = self.comparison_plan("app/example", payload)
        cases = [[], [b"x" * len(payload)], [payload, b"x" * len(payload)],
                 [b"x" * len(payload), payload], [payload, (tarfile.SYMTYPE, "other")],
                 [payload, (tarfile.DIRTYPE, "")], [payload, b"short"]]
        for entries in cases:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as directory:
                layers = [(privacy.TAR, archive([("app/example", entry)])) for entry in entries]
                fixture = Layout(directory, layers=layers or [(privacy.TAR, archive([("app/other", b"safe")]))])
                with self.trusted_comparison(plan) as (path, data):
                    result = fixture.inspect(public_comparisons=path, qualify_public_members=True)
                    with self.assertRaisesRegex(privacy.Refusal, "invalid_public_member_qualification"):
                        privacy.require_public_member_qualification(result, data)
                self.assertTrue(result["inspectionComplete"], result)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["publicMemberQualification"]["status"], "failed")
                self.assertNotIn("refusal", result)

    def test_qualification_never_suppresses_other_rules_or_paths_and_metadata(self):
        payload = b"sk-" + b"S" * 30 + b" ASIA" + b"A" * 16 + b" ghp_" + b"G" * 30
        config = {"os": "linux", "architecture": "amd64", "config": {
            "Labels": {"org.opencontainers.image.revision": SOURCE}, "Env": ["PUBLIC_VALUE=sk-" + "M" * 30]}}
        fixture = self.files([("app/.env", payload)], config=config)
        plan = self.comparison_plan("app/.env", payload)
        with self.trusted_comparison(plan) as (path, data):
            result = fixture.inspect(public_comparisons=path, qualify_public_members=True)
            privacy.require_public_member_qualification(result, data)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["inspectionComplete"])
        self.assertEqual(result["publicMemberQualification"]["status"], "satisfied")
        self.assertEqual(result["findingSummary"]["byRule"]["private_runtime_path"], 1)
        self.assertEqual(result["findingSummary"]["byRule"]["aws_access_key"], 1)
        self.assertEqual(result["findingSummary"]["byRule"]["github_token"], 1)
        self.assertEqual(result["findingSummary"]["byRule"]["service_token"], 1)

    def test_qualification_does_not_suppress_pax_or_a_different_path(self):
        payload = b"sk-" + b"S" * 30
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as output:
            member = tarfile.TarInfo("app/example")
            member.size = len(payload)
            member.pax_headers = {"comment": "sk-" + "P" * 30}
            output.addfile(member, io.BytesIO(payload))
            other = tarfile.TarInfo("app/other")
            other.size = len(payload)
            output.addfile(other, io.BytesIO(payload))
        fixture = self.layout(layers=[(privacy.TAR, buffer.getvalue())])
        with self.trusted_comparison(self.comparison_plan("app/example", payload)) as (path, _):
            result = fixture.inspect(public_comparisons=path, qualify_public_members=True)
        self.assertTrue(result["inspectionComplete"])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["findingSummary"]["byRule"]["service_token"], 2)
        self.assertEqual(result["publicMemberQualification"]["records"][0]["memberOccurrences"], 1)

    def test_qualification_incomplete_member_flushes_pending_and_late_errors_still_fail(self):
        payload = b"sk-" + b"S" * 30
        fixture = self.files([("app/example", payload)])
        plan = self.comparison_plan("app/example", payload)
        with self.trusted_comparison(plan) as (path, _), \
                patch.object(tarfile.TarFile, "extractfile", side_effect=lambda *args: io.BytesIO(payload[:-1])):
            result = fixture.inspect(public_comparisons=path, qualify_public_members=True)
        self.assertFalse(result["inspectionComplete"])
        self.assertEqual(result["refusal"], "truncated_member")
        self.assertEqual(result["findingSummary"]["byRule"]["service_token"], 1)
        self.assertEqual(result["publicMemberQualification"]["records"], [])
        with tempfile.TemporaryDirectory() as directory:
            fixture = Layout(directory, layers=[(privacy.TAR, archive([("app/example", payload)]) + b"hidden")])
            with self.trusted_comparison(plan) as (path, data):
                result = fixture.inspect(public_comparisons=path, qualify_public_members=True)
                with self.assertRaises(privacy.Refusal):
                    privacy.require_public_member_qualification(result, data)
            self.assertFalse(result["inspectionComplete"])
            self.assertEqual(result["refusal"], "trailing_archive_data")
            self.assertEqual(result["status"], "failed")

    def test_qualification_consumer_rejects_fabricated_missing_and_duplicate_records(self):
        payload = b"sk-" + b"S" * 30
        fixture = self.files([("app/example", payload)])
        with self.trusted_comparison(self.comparison_plan("app/example", payload)) as (path, data):
            valid = fixture.inspect(public_comparisons=path, qualify_public_members=True)
            privacy.require_public_member_qualification(valid, data)
            mutations = [lambda receipt: receipt.pop("publicMemberQualification"),
                         lambda receipt: receipt.update(inspectionComplete=False),
                         lambda receipt: receipt.update(sourceSha="c" * 40),
                         lambda receipt: receipt["publicMemberQualification"].update(status="failed"),
                         lambda receipt: receipt["publicMemberQualification"].update(records=[]),
                         lambda receipt: receipt["publicMemberComparisons"].update(records=[]),
                         lambda receipt: receipt["publicMemberQualification"]["records"].append(
                             copy.deepcopy(receipt["publicMemberQualification"]["records"][0]))]
            for field, value in (("id", "unknown"), ("rule", "private_key"), ("memberSha256", "0" * 64),
                                 ("locationSha256", "0" * 64), ("memberBytes", True), ("memberOccurrences", True),
                                 ("memberOccurrences", 2), ("sourceSha", "c" * 40), ("planSha256", "0" * 64)):
                mutations.append(lambda receipt, key=field, item=value:
                                 receipt["publicMemberQualification"]["records"][0].update({key: item}))
            for mutate in mutations:
                changed = copy.deepcopy(valid)
                mutate(changed)
                with self.subTest(changed=changed), self.assertRaisesRegex(privacy.Refusal, "invalid_public_member_qualification"):
                    privacy.require_public_member_qualification(changed, data)
            with self.assertRaises(privacy.Refusal):
                privacy.require_public_member_qualification(valid, data + b" ")

    def test_public_qualification_cli_is_explicit_pinned_and_sanitized(self):
        payload = b"sk-" + b"S" * 30
        fixture = self.files([("app/example", payload)])
        with self.trusted_comparison(self.comparison_plan("app/example", payload)) as (path, _):
            for qualify, trusted_hash, expected in ((False, None, 1), (True, None, 0), (True, "0" * 64, 1)):
                with self.subTest(qualify=qualify, trusted_hash=trusted_hash), tempfile.TemporaryDirectory() as directory:
                    output = Path(directory) / "receipt.json"
                    trusted = dict(privacy.PUBLIC_MEMBER_QUALIFICATION)
                    if trusted_hash:
                        trusted["planSha256"] = trusted_hash
                    # Invoke the actual CLI parser/main in a separate process;
                    # only its production trust constant is replaced for this synthetic fixture.
                    script = ("import json,sys; import hosted_privacy as privacy; "
                              "privacy.PUBLIC_MEMBER_QUALIFICATION=json.loads(sys.argv.pop(1)); "
                              "raise SystemExit(privacy.main())")
                    command = [sys.executable, "-c", script, json.dumps(trusted),
                        "--oci-dir", str(fixture.directory), "--expected-index-digest", fixture.index["digest"],
                        "--source-sha", SOURCE, "--tooling-sha", TOOLING, "--output", str(output),
                        "--public-comparisons", str(path)]
                    if qualify:
                        command.append("--qualify-public-members")
                    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                    receipt = json.loads(output.read_text())
                    if expected == 0:
                        self.assertEqual(receipt["publicMemberQualification"]["status"], "satisfied")
                        records = [json.loads(line) for line in result.stdout.splitlines()]
                        summary = next(record for record in records if record["recordType"] == "public_member_qualification_summary")
                        batch = next(record for record in records if record["recordType"] == "qualified_public_members")
                        self.assertEqual(summary["planSha256"], trusted["planSha256"])
                        self.assertEqual(batch["items"], receipt["publicMemberQualification"]["records"])
                    for value in (payload.decode(), "app/example"):
                        self.assertNotIn(value, result.stdout + result.stderr + output.read_text())

    def test_public_comparison_is_diagnostic_only_for_matching_and_changed_bytes(self):
        public = b"sk-" + b"S" * 30
        for data, status in ((public, "matched"), (b"sk-" + b"X" * 30, "mismatch")):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                fixture = Layout(directory, layers=[(privacy.TAR, archive([("app/example.js", data)]))])
                baseline = fixture.inspect()
                compared = self.compare(fixture, self.comparison_plan("app/example.js", public))
                self.assert_diagnostic_only(baseline, compared)
                self.assertEqual(compared["status"], "failed")
                self.assertEqual(compared["findingSummary"]["byRule"]["service_token"], 1)
                report = compared["publicMemberComparisons"]
                self.assertTrue(report["diagnosticOnly"])
                self.assertTrue(report["inspectionComplete"])
                self.assertEqual(report["sourceSha"], SOURCE)
                record = report["records"][0]
                self.assertEqual(record["status"], status)
                self.assertEqual(record["observedMembers"], 1)
                self.assertEqual(record["matchedMembers"], int(status == "matched"))
                self.assertEqual(record["mismatchedMembers"], int(status == "mismatch"))
                self.assertEqual(record["memberSha256"], privacy.sha256(public))
                self.assertNotIn("app/example.js", json.dumps(report))
                if data != public:
                    self.assertNotIn(privacy.sha256(data), json.dumps(report))

    def test_comparison_path_size_and_rule_never_expand_or_remove_detection(self):
        payload = b"sk-" + b"S" * 30
        fixture = self.files([("app/.env", payload)])
        baseline = fixture.inspect()
        for name, changes, status in (("app/absent", {}, "missing"),
                                      ("app/.env", {"memberBytes": len(payload) + 1}, "mismatch"),
                                      ("app/.env", {"rules": ["credential_url"]}, "matched")):
            with self.subTest(name=name, changes=changes):
                compared = self.compare(fixture, self.comparison_plan(name, payload, **changes))
                self.assert_diagnostic_only(baseline, compared)
                self.assertEqual(compared["publicMemberComparisons"]["records"][0]["status"], status)
                self.assertEqual(compared["findingSummary"]["byRule"]["private_runtime_path"], 1)
                self.assertEqual(compared["findingSummary"]["byRule"]["service_token"], 1)

    def test_comparison_mismatch_is_sticky_across_layers_and_nonregular_members(self):
        payload = b"sk-" + b"S" * 30
        for entries in ((payload, b"sk-" + b"X" * 30), (b"sk-" + b"X" * 30, payload),
                        (payload, (tarfile.SYMTYPE, "other")),
                        (payload, (tarfile.DIRTYPE, ""))):
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as directory:
                fixture = Layout(directory, layers=[(privacy.TAR, archive([("app/example", data)])) for data in entries])
                compared = self.compare(fixture, self.comparison_plan("app/example", payload))
                self.assert_diagnostic_only(fixture.inspect(), compared)
                record = compared["publicMemberComparisons"]["records"][0]
                self.assertEqual((record["status"], record["observedMembers"], record["matchedMembers"],
                                  record["mismatchedMembers"]), ("mismatch", 2, 1, 1))

    def test_comparison_incomplete_read_and_late_archive_error_remain_incomplete(self):
        payload = b"sk-" + b"S" * 30
        fixture = self.files([("app/example", payload)])
        with patch.object(tarfile.TarFile, "extractfile", side_effect=lambda *args: io.BytesIO(payload[:-1])):
            baseline = fixture.inspect()
            compared = self.compare(fixture, self.comparison_plan("app/example", payload))
        self.assert_diagnostic_only(baseline, compared)
        self.assertEqual(compared["refusal"], "truncated_member")
        self.assertEqual(compared["publicMemberComparisons"]["records"][0]["status"], "mismatch")
        self.assertFalse(compared["publicMemberComparisons"]["inspectionComplete"])
        with tempfile.TemporaryDirectory() as directory:
            fixture = Layout(directory, layers=[(privacy.TAR, archive([("app/example", payload)]) + b"hidden")])
            compared = self.compare(fixture, self.comparison_plan("app/example", payload))
            self.assert_diagnostic_only(fixture.inspect(), compared)
            self.assertEqual(compared["refusal"], "trailing_archive_data")
            self.assertEqual(compared["publicMemberComparisons"]["records"][0]["status"], "matched")
            self.assertFalse(compared["publicMemberComparisons"]["inspectionComplete"])

    def test_comparison_plan_validation_is_closed_and_fail_closed(self):
        fixture = self.layout()
        original = self.comparison_plan("app/example", b"public")
        mutations = [lambda plan: plan.update(extra="unknown"),
                     lambda plan: plan.update(sourceSha="c" * 40),
                     lambda plan: plan.update(schema="unknown"),
                     lambda plan: plan.update(entries=[copy.deepcopy(plan["entries"][0])] * 129),
                     lambda plan: plan["entries"].append(copy.deepcopy(plan["entries"][0])),
                     lambda plan: plan["entries"].append({**plan["entries"][0], "id": "second-id"})]
        for field, value in (("id", "bad id"), ("path", "/absolute"), ("path", "app/../escape"),
                             ("path", "app//double"), ("path", "app/./dot"), ("path", "app/end/"),
                             ("path", "app/\u0000bad"), ("memberSha256", "x" * 64), ("memberBytes", True),
                             ("memberBytes", -1), ("memberBytes", 1.0), ("memberBytes", privacy.Limits().member_bytes + 1),
                             ("rules", []), ("rules", ["unknown"]), ("rules", ["service_token"] * 2),
                             ("evidence", {"reference": "https://user:pass@example.org/source", "sha256": "a" * 64}),
                             ("evidence", {"reference": "https://example.org/source", "sha256": "bad"})):
            mutations.append(lambda plan, key=field, item=value: plan["entries"][0].update({key: item}))
        for mutate in mutations:
            plan = copy.deepcopy(original)
            mutate(plan)
            with self.subTest(plan=plan):
                result = self.compare(fixture, plan)
                self.assertEqual(result["status"], "failed")
                self.assertFalse(result["inspectionComplete"])
                self.assertEqual(result["refusal"], "invalid_public_comparison_plan")
                self.assertNotIn("publicMemberComparisons", result)
        with tempfile.TemporaryDirectory() as directory:
            plan_path = Path(directory) / "oversized.json"
            plan_path.write_bytes(b" " * (privacy.MAX_COMPARISON_PLAN_BYTES + 1))
            result = fixture.inspect(public_comparisons=plan_path)
            self.assertEqual(result["refusal"], "invalid_public_comparison_plan")

    def test_public_comparison_cli_hash_binding_and_safe_output(self):
        payload = b"sk-" + b"S" * 30
        fixture = self.files([("app/example", payload)])
        for tampered in (False, True):
            with self.subTest(tampered=tampered), tempfile.TemporaryDirectory() as directory:
                plan = self.comparison_plan("app/example", payload)
                if tampered:
                    plan["sourceSha"] = "c" * 40
                plan_path, output = Path(directory) / "public.json", Path(directory) / "receipt.json"
                data = json.dumps(plan).encode()
                plan_path.write_bytes(data)
                result = subprocess.run([sys.executable, str(Path(privacy.__file__)),
                    "--oci-dir", str(fixture.directory), "--expected-index-digest", fixture.index["digest"],
                    "--source-sha", SOURCE, "--tooling-sha", TOOLING, "--output", str(output),
                    "--public-comparisons", str(plan_path)], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 1)
                receipt = json.loads(output.read_text())
                records = [json.loads(line) for line in result.stdout.splitlines()]
                if tampered:
                    self.assertEqual(receipt["refusal"], "invalid_public_comparison_plan")
                else:
                    comparison = receipt["publicMemberComparisons"]
                    self.assertEqual(comparison["planSha256"], privacy.sha256(data))
                    self.assertEqual(comparison["records"][0]["status"], "matched")
                    self.assertEqual(receipt["findingSummary"]["byRule"]["service_token"], 1)
                    summary = next(item for item in records if item["recordType"] == "public_member_comparison_summary")
                    batch = next(item for item in records if item["recordType"] == "public_member_comparisons")
                    self.assertEqual(summary["planSha256"], privacy.sha256(data))
                    self.assertEqual(batch["items"], comparison["records"])
                    self.assertEqual(batch["sourceSha"], SOURCE)
                for private in ("app/example", payload.decode(), plan["entries"][0]["evidence"]["reference"]):
                    self.assertNotIn(private, result.stdout + result.stderr + output.read_text())

    def test_public_image_passes_and_binds_identities(self):
        fixture = self.layout()
        receipt = fixture.inspect()
        self.assertEqual(receipt["status"], "passed", receipt)
        self.assertTrue(receipt["inspectionComplete"])
        self.assertEqual(receipt["schema"], "openclaw.hosted-privacy.v2")
        self.assertEqual(receipt["indexDigest"], fixture.index["digest"])
        self.assertEqual(receipt["sourceSha"], SOURCE)
        self.assertEqual(receipt["toolingSha"], TOOLING)
        self.assertEqual(receipt["counts"]["files"], 1)
        self.assertTrue(receipt["heuristicOnly"])
        self.assertEqual(receipt["findingSummary"]["total"], 0)
        self.assertFalse(receipt["representativesTruncated"])

    def test_uncompressed_layer_and_normal_container_symlinks(self):
        result = self.files([("usr/bin/tool", b"public"),
                             ("bin/tool", (tarfile.SYMTYPE, "/usr/bin/tool")),
                             ("bin/other", (tarfile.SYMTYPE, "../usr/bin/tool")),
                             ("usr/bin/hard", (tarfile.LNKTYPE, "usr/bin/tool"))], compressed=False).inspect()
        self.assertEqual(result["status"], "passed", result)

    def test_modern_attestation_empty_config_cli(self):
        fixture = self.layout(artifact=True)
        with tempfile.TemporaryDirectory() as evidence:
            output = Path(evidence) / "receipt.json"
            result = subprocess.run([sys.executable, str(Path(privacy.__file__)),
                "--oci-dir", str(fixture.directory), "--expected-index-digest", fixture.index["digest"],
                "--source-sha", SOURCE, "--tooling-sha", TOOLING, "--output", str(output)],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            receipt = json.loads(output.read_text())
            self.assertEqual(receipt["status"], "passed")
            self.assertTrue(receipt["inspectionComplete"])
            self.assertEqual(receipt["findingSummary"]["total"], 0)

    def test_modern_empty_config_without_inline_and_legacy_config_pass(self):
        for artifact in (False, True):
            with self.subTest(artifact=artifact), tempfile.TemporaryDirectory() as directory:
                fixture = Layout(directory, artifact=artifact,
                                 attestation=lambda manifest: manifest["config"].pop("data", None))
                result = fixture.inspect()
                self.assertEqual(result["status"], "passed", result)
                self.assertTrue(result["inspectionComplete"])

    def test_empty_attestation_config_rejects_noncanonical_descriptors(self):
        for field, value in (("digest", "sha256:" + "0" * 64), ("size", 3), ("size", True),
                             ("size", 2.0), ("data", None), ("data", "e30=\n"), ("data", "W10="),
                             ("urls", ["https://example.invalid/blob"]), ("mediaType", "unknown")):
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as directory:
                fixture = Layout(directory, artifact=True,
                                 attestation=lambda manifest: manifest["config"].update({field: value}))
                result = fixture.inspect()
                self.assertFalse(result["inspectionComplete"])
                self.assertEqual(result["refusal"], "unsupported_empty_attestation_config")

    def test_empty_attestation_requires_exact_artifact_and_subject(self):
        mutations = [
            (lambda manifest: manifest.pop("artifactType"), "unsupported_attestation_artifact"),
            (lambda manifest: manifest.update(artifactType="unknown"), "unsupported_attestation_artifact"),
            (lambda manifest: manifest.pop("subject"), "attestation_subject_mismatch"),
            (lambda manifest: manifest.update(subject=None), "attestation_subject_mismatch"),
        ]
        for field, value in (("mediaType", privacy.CONFIG), ("digest", "sha256:" + "0" * 64),
                             ("size", 2), ("size", True)):
            mutations.append((lambda manifest, key=field, item=value: manifest["subject"].update({key: item}),
                              "attestation_subject_mismatch"))
        for field, value in (("data", "e30="), ("urls", ["https://example.invalid/manifest"])):
            mutations.append((lambda manifest, key=field, item=value: manifest["subject"].update({key: item}),
                              "external_or_inline_blob"))
        for mutate, refusal in mutations:
            with self.subTest(refusal=refusal), tempfile.TemporaryDirectory() as directory:
                result = Layout(directory, artifact=True, attestation=mutate).inspect()
                self.assertFalse(result["inspectionComplete"])
                self.assertEqual(result["refusal"], refusal)

    def test_inline_empty_config_never_substitutes_for_verified_local_blob(self):
        for payload, refusal in ((None, "malformed_or_unreadable_layout"),
                                 (b"[]", "blob_digest_mismatch"), (b"{}\n", "blob_size_mismatch")):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as directory:
                fixture = Layout(directory, artifact=True)
                blob = fixture.directory / "blobs/sha256" / privacy.EMPTY_CONFIG_DIGEST[7:]
                if payload is None:
                    blob.unlink()
                else:
                    blob.write_bytes(payload)
                result = fixture.inspect()
                self.assertFalse(result["inspectionComplete"])
                self.assertEqual(result["refusal"], refusal)

    def test_empty_attestation_does_not_relax_other_descriptor_positions(self):
        cases = [
            (False, None, lambda manifest: manifest["config"].update(mediaType=EMPTY_CONFIG_MEDIA),
             "unsupported_config"),
            (False, None, lambda manifest: manifest["config"].update(data="e30="),
             "external_or_inline_blob"),
            (False, lambda manifest: manifest["config"].update(data="e30="), None,
             "external_or_inline_blob"),
            (True, lambda manifest: manifest["layers"][0].update(data="e30="), None,
             "external_or_inline_blob"),
        ]
        for artifact, attestation, runtime, refusal in cases:
            with self.subTest(refusal=refusal), tempfile.TemporaryDirectory() as directory:
                result = Layout(directory, artifact=artifact, attestation=attestation,
                                runtime_manifest=runtime).inspect()
                self.assertFalse(result["inspectionComplete"])
                self.assertEqual(result["refusal"], refusal)

    def test_modern_artifact_still_requires_provenance_and_reports_findings(self):
        mutations = [
            (lambda statement: statement.update(predicateType="unknown"), "missing_source_provenance"),
            (lambda statement: statement["subject"][0]["digest"].update(sha256="0" * 64),
             "provenance_subject_mismatch"),
            (lambda statement: statement["predicate"]["buildDefinition"]["externalParameters"]["configSource"].update(
                uri="https://example.invalid/repository"), "provenance_source_mismatch"),
        ]
        for mutate, refusal in mutations:
            with self.subTest(refusal=refusal), tempfile.TemporaryDirectory() as directory:
                result = Layout(directory, artifact=True, provenance=mutate).inspect()
                self.assertFalse(result["inspectionComplete"])
                self.assertEqual(result["refusal"], refusal)
        result = self.files([("app/leak", b"sk-" + b"S" * 30)], artifact=True).inspect()
        self.assertTrue(result["inspectionComplete"])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["findingSummary"]["byRule"]["service_token"], 1)

    def test_bundle_closure_preserves_empty_attestation_blob_and_byte_budget(self):
        import hosted_bundle as bundle
        root = Path(self.temp.name).resolve()
        fixture = Layout(root / "oci/default", artifact=True)
        inputs = bundle.Inputs(root)
        try:
            closure = bundle.Closure(inputs, {"indexDigest": fixture.index["digest"],
                                             "sourceSha": SOURCE, "toolingSha": TOOLING})
            closure.run()
            self.assertEqual(closure.blobs[privacy.EMPTY_CONFIG_DIGEST], 2)
            self.assertEqual(closure.finding_total, 0)
            self.assertEqual(closure.counts["blobBytes"], sum(closure.blobs.values()))
        finally:
            inputs.close()
        result = fixture.inspect(limits=dataclasses.replace(privacy.Limits(),
                                 total_blob_bytes=closure.counts["blobBytes"] - 1))
        self.assertEqual(result["refusal"], "blob_total_limit")

    def test_private_runtime_paths(self):
        for name in ("app/.env", "app/.env.production", "home/node/.openclaw/config.json",
                     "root/.aws/credentials", "tmp/cookies.txt", "data/openclaw-agent.sqlite-wal"):
            with self.subTest(path=name), tempfile.TemporaryDirectory() as directory:
                result = Layout(directory, layers=[(privacy.TAR, archive([(name, b"synthetic")]))]).inspect()
                self.assertEqual(result["status"], "failed")
                self.assertTrue(result["inspectionComplete"])
                self.assertIn("private_runtime_path", [item["rule"] for item in result["findings"]])
                self.assertNotIn(name, json.dumps(result))

    def test_symlink_indexes_both_private_paths_but_counts_one_member_rule(self):
        name, target = "app/.env", "/root/.aws/credentials"
        result = self.files([(name, (tarfile.SYMTYPE, target))]).inspect()
        self.assertTrue(result["inspectionComplete"])
        self.assertEqual(result["findingSummary"]["total"], 1)
        self.assertEqual(result["findingSummary"]["byRule"]["private_runtime_path"], 1)
        self.assertEqual(len(result["findings"]), 1)
        self.assertFalse(result["representativesTruncated"])
        self.assertFalse(result["locationIndexTruncated"])
        self.assertEqual({entry["locationSha256"] for entry in result["locationIndex"]},
                         {privacy.sha256(name.encode()), privacy.sha256(b"root/.aws/credentials")})
        self.assertEqual(len(result["locationIndex"]), 2)
        self.assertEqual({entry["rule"] for entry in result["locationIndex"]}, {"private_runtime_path"})
        self.assertNotIn(name, json.dumps(result))
        self.assertNotIn(target, json.dumps(result))

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

    def test_embedded_aws_identifiers_keep_their_real_stream_predecessor(self):
        for family in (b"AKIA", b"ASIA"):
            token = family + b"A" * 16
            for offset in (0, privacy.CHUNK - privacy.OVERLAP - 1,
                           privacy.CHUNK - privacy.OVERLAP, privacy.CHUNK - 1):
                with self.subTest(family=family, offset=offset), tempfile.TemporaryDirectory() as directory:
                    payload = b"x" * offset + b"_" + token + b" " + b"x" * privacy.CHUNK
                    fixture = Layout(directory, layers=[(privacy.TAR, archive([("app/public", payload)]))])
                    result = inspect_with_short_member_reads(fixture, 17) if offset == 0 else fixture.inspect()
                    self.assertEqual(result["status"], "passed", result)

    def test_aws_tokens_keep_real_delimiters_json_and_split_controls(self):
        for family in (b"AKIA", b"ASIA"):
            token = family + b"A" * 16
            cases = [token, b'"' + token + b'"', b"AWS_ACCESS_KEY_ID=" + token,
                     b"\0\xff" + token + b"\0", b"\xc3\xa9" + token,
                     b" " * (privacy.CHUNK - 2) + token,
                     b" " * (privacy.CHUNK - privacy.OVERLAP) + token + b" " * privacy.CHUNK,
                     b"x" * (privacy.CHUNK - privacy.OVERLAP - 1) + b"_" + token +
                     b" " * 300 + token]
            for index, payload in enumerate(cases):
                with self.subTest(family=family, case=index), tempfile.TemporaryDirectory() as directory:
                    fixture = Layout(directory, layers=[(privacy.TAR, archive([("app/data", payload)]))])
                    result = inspect_with_short_member_reads(fixture, 7) if index == 0 else fixture.inspect()
                    self.assertIn("aws_access_key", [item["rule"] for item in result["findings"]], result)
            inspector = privacy.Inspector("unused", None, SOURCE, TOOLING, privacy.Limits())
            inspector.scan_json({"example": token.decode()}, "metadata")
            self.assertEqual([f["rule"] for f in inspector.findings], ["aws_access_key"])

    def test_credential_url_authority_stops_at_query_and_fragment(self):
        cases = [b"https://public.invalid?redirect=user:pass@example.invalid",
                 b"https://public.invalid#section:user@example.invalid",
                 b"https://public.invalid:user?pass@example.invalid",
                 b"https://public.invalid:user#pass@example.invalid",
                 b"https://user?part:pass@example.invalid",
                 b"https://user#part:pass@example.invalid"]
        for index, value in enumerate(cases):
            with self.subTest(case=index), tempfile.TemporaryDirectory() as directory:
                payload = b" " * (privacy.CHUNK - 10) + value
                fixture = Layout(directory, layers=[(privacy.TAR, archive([("app/public", payload)]))])
                self.assertEqual(fixture.inspect()["status"], "passed")

    def test_credential_url_retains_real_userinfo_and_percent_encoded_delimiters(self):
        cases = [b"https://user:pass@example.invalid/path?query=value#fragment",
                 b"http://user:p:a:ss@[2001:db8::1]/?next=other@example.invalid",
                 b"https://us%3Fer:p%23as%40s@example.invalid",
                 b'"https://user:pass@example.invalid"',
                 b"\0https://user:pass@example.invalid\0",
                 b"https://" + b"u" * 100 + b":" + b"p" * 150 + b"@example.invalid"]
        for index, value in enumerate(cases):
            with self.subTest(case=index), tempfile.TemporaryDirectory() as directory:
                payload = b" " * (privacy.CHUNK - 10) + value
                fixture = Layout(directory, layers=[(privacy.TAR, archive([("app/data", payload)]))])
                result = inspect_with_short_member_reads(fixture, 17) if index == 0 else fixture.inspect()
                self.assertIn("credential_url", [f["rule"] for f in result["findings"]], result)

    def test_match_diagnostics_are_bounded_syntax_not_value_fingerprints(self):
        token = b"ASIA" + b"A" * 16
        inspector = privacy.Inspector("unused", None, SOURCE, TOOLING, privacy.Limits())
        with inspector.scan_unit("archive_member"):
            inspector.scan_bytes(b'"' + token + b'"', "private-path")
            inspector.scan_bytes(token, "private-path")
        finding = inspector.findings[0]
        self.assertEqual(finding["matchLength"], len(token))
        self.assertEqual(finding["syntaxFlags"], {
            "leftContext": "ascii_delimiter", "rightContext": "ascii_delimiter", "percentEncoded": False})
        inspector.scan_bytes(b"https://u%3Fer:p%23ass@example.invalid", "other-path")
        self.assertTrue(inspector.findings[1]["syntaxFlags"]["percentEncoded"])
        self.assertEqual(inspector.findings[1]["syntaxFlags"]["leftContext"], "input_start")
        rendered = json.dumps(inspector.findings)
        for forbidden in (token.decode(), hashlib.sha256(token).hexdigest(), "private-path", "other-path"):
            self.assertNotIn(forbidden, rendered)
        # Repeated windows in the member retained its first diagnostic only.
        self.assertEqual(len(inspector.findings), 2)
        self.assertEqual(inspector.findings[0], finding)

    def public_self_test_fixture(self, extra=b""):
        payload = b"-----BEGIN " + PRIVATE_KEY_LABEL + b"-----\n" + b"A" * 64 + b"\n" + extra
        name = "usr/lib/synthetic-public-self-test.so"
        data = archive([(name, payload)])
        fixture = self.layout(layers=[(privacy.TAR, data)])
        record = {**privacy.PUBLIC_GNUTLS_SELF_TEST, "path": name,
                  "blobDigest": "sha256:" + hashlib.sha256(data).hexdigest(),
                  "memberSha256": hashlib.sha256(payload).hexdigest(), "memberBytes": len(payload)}
        return fixture, record, payload

    def test_public_self_test_requires_exact_full_member_binding(self):
        fixture, record, payload = self.public_self_test_fixture()
        with patch.object(privacy, "PUBLIC_GNUTLS_SELF_TEST", record):
            result = inspect_with_short_member_reads(fixture, 17)
        self.assertEqual(result["status"], "passed", result)
        self.assertTrue(result["inspectionComplete"])
        self.assertEqual(result["findings"], [])
        qualified = result["qualifiedPublicFixtures"]
        self.assertEqual(len(qualified), 1)
        self.assertEqual(qualified[0], {**{k: record[k] for k in
            ("rule", "blobDigest", "memberSha256", "memberBytes", "publicSourceSha256")},
            "locationSha256": hashlib.sha256(record["path"].encode()).hexdigest()})
        self.assertNotIn(record["path"], json.dumps(result))
        self.assertNotIn(payload.decode(), json.dumps(result))
        for key, value in (("rule", "aws_access_key"), ("blobDigest", "sha256:" + "0" * 64),
                           ("path", "usr/lib/different.so"), ("memberSha256", "0" * 64),
                           ("memberBytes", len(payload) + 1)):
            with self.subTest(binding=key), patch.object(privacy, "PUBLIC_GNUTLS_SELF_TEST", {**record, key: value}):
                refused = fixture.inspect()
                self.assertEqual([f["rule"] for f in refused["findings"]], ["private_key"])
                self.assertEqual(refused["qualifiedPublicFixtures"], [])
                self.assertEqual(refused["status"], "failed")

    def test_public_self_test_cannot_qualify_other_rules_or_an_incomplete_member(self):
        fixture, record, _ = self.public_self_test_fixture(b"ASIA" + b"A" * 16)
        with patch.object(privacy, "PUBLIC_GNUTLS_SELF_TEST", record):
            result = fixture.inspect()
        self.assertEqual([f["rule"] for f in result["findings"]], ["aws_access_key"])
        self.assertEqual(len(result["qualifiedPublicFixtures"]), 1)
        self.assertEqual(result["status"], "failed")
        extractfile = tarfile.TarFile.extractfile
        class InterruptedRead:
            def __init__(self, stream):
                self.stream, self.calls = stream, 0
            def read(self, size):
                self.calls += 1
                if self.calls > 1:
                    raise OSError("synthetic interrupted member")
                return self.stream.read(size)
        def interrupt(archive_file, member):
            return InterruptedRead(extractfile(archive_file, member))
        with patch.object(privacy, "PUBLIC_GNUTLS_SELF_TEST", record), \
                patch.object(tarfile.TarFile, "extractfile", interrupt):
            refused = fixture.inspect()
        self.assertFalse(refused["inspectionComplete"])
        self.assertEqual(refused["qualifiedPublicFixtures"], [])
        self.assertIn("private_key", [f["rule"] for f in refused["findings"]])

    def test_public_comparison_preserves_exact_gnutls_qualification_and_other_findings(self):
        fixture, record, payload = self.public_self_test_fixture(b"ASIA" + b"A" * 16)
        with patch.object(privacy, "PUBLIC_GNUTLS_SELF_TEST", record):
            baseline = fixture.inspect()
            compared = self.compare(fixture, self.comparison_plan(record["path"], payload, rules=["private_key"]))
        self.assert_diagnostic_only(baseline, compared)
        self.assertEqual(len(compared["qualifiedPublicFixtures"]), 1)
        self.assertEqual(compared["status"], "failed")
        self.assertEqual(compared["findingSummary"]["byRule"]["aws_access_key"], 1)
        self.assertEqual(compared["publicMemberComparisons"]["records"][0]["status"], "matched")

    def test_member_qualification_coexists_with_exact_gnutls_and_keeps_unplanned_rules(self):
        fixture, record, payload = self.public_self_test_fixture(b"sk-" + b"S" * 30 + b" ASIA" + b"A" * 16)
        with patch.object(privacy, "PUBLIC_GNUTLS_SELF_TEST", record), \
                self.trusted_comparison(self.comparison_plan(record["path"], payload)) as (path, data):
            result = fixture.inspect(public_comparisons=path, qualify_public_members=True)
            privacy.require_public_member_qualification(result, data)
        self.assertTrue(result["inspectionComplete"])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(len(result["qualifiedPublicFixtures"]), 1)
        self.assertEqual(result["publicMemberQualification"]["records"][0]["rule"], "service_token")
        self.assertEqual(result["findingSummary"]["total"], 1)
        self.assertEqual(result["findingSummary"]["byRule"]["aws_access_key"], 1)

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
            summary, details, locations = cli_diagnostics(result.stdout)
            self.assertEqual(summary["recordType"], "summary")
            self.assertEqual(summary["findings"], 3)
            counts = dict.fromkeys(privacy.FINDING_RULES, 0)
            counts.update(private_runtime_path=1, service_token=1, github_token=1)
            self.assertEqual(summary["findingCounts"], counts)
            receipt = json.loads(output.read_text())
            self.assertEqual(details, receipt["findings"])
            self.assertEqual(locations, receipt["locationIndex"])
            for key in ("sourceSha", "toolingSha", "indexDigest", "imageDigest", "configDigest"):
                self.assertEqual(summary[key], receipt[key])
            for finding in details:
                expected = {"rule", "unit", "locationSha256", "blobDigest"}
                self.assertIn(finding["unit"], privacy.FINDING_UNITS)
                if finding["rule"] != "private_runtime_path":
                    expected |= {"matchLength", "syntaxFlags"}
                    self.assertIs(type(finding["matchLength"]), int)
                    self.assertEqual(set(finding["syntaxFlags"]), {"leftContext", "rightContext", "percentEncoded"})
                self.assertEqual(set(finding), expected)
                self.assertRegex(finding["locationSha256"], r"^[a-f0-9]{64}$")
                self.assertRegex(finding["blobDigest"], r"^sha256:[a-f0-9]{64}$")
            before = output.read_bytes()
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(output.read_bytes(), before)
            self.assertIn("receipt_write_failed", result.stdout)
            retry_summary, retry_details, retry_locations = cli_diagnostics(result.stdout)
            self.assertTrue(summary["receiptPersisted"])
            self.assertIsNone(summary["persistenceRefusal"])
            self.assertFalse(retry_summary["receiptPersisted"])
            self.assertEqual(retry_summary["persistenceRefusal"], "receipt_write_failed")
            self.assertTrue(retry_summary["inspectionComplete"])
            self.assertEqual(retry_summary["findingSummary"], summary["findingSummary"])
            for key in ("sourceSha", "toolingSha", "indexDigest", "imageDigest", "configDigest"):
                self.assertEqual(retry_summary[key], receipt[key])
            self.assertEqual(retry_details, details)
            self.assertEqual(retry_locations, locations)

    def test_cli_clean_scan_write_error_keeps_diagnostics_and_fails(self):
        fixture = self.layout()
        with tempfile.TemporaryDirectory() as evidence:
            output = Path(evidence) / "missing" / "receipt.json"
            result = subprocess.run([sys.executable, str(Path(privacy.__file__)),
                "--oci-dir", str(fixture.directory), "--expected-index-digest", fixture.index["digest"],
                "--source-sha", SOURCE, "--tooling-sha", TOOLING, "--output", str(output)],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1, result.stderr)
            summary, details, locations = cli_diagnostics(result.stdout)
            self.assertEqual(summary["status"], "failed")
            self.assertTrue(summary["inspectionComplete"])
            self.assertEqual(summary["findings"], 0)
            self.assertEqual(details, [])
            self.assertEqual(locations, [])
            self.assertFalse(summary["receiptPersisted"])
            self.assertEqual(summary["persistenceRefusal"], "receipt_write_failed")
            self.assertIsNone(summary["refusal"])
            self.assertEqual(summary["sourceSha"], SOURCE)
            self.assertEqual(summary["toolingSha"], TOOLING)
            self.assertEqual(summary["indexDigest"], fixture.index["digest"])
            self.assertEqual(summary["imageDigest"], fixture.runtime["digest"])
            self.assertRegex(summary["configDigest"], r"^sha256:[a-f0-9]{64}$")
            self.assertFalse(output.exists())
            self.assertNotIn(str(output), result.stdout + result.stderr)

    def test_cli_counts_continue_after_the_original_representative_limit(self):
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
            summary, details, locations = cli_diagnostics(result.stdout)
            self.assertIsNone(summary["refusal"])
            self.assertTrue(summary["inspectionComplete"])
            self.assertEqual(summary["findings"], limit + 1)
            counts = dict.fromkeys(privacy.FINDING_RULES, 0)
            counts["service_token"] = limit + 1
            self.assertEqual(summary["findingCounts"], counts)
            self.assertTrue(summary["representativesTruncated"])
            self.assertLess(summary["retainedFindings"], limit)
            self.assertEqual(summary["retainedFindings"], len(details))
            self.assertEqual(summary["indexedLocations"], limit + 1)
            self.assertEqual(len(locations), limit + 1)
            self.assertFalse(summary["locationIndexTruncated"])
            self.assertNotIn("app/sentinel-", result.stdout + result.stderr + output.read_text())
            self.assertNotIn("sk-" + "S" * 30, result.stdout + result.stderr + output.read_text())

    def test_complete_multilayer_counts_and_later_rules_survive_sample_saturation(self):
        token = b"sk-" + b"S" * 30
        first = archive([(f"app/repeated-{i}", token) for i in range(70)])
        last = archive([(f"app/url-{i}", b"https://user:pass@example.invalid") for i in range(70)] + [
            ("app/rare", b"ASIA" + b"A" * 16),
            ("app/stream", (token + b" ") * (privacy.CHUNK // 10)),
            ("app/.env", (tarfile.SYMTYPE, "/root/.aws/credentials"))])
        result = self.layout(layers=[(privacy.TAR, first), (privacy.TAR, first), (privacy.TAR, last)]).inspect()
        self.assertTrue(result["inspectionComplete"], result)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["counts"]["layers"], 3)
        counts = dict.fromkeys(privacy.FINDING_RULES, 0)
        counts.update(service_token=141, credential_url=70, aws_access_key=1, private_runtime_path=1)
        self.assertEqual(result["findingSummary"]["byRule"], counts)
        self.assertEqual(result["findingSummary"]["total"], 213)
        self.assertEqual(result["findingSummary"]["byUnit"]["archive_member"], 213)
        self.assertLessEqual(len(result["findings"]), 64)
        self.assertEqual({f["rule"] for f in result["findings"]},
                         {"service_token", "credential_url", "aws_access_key", "private_runtime_path"})
        self.assertTrue(result["representativesTruncated"])

    def test_json_occurrence_units_and_member_context_are_independent_and_bounded(self):
        inspector = privacy.Inspector("unused", None, SOURCE, TOOLING, privacy.Limits())
        token = "sk-" + "S" * 30
        with inspector.scan_unit("archive_member"):
            inspector.scan_bytes(token.encode(), "member")
            inspector.scan_json({token: token, "other": token}, "pax")
            inspector.scan_bytes(token.encode(), "member")
        summary = inspector.finding_summary()
        self.assertEqual(summary["total"], 4)
        self.assertEqual(summary["byRule"]["service_token"], 4)
        self.assertEqual(summary["byUnit"], {
            "archive_member": 1, "json_key": 1, "json_string": 2, "metadata_value": 0, "byte_input": 0})
        self.assertIsNone(inspector.unit_kind)
        self.assertEqual(inspector.unit_rules, set())
        self.assertFalse(hasattr(inspector, "seen_findings"))

    def test_zero_representatives_cannot_turn_findings_into_a_pass(self):
        result = self.files([("app/data", b"sk-" + b"S" * 30)]).inspect(
            limits=dataclasses.replace(privacy.Limits(), findings=0))
        self.assertTrue(result["inspectionComplete"])
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["findingSummary"]["total"], 1)
        self.assertTrue(result["representativesTruncated"])
        self.assertEqual(result["status"], "failed")

    def test_saturated_samples_do_not_hide_later_structural_failures(self):
        first = archive([(f"app/leak-{i}", b"sk-" + b"S" * 30) for i in range(70)])
        for media, broken, refusal in ((privacy.TAR, b"broken tar", "malformed_or_unreadable_layout"),
                                      (privacy.TAR + "+zstd", b"unsupported", "unsupported_layer_format"),
                                      (privacy.TAR, archive([("app/last", b"ok")]) + b"hidden", "trailing_archive_data")):
            with self.subTest(refusal=refusal), tempfile.TemporaryDirectory() as directory:
                fixture = Layout(directory, layers=[(privacy.TAR, first), (media, broken)])
                result = fixture.inspect()
                self.assertFalse(result["inspectionComplete"])
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["refusal"], refusal)
                self.assertEqual(result["findingSummary"]["byRule"]["service_token"], 70)
                self.assertTrue(result["representativesTruncated"])

    def test_location_index_and_identity_set_remain_bounded_after_overflow(self):
        inspector = privacy.Inspector("unused", None, SOURCE, TOOLING, privacy.Limits())
        for index in range(7000):
            inspector.scan_bytes(b"sk-" + b"S" * 30, f"app/location-{index}", "sha256:" + "c" * 64)
        self.assertEqual(inspector.finding_total, 7000)
        self.assertLessEqual(len(inspector.location_identities), 4096)
        self.assertEqual(len(inspector.location_identities), len(inspector.location_index))
        encoded = json.dumps(inspector.location_index, sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(len(encoded), inspector.location_index_bytes)
        self.assertLessEqual(len(encoded), 512 * 1024)
        self.assertTrue(inspector.location_index_truncated)
        self.assertLessEqual(len(inspector.findings), 64)
        self.assertLessEqual(len(inspector.unit_rules), len(privacy.FINDING_RULES))
        # Counts represent occurrences, while the bounded index deduplicates names.
        inspector.scan_bytes(b"sk-" + b"S" * 30, "app/location-0", "sha256:" + "c" * 64)
        self.assertEqual(inspector.finding_total, 7001)
        self.assertEqual(len(encoded), inspector.location_index_bytes)

    def test_large_complete_cli_report_stays_readable_and_chunked(self):
        fixture = self.files([(f"app/location-{i}", b"sk-" + b"S" * 30) for i in range(7000)])
        with tempfile.TemporaryDirectory() as evidence:
            output = Path(evidence) / "receipt.json"
            result = subprocess.run([sys.executable, str(Path(privacy.__file__)),
                "--oci-dir", str(fixture.directory), "--expected-index-digest", fixture.index["digest"],
                "--source-sha", SOURCE, "--tooling-sha", TOOLING, "--output", str(output)],
                capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 1, result.stderr)
            summary, details, locations = cli_diagnostics(result.stdout)
            disk = json.loads(output.read_text())
            self.assertTrue(summary["inspectionComplete"])
            self.assertEqual(summary["findings"], 7000)
            self.assertTrue(summary["locationIndexTruncated"])
            self.assertTrue(summary["representativesTruncated"])
            self.assertEqual(details, disk["findings"])
            self.assertEqual(locations, disk["locationIndex"])
            self.assertLessEqual(output.stat().st_size, 1024 * 1024)
            self.assertLessEqual(len(json.dumps(locations, sort_keys=True, separators=(",", ":")).encode()), 512 * 1024)
            self.assertLess(max(len(line.encode()) for line in result.stdout.splitlines()), 16 * 1024)
            for kind, maximum in (("finding_details", 16), ("location_index", 32)):
                offset = 0
                for record in map(json.loads, result.stdout.splitlines()):
                    if record.get("recordType") == kind:
                        self.assertEqual(record["offset"], offset)
                        self.assertLessEqual(len(record["items"]), maximum)
                        offset += len(record["items"])
            self.assertNotIn("app/location-", result.stdout + output.read_text())
            self.assertNotIn("sk-" + "S" * 30, result.stdout + output.read_text())


if __name__ == "__main__":
    unittest.main()

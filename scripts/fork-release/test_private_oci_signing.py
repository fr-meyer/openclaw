"""Canonical signing vectors and fake entrypoints; never acquire credentials."""
import base64
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import private_oci_signing as signing
import private_oci_transfer as transfer


NOW = 1_792_843_200.0
PUT_VECTOR = """PUT
/synthetic-private-bucket/oci-quarantine/v2026.10.5/30786562e236aab6a924981c62aa61b920132c76/synthetic/retained-oci.tar
X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=synthetic-signer%40synthetic-project.iam.gserviceaccount.com%2F20261024%2Fauto%2Fstorage%2Fgoog4_request&X-Goog-Date=20261024T120000Z&X-Goog-Expires=600&X-Goog-SignedHeaders=content-type%3Bhost%3Bx-goog-content-length-range%3Bx-goog-if-generation-match
content-type:application/octet-stream
host:storage.googleapis.com
x-goog-content-length-range:1,2147483648
x-goog-if-generation-match:0

content-type;host;x-goog-content-length-range;x-goog-if-generation-match
UNSIGNED-PAYLOAD"""
GET_VECTOR = """GET
/synthetic-private-bucket/oci-quarantine/v2026.10.5/30786562e236aab6a924981c62aa61b920132c76/synthetic/retained-oci.tar
X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=synthetic-signer%40synthetic-project.iam.gserviceaccount.com%2F20261024%2Fauto%2Fstorage%2Fgoog4_request&X-Goog-Date=20261024T120000Z&X-Goog-Expires=900&X-Goog-SignedHeaders=host&generation=1234
host:storage.googleapis.com

host
UNSIGNED-PAYLOAD"""


class Response:
    status = 200

    def __init__(self):
        self.body = json.dumps({"keyId": "synthetic-key", "signedBlob": base64.b64encode(bytes(range(256))).decode()}).encode()
        self.headers = []

    def getheaders(self):
        return self.headers

    def read(self, size):
        return self.body[:size]


class SigningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.plan = {
            "schema": "openclaw.private-oci-signing-plan.v1", "sourceSha": transfer.SOURCE,
            "workflowSha": "a" * 40, "bucket": "synthetic-private-bucket",
            "object": f"oci-quarantine/v2026.10.5/{transfer.SOURCE}/synthetic/retained-oci.tar",
            "signer": "synthetic-signer@synthetic-project.iam.gserviceaccount.com",
            "operator": "approved@example.test", "method": "PUT", "expiresSeconds": 600, "generation": None,
        }
        self.plan_path = self.root / "plan.json"
        self.output = self.root / "capability.json"
        self.response = Response()
        self.token_calls = []
        self.requests = []
        self.connections = []
        self.token = b"ya29.synthetic_operator_token_12345"
        self.write_plan()
        self.patch = mock.patch.object(signing, "gcloud_executable", return_value="/synthetic-approved-sdk/bin/gcloud")
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def write_plan(self):
        raw = json.dumps(self.plan).encode()
        self.plan_path.write_bytes(raw)
        self.plan_path.chmod(0o600)
        self.plan_hash = hashlib.sha256(raw).hexdigest()

    def runner(self, command, **options):
        self.assertEqual(command, ["/synthetic-approved-sdk/bin/gcloud", "auth", "print-access-token", "--account",
                                   "approved@example.test", "--quiet", "--verbosity=error"])
        self.assertNotIn("--impersonate-service-account", command)
        self.assertEqual(options["timeout"], 30)
        env = options["env"]
        for name in ("CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT", "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE", "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"):
            self.assertEqual(env[name], "")
        for name in ("CLOUDSDK_AUTH_ACCESS_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS", "PYTHONPATH", "HTTPS_PROXY"):
            self.assertNotIn(name, env)
        self.assertEqual(env["CLOUDSDK_CORE_LOG_HTTP"], "false")
        self.assertEqual(env["CLOUDSDK_CORE_DISABLE_FILE_LOGGING"], "true")
        self.assertTrue(Path(str(self.output) + ".attempt.json").exists())
        self.token_calls.append(command)
        return SimpleNamespace(returncode=0, stdout=self.token + b"\n", stderr=b"ignored synthetic sensitive warning")

    def factory(self, host, timeout):
        self.assertEqual(host, "iamcredentials.googleapis.com")
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 30)
        outer = self
        class Connection:
            closed = False

            def request(self, method, path, *, body, headers):
                outer.assertEqual(method, "POST")
                outer.assertEqual(path, "/v1/projects/-/serviceAccounts/synthetic-signer%40synthetic-project.iam.gserviceaccount.com:signBlob")
                outer.assertEqual(headers["Authorization"], "Bearer " + outer.token.decode())
                outer.assertEqual(headers["Content-Length"], str(len(body)))
                outer.assertEqual(set(json.loads(body)), {"payload"})
                outer.requests.append((method, path, body, headers))

            def getresponse(self):
                return outer.response

            def close(self):
                self.closed = True
        connection = Connection()
        self.connections.append(connection)
        return connection

    def run_entry(self, action=None, *, extra=(), runner=None, factory=None, clock=None):
        args = ([action] if action else []) + ["--plan", str(self.plan_path), "--plan-sha256", self.plan_hash,
                                               "--operator", "approved@example.test"] + list(extra)
        if action == "sign":
            args += ["--output", str(self.output)]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = signing.main(args, runner=runner or self.runner, connection_factory=factory or self.factory,
                                clock=clock or (lambda: NOW), environ={"HOME": "/synthetic/home", "PATH": "/untrusted",
                                "CLOUDSDK_AUTH_ACCESS_TOKEN": "ignored-secret", "HTTPS_PROXY": "https://not-used",
                                "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT": "ignored-signer"})
        self.assertEqual(err.getvalue(), "")
        for forbidden in (self.token.decode(), "X-Goog", self.plan["signer"], "ignored-secret", "synthetic sensitive"):
            self.assertNotIn(forbidden, out.getvalue())
        return code, json.loads(out.getvalue())

    def test_fixed_put_and_get_vectors_bind_canonical_headers_and_scope(self):
        for method, expiry, generation, expected in [("PUT", 600, None, PUT_VECTOR), ("GET", 900, "1234", GET_VECTOR)]:
            with self.subTest(method=method):
                self.plan.update(method=method, expiresSeconds=expiry, generation=generation)
                result = signing.prepare(self.plan, "approved@example.test", NOW)
                self.assertEqual(result["canonicalRequest"], expected)
                expected_hash = hashlib.sha256(expected.encode()).hexdigest()
                self.assertEqual(result["canonicalRequestSha256"], expected_hash)
                expected_string = "GOOG4-RSA-SHA256\n20261024T120000Z\n20261024/auto/storage/goog4_request\n" + expected_hash
                self.assertEqual(result["stringToSign"], expected_string)
                self.assertEqual(base64.b64decode(result["signBlobBody"]["payload"]).decode(), expected_string)
                self.assertNotIn("X-Goog-Signature", result["unsignedUrl"])

    def test_default_prepare_has_no_credentials_or_network_and_only_safe_hashes(self):
        code, result = self.run_entry()
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "prepared")
        self.assertFalse(self.token_calls or self.requests)
        signing.gcloud_executable.assert_not_called()
        self.assertFalse(self.output.exists())
        self.assertEqual(self.run_entry(extra=("--output", str(self.output)))[0], 0)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(self.output.read_text())["canonicalRequest"], PUT_VECTOR)

    def test_explicit_sign_outputs_only_exact_seven_field_private_envelope(self):
        code, result = self.run_entry("sign")
        self.assertEqual(code, 0)
        envelope = json.loads(self.output.read_text())
        self.assertEqual(set(envelope), {"schema", "sourceSha", "workflowSha", "bucket", "object", "signer", "url"})
        self.assertEqual(envelope["schema"], "openclaw.private-oci-capability.v1")
        self.assertEqual(envelope["url"].split("X-Goog-Signature=")[1], bytes(range(256)).hex())
        self.assertEqual(result["capabilitySha256"], hashlib.sha256(self.output.read_bytes()).hexdigest())
        self.assertFalse(result["productionAuthorized"])
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        self.assertTrue(self.connections[0].closed)
        before = self.output.read_bytes()
        self.assertEqual(self.run_entry("sign")[0], 1)
        self.assertEqual(self.output.read_bytes(), before)
        self.assertEqual(len(self.token_calls), 1)

    def test_signed_url_compatible_with_existing_transfer_scope_checks(self):
        self.assertEqual(self.run_entry("sign")[0], 0)
        envelope = json.loads(self.output.read_text())
        plan = {"bucket": self.plan["bucket"], "object": self.plan["object"], "signer": self.plan["signer"],
                "generation": None, "archiveBytes": 8}
        _, headers, _ = transfer.validate_capability(envelope["url"], plan, "PUT", NOW)
        self.assertEqual(headers["x-goog-content-length-range"], "1,2147483648")

    def test_small_probe_bound_is_explicit_and_signed_not_default_reduction(self):
        self.plan["maximumBytes"] = 8
        result = signing.prepare(self.plan, "approved@example.test", NOW)
        self.assertIn("x-goog-content-length-range:1,8\n", result["canonicalRequest"])
        self.assertNotEqual(result["canonicalRequestSha256"], hashlib.sha256(PUT_VECTOR.encode()).hexdigest())

    def test_wrong_principal_source_endpoint_bounds_and_unknown_fields_refused(self):
        cases = [("operator", "other@example.test"), ("sourceSha", "b" * 40), ("workflowSha", "short"),
                 ("bucket", "bad/host"), ("object", "elsewhere/file"), ("signer", "bad@other.test"),
                 ("method", "POST"), ("expiresSeconds", 3601), ("expiresSeconds", True),
                 ("maximumBytes", 0), ("maximumBytes", transfer.MAX_BYTES + 1), ("maximumBytes", True),
                 ("endpoint", "https://other.example")]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                original = copy.deepcopy(self.plan)
                self.plan[key] = value
                self.write_plan()
                self.assertEqual(self.run_entry("sign")[0], 1)
                self.assertFalse(self.token_calls or self.requests)
                self.plan = original

    def test_get_generation_and_shorter_expiry_are_required(self):
        self.plan.update(method="GET", generation="1234", expiresSeconds=900)
        self.write_plan()
        self.assertEqual(self.run_entry("sign")[0], 0)
        envelope = json.loads(self.output.read_text())
        self.assertIn("generation=1234&X-Goog-Signature=", envelope["url"])
        for key, value in [("generation", None), ("generation", "0"), ("expiresSeconds", 901), ("maximumBytes", 8)]:
            invalid = dict(self.plan, **{key: value})
            with self.assertRaises(transfer.Refusal):
                signing.prepare(invalid, "approved@example.test", NOW)

    def test_private_plan_integrity_and_parse_errors_do_not_disclose_values(self):
        self.plan_path.write_bytes(self.plan_path.read_bytes() + b" ")
        self.assertEqual(self.run_entry("sign")[1]["reason"], "plan_hash_mismatch")
        self.write_plan()
        self.plan_path.chmod(0o644)
        self.assertEqual(self.run_entry("sign")[1]["reason"], "private_file_required")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(signing.main(["synthetic-secret-invalid-action"]), 1)
        self.assertEqual(err.getvalue(), "")
        self.assertNotIn("synthetic-secret", out.getvalue())
        self.assertFalse(self.token_calls or self.requests)

    def test_token_failure_keeps_reservation_and_never_contacts_iam(self):
        def failed(command, **options):
            return SimpleNamespace(returncode=1, stdout=self.token, stderr=self.token)
        code, result = self.run_entry("sign", runner=failed)
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "operator_token_failed")
        self.assertTrue(Path(str(self.output) + ".attempt.json").exists())
        self.assertFalse(self.requests)
        self.assertEqual(self.output.read_bytes(), b"")

    def test_iam_errors_redirects_bad_json_and_signatures_are_sanitized(self):
        cases = [(307, b"synthetic sensitive redirect", [("location", "https://other.example")]),
                 (403, self.token, []), (200, b"x" * (signing.LIMIT + 1), []),
                 (200, b'{"signedBlob":"x","signedBlob":"y","keyId":"key"}', []),
                 (200, json.dumps({"keyId": "key", "signedBlob": base64.b64encode(b"short").decode()}).encode(), []),
                 (200, json.dumps({"keyId": "key", "signedBlob": "invalid!"}).encode(), [])]
        for number, (status, body, headers) in enumerate(cases):
            with self.subTest(number=number):
                self.output = self.root / f"capability-{number}.json"
                self.response.status, self.response.body, self.response.headers = status, body, headers
                self.assertEqual(self.run_entry("sign")[0], 1)
                self.assertEqual(self.output.read_bytes(), b"")
                self.assertTrue(self.connections[-1].closed)

    def test_expiry_after_token_and_after_signing_refuses_capability(self):
        values = iter([NOW, NOW + 601])
        self.assertEqual(self.run_entry("sign", clock=lambda: next(values))[1]["reason"], "capability_expired")
        self.assertFalse(self.requests)
        self.output = self.root / "late-capability.json"
        values = iter([NOW, NOW, NOW + 601])
        self.assertEqual(self.run_entry("sign", clock=lambda: next(values))[1]["reason"], "capability_expired")
        self.assertEqual(self.output.read_bytes(), b"")

    def probe_setup(self):
        self.plan.update(maximumBytes=8, expiresSeconds=120)
        self.write_plan()
        blueprint = signing.prepare(self.plan, "approved@example.test", NOW)
        self.probe_envelope = {key: self.plan[key] for key in ("sourceSha", "workflowSha", "bucket", "object", "signer")}
        self.probe_envelope.update(schema="openclaw.private-oci-capability.v1",
                                   url=blueprint["unsignedUrl"] + "&X-Goog-Signature=" + bytes(range(256)).hex())
        self.capability_path = self.root / "probe-capability.json"
        self.write_probe_envelope()

    def write_probe_envelope(self):
        raw = json.dumps(self.probe_envelope).encode()
        self.capability_path.write_bytes(raw)
        self.capability_path.chmod(0o600)
        self.capability_hash = hashlib.sha256(raw).hexdigest()

    def run_probe(self, statuses=(400, 403, 200, 412), *, generation="5678", failure=None, clock=None):
        outer = self
        calls = []
        connections = []
        def factory(host, timeout):
            self.assertEqual(host, transfer.HOST)
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 30)
            self.assertTrue(Path(str(self.output) + ".attempt.json").exists())
            class Connection:
                closed = False

                def request(self, method, target, *, body, headers):
                    outer.assertEqual(method, "PUT")
                    outer.assertTrue(target.startswith("/synthetic-private-bucket/oci-quarantine/"))
                    outer.assertEqual(headers["content-type"], "application/octet-stream")
                    outer.assertEqual(headers["x-goog-if-generation-match"], "0")
                    outer.assertEqual(headers["content-length"], str(len(body)))
                    calls.append((body, headers.copy()))
                    if failure:
                        raise OSError(failure)

                def getresponse(self):
                    response = Response()
                    response.status = statuses[len(calls) - 1]
                    response.headers = [("x-goog-generation", generation)] if response.status == 200 else []
                    def forbidden_read(size):
                        outer.fail("Probe must not read or log provider response bodies")
                    response.read = forbidden_read
                    return response

                def close(self):
                    self.closed = True
            conn = Connection()
            connections.append(conn)
            return conn
        code, result = self.run_entry("probe", extra=("--capability-file", str(self.capability_path),
            "--capability-sha256", self.capability_hash, "--output", str(self.output)), factory=factory, clock=clock)
        self.assertFalse(self.token_calls)
        signing.gcloud_executable.assert_not_called()
        self.assertTrue(all(connection.closed for connection in connections))
        return code, result, calls

    def test_probe_actual_entrypoint_uses_only_four_fixed_bodies_and_signed_headers(self):
        self.probe_setup()
        code, result, calls = self.run_probe()
        self.assertEqual(code, 0)
        self.assertEqual(result["httpStatuses"], [400, 403, 200, 412])
        self.assertEqual(result["generation"], "5678")
        self.assertTrue(result["providerEnforcementVerified"])
        self.assertFalse(result["productionAuthorized"])
        self.assertEqual([body for body, _ in calls], [b"OCIprobe!", b"OCIprobe!", b"OCIprobe", b"OCIprobe"])
        self.assertEqual([headers["x-goog-content-length-range"] for _, headers in calls], ["1,8", "1,9", "1,8", "1,8"])
        self.assertEqual(json.loads(self.output.read_text()), result)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(result["capabilitySha256"], self.capability_hash)
        self.assertEqual(result["signingOwnerSha256"], hashlib.sha256(Path(signing.__file__).read_bytes()).hexdigest())
        self.assertEqual(self.run_probe()[0], 1)

    def test_probe_unexpected_acceptance_or_status_stops_immediately(self):
        self.probe_setup()
        for number, statuses in enumerate(((200,), (400, 200), (400, 403, 403), (400, 403, 200, 200), (302,))):
            with self.subTest(number=number):
                self.output = self.root / f"probe-failed-{number}.json"
                code, result, calls = self.run_probe(statuses)
                self.assertEqual(code, 1)
                self.assertEqual(len(calls), len(statuses))
                self.assertEqual(result["httpStatuses"], list(statuses))
                self.assertFalse(result["providerEnforcementVerified"])
                self.assertEqual(result["reason"], "probe_unexpected_status")
                self.assertEqual(json.loads(self.output.read_text()), result)

    def test_probe_plan_requires_explicit_eight_byte_bound_and_short_expiry(self):
        self.probe_setup()
        for key, value in (("maximumBytes", 9), ("maximumBytes", True), ("expiresSeconds", 121),
                           ("method", "GET"), ("operator", "other@example.test")):
            with self.subTest(key=key):
                original = copy.deepcopy(self.plan)
                self.plan[key] = value
                self.write_plan()
                code, _, calls = self.run_probe()
                self.assertEqual(code, 1)
                self.assertFalse(calls)
                self.plan = original
        self.plan.pop("maximumBytes")
        self.write_plan()
        self.assertEqual(self.run_probe()[0], 1)

    def test_probe_envelope_identity_signature_url_and_hash_are_pinned(self):
        self.probe_setup()
        for key, value in (("workflowSha", "b" * 40), ("sourceSha", "b" * 40),
                           ("url", self.probe_envelope["url"].replace(transfer.HOST, "other.example")),
                           ("url", self.probe_envelope["url"].replace("X-Goog-Expires=120", "X-Goog-Expires=121")),
                           ("extra", "not-allowed")):
            with self.subTest(key=key, value=value[:20]):
                original = copy.deepcopy(self.probe_envelope)
                self.probe_envelope[key] = value
                self.write_probe_envelope()
                code, _, calls = self.run_probe()
                self.assertEqual(code, 1)
                self.assertFalse(calls)
                self.probe_envelope = original
        self.write_probe_envelope()
        self.capability_path.write_bytes(self.capability_path.read_bytes() + b" ")
        self.assertEqual(self.run_probe()[1]["reason"], "capability_hash_mismatch")

    def test_probe_expiry_missing_generation_and_network_error_never_grant_proof(self):
        self.probe_setup()
        self.assertEqual(self.run_probe(clock=lambda: NOW + 121)[0], 1)
        code, result, calls = self.run_probe(generation="malformed-generation")
        self.assertEqual(code, 1)
        self.assertEqual(len(calls), 3)
        self.assertEqual(result["reason"], "probe_response_generation")
        self.output = self.root / "network-failed-probe.json"
        code, result, calls = self.run_probe(failure="synthetic sensitive " + self.probe_envelope["url"])
        self.assertEqual(code, 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["reason"], "probe_io_error")
        self.assertNotIn("synthetic sensitive", self.output.read_text())


if __name__ == "__main__":
    unittest.main()

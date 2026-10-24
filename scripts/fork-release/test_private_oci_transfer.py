"""Synthetic entrypoint proofs; no provider requests or real credentials."""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import tempfile
import unittest
from urllib.parse import urlencode

import private_oci_transfer as transfer


NOW = 1_792_843_200.0  # 2026-10-24T12:00:00Z


class Response:
    def __init__(self, body=b"", status=200, headers=None):
        self.status = status
        self.body = io.BytesIO(body)
        self.headers = headers or [("x-goog-generation", "1234"), ("content-length", str(len(body)))]

    def getheaders(self):
        return self.headers

    def read(self, size):
        return self.body.read(size)


class Connection:
    def __init__(self, response):
        self.response = response
        self.request = None
        self.headers = {}
        self.sent = bytearray()
        self.closed = False

    def putrequest(self, method, target, **kwargs):
        self.request = (method, target, kwargs)

    def putheader(self, key, value):
        self.headers[key] = value

    def endheaders(self):
        pass

    def send(self, value):
        self.sent.extend(value)

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class PrivateTransferTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.body = b"synthetic opaque OCI archive\x00\x01"
        self.plan = {
            "schema": "openclaw.private-oci-transfer-plan.v1", "sourceSha": transfer.SOURCE,
            "toolingSha": "a" * 40, "runId": "123", "attempt": "1",
            "archiveSha256": hashlib.sha256(self.body).hexdigest(), "archiveBytes": len(self.body),
            "bucket": "synthetic-private-bucket",
            "object": f"oci-quarantine/v2026.10.5/{transfer.SOURCE}/synthetic/retained-oci.tar",
            "signer": "synthetic-signer@synthetic-project.iam.gserviceaccount.com", "generation": None,
        }
        self.plan_path = self.root / "plan.json"
        self.url_path = self.root / "capability.txt"
        self.archive = self.root / "archive.tar"
        self.receipt = self.root / "receipt.json"
        self.archive.write_bytes(self.body)
        self.calls = []
        self.connection = Connection(Response())
        self.write_plan()
        self.write_url(self.url())

    def write_plan(self):
        raw = json.dumps(self.plan).encode()
        self.plan_path.write_bytes(raw)
        self.plan_path.chmod(0o600)
        self.plan_hash = hashlib.sha256(raw).hexdigest()

    def url(self, method="PUT", changes=None):
        values = {
            "X-Goog-Algorithm": "GOOG4-RSA-SHA256",
            "X-Goog-Credential": f"{self.plan['signer']}/20261024/auto/storage/goog4_request",
            "X-Goog-Date": "20261024T120000Z", "X-Goog-Expires": "600",
            "X-Goog-SignedHeaders": transfer.PUT_HEADERS if method == "PUT" else "host",
            "X-Goog-Signature": "b" * 512,
        }
        if method == "GET":
            values["generation"] = self.plan["generation"]
        values.update(changes or {})
        return f"https://{transfer.HOST}/{self.plan['bucket']}/{self.plan['object']}?{urlencode(values)}"

    def write_url(self, value):
        self.url_path.write_text(value)
        self.url_path.chmod(0o600)

    def factory(self, host, timeout):
        self.assertEqual(host, transfer.HOST)
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 30)
        self.assertTrue(Path(str(self.receipt) + ".attempt.json").is_file())
        self.calls.append(host)
        return self.connection

    def run_entry(self, action=None, extra=(), factory=None, clock=None, environ=None):
        argv = ([action] if action else []) + [
            "--plan", str(self.plan_path), "--plan-sha256", self.plan_hash,
            "--capability-file", str(self.url_path), "--archive", str(self.archive), "--receipt", str(self.receipt),
        ] + list(extra)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = transfer.main(argv, connection_factory=factory or self.factory, clock=clock or (lambda: NOW), environ=environ)
        self.assertNotIn("X-Goog-Signature", output.getvalue())
        self.assertNotIn(self.plan["signer"], output.getvalue())
        self.assertNotIn(self.plan["object"], output.getvalue())
        return code, json.loads(output.getvalue())

    def get_setup(self):
        self.plan["generation"] = "1234"
        self.write_plan()
        self.write_url(self.url("GET"))
        self.archive = self.root / "download.tar"
        self.connection = Connection(Response(self.body))

    def test_default_validates_without_network_or_receipt(self):
        code, result = self.run_entry()
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "validated")
        self.assertFalse(result["signatureAuthenticated"])
        self.assertFalse(result["providerEnforcementVerified"])
        self.assertFalse(self.calls)
        self.assertFalse(self.receipt.exists())

    def test_put_actual_entrypoint_preserves_bytes_headers_and_nonpromotable_receipts(self):
        code, result = self.run_entry("put")
        self.assertEqual(code, 0)
        self.assertEqual(bytes(self.connection.sent), self.body)
        self.assertEqual(self.connection.request[0], "PUT")
        self.assertEqual(self.connection.headers["x-goog-if-generation-match"], "0")
        self.assertEqual(self.connection.headers["x-goog-content-length-range"], "1,2147483648")
        self.assertEqual(self.connection.headers["content-type"], "application/octet-stream")
        self.assertEqual(self.connection.headers["content-length"], str(len(self.body)))
        self.assertEqual(result["remoteOutcome"], "put_acknowledged")
        self.assertEqual(result["generation"], "1234")
        self.assertFalse(result["productionAuthorized"])
        self.assertFalse(result["imageQualified"])
        for path in (self.receipt, Path(str(self.receipt) + ".attempt.json")):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(self.receipt.read_text()), result)
        self.assertTrue(self.connection.closed)
        code, _ = self.run_entry("put")
        self.assertEqual(code, 1)
        self.assertEqual(len(self.calls), 1)

    def test_get_exact_generation_hash_bytes_and_private_output(self):
        self.get_setup()
        code, result = self.run_entry("get")
        self.assertEqual(code, 0)
        self.assertEqual(self.archive.read_bytes(), self.body)
        self.assertEqual(self.archive.stat().st_mode & 0o777, 0o600)
        self.assertEqual(result["remoteOutcome"], "download_verified")
        self.assertEqual(self.connection.headers, {"host": transfer.HOST})
        self.assertIn("generation=1234", self.connection.request[1])

    def test_plan_hash_source_fields_and_limits_fail_before_network(self):
        for field, value in [("sourceSha", "c" * 40), ("toolingSha", "short"), ("attempt", True),
                             ("archiveBytes", transfer.MAX_BYTES + 1), ("archiveBytes", True),
                             ("object", "../retained-oci.tar"), ("signer", "other@example.com"),
                             ("unknown", "value")]:
            with self.subTest(field=field, value=value):
                original = copy.deepcopy(self.plan)
                self.plan[field] = value
                self.write_plan()
                code, _ = self.run_entry("put")
                self.assertEqual(code, 1)
                self.assertFalse(self.calls)
                self.plan = original
        self.write_plan()
        self.plan_path.write_text(self.plan_path.read_text() + " ")
        self.assertEqual(self.run_entry("put")[1]["reason"], "plan_hash_mismatch")

    def test_capability_authority_scope_and_signed_headers_are_closed(self):
        urls = [
            self.url().replace(transfer.HOST, "elsewhere.example"),
            self.url().replace(transfer.HOST, transfer.HOST + ":443"),
            self.url().replace("https://", "http://"), self.url() + "#fragment",
            self.url().replace("/oci-quarantine/", "/%6fci-quarantine/"),
            self.url().replace("X-Goog-Algorithm=", "%58-Goog-Algorithm="),
            self.url() + "&X-Goog-Expires=600", self.url() + "&extra=1",
            self.url(changes={"X-Goog-Expires": "3601"}),
            self.url(changes={"X-Goog-Date": "20261024T130000Z"}),
            self.url(changes={"X-Goog-Date": "20261024T100000Z"}),
            self.url(changes={"X-Goog-SignedHeaders": "host"}),
            self.url(changes={"X-Goog-SignedHeaders": transfer.PUT_HEADERS + ";x-other"}),
            self.url(changes={"X-Goog-Credential": f"{self.plan['signer']}/20261024/other/storage/goog4_request"}),
            self.url(changes={"X-Goog-Signature": "bad"}),
        ]
        for url in urls:
            with self.subTest(index=urls.index(url)):
                self.write_url(url)
                self.assertEqual(self.run_entry("put")[0], 1)
                self.assertFalse(self.calls)

    def test_private_capability_file_and_env_without_value_disclosure(self):
        self.url_path.chmod(0o644)
        self.assertEqual(self.run_entry()[1]["reason"], "private_file_required")
        self.url_path.unlink()
        target = self.root / "actual-secret"
        target.write_text(self.url())
        target.chmod(0o600)
        self.url_path.symlink_to(target)
        self.assertEqual(self.run_entry()[0], 1)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = transfer.main(["--plan", str(self.plan_path), "--plan-sha256", self.plan_hash,
                                  "--capability-env", "SYNTHETIC_UPLOAD_URL"],
                                 environ={"SYNTHETIC_UPLOAD_URL": self.url()}, clock=lambda: NOW,
                                 connection_factory=self.factory)
        self.assertEqual(code, 0)
        self.assertNotIn(self.url(), output.getvalue())
        self.assertFalse(self.calls)

    def test_put_bad_bytes_or_size_refused_before_network(self):
        self.archive.write_bytes(b"x" * len(self.body))
        self.assertEqual(self.run_entry("put")[1]["reason"], "archive_hash_mismatch")
        self.archive.write_bytes(self.body + b"x")
        self.assertEqual(self.run_entry("put")[1]["reason"], "archive_size_mismatch")
        with self.archive.open("wb") as stream:
            stream.truncate(transfer.MAX_BYTES + 1)
        self.assertEqual(self.run_entry("put")[1]["reason"], "input_type_or_size")
        self.assertFalse(self.calls)

    def test_put_in_place_mutation_is_uncertain_never_success(self):
        def factory(host, timeout):
            self.archive.write_bytes(b"x" * len(self.body))
            return self.factory(host, timeout)
        code, result = self.run_entry("put", factory=factory)
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "archive_changed")
        self.assertEqual(result["remoteOutcome"], "unknown")
        self.assertFalse(result["imageQualified"])

    def test_expiry_rechecked_after_hash_before_connecting(self):
        values = iter([NOW, NOW, NOW + 601])
        code, result = self.run_entry("put", clock=lambda: next(values))
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "capability_expired_or_future")
        self.assertEqual(result["remoteOutcome"], "not_attempted")
        self.assertFalse(self.calls)

    def test_redirect_and_sensitive_network_errors_never_follow_or_print(self):
        self.connection.response = Response(status=307, headers=[("location", "https://secret.example/private")])
        code, result = self.run_entry("put")
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "http_status_refused")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(result["remoteOutcome"], "unknown")
        self.receipt = self.root / "another-receipt.json"
        def fail(host, timeout):
            raise OSError(self.url() + " synthetic-secret")
        code, result = self.run_entry("put", factory=fail)
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "transfer_io_error")
        self.assertNotIn("synthetic-secret", self.receipt.read_text())

    def test_get_rejects_generation_size_hash_and_preserves_unqualified_partial(self):
        self.get_setup()
        cases = [Response(self.body, headers=[("x-goog-generation", "999"), ("content-length", str(len(self.body)))]),
                 Response(self.body + b"x"), Response(b"x" * len(self.body)),
                 Response(self.body + b"x", headers=[("x-goog-generation", "1234"), ("content-length", str(len(self.body)))]),
                 Response(self.body[:-1], headers=[("x-goog-generation", "1234"), ("content-length", str(len(self.body)))])]
        for number, response in enumerate(cases):
            with self.subTest(number=number):
                self.archive = self.root / f"download-{number}.tar"
                self.receipt = self.root / f"receipt-{number}.json"
                self.connection = Connection(response)
                code, result = self.run_entry("get")
                self.assertEqual(code, 1)
                self.assertEqual(result["remoteOutcome"], "unknown")
                self.assertFalse(result["imageQualified"])
                self.assertTrue(self.archive.exists())

    def test_get_query_generation_and_put_direction_cannot_be_substituted(self):
        self.get_setup()
        self.write_url(self.url("GET", {"generation": "5678"}))
        self.assertEqual(self.run_entry("get")[1]["reason"], "get_generation")
        self.write_url(self.url("GET"))
        self.assertEqual(self.run_entry("put")[0], 1)
        self.assertFalse(self.calls)

    def test_existing_reservation_and_output_never_overwritten(self):
        marker = Path(str(self.receipt) + ".attempt.json")
        marker.write_bytes(b"preserved uncertain attempt")
        self.assertEqual(self.run_entry("put")[0], 1)
        self.assertEqual(marker.read_bytes(), b"preserved uncertain attempt")
        self.assertFalse(self.calls)
        self.get_setup()
        self.archive.write_bytes(b"existing file")
        self.assertEqual(self.run_entry("get")[0], 1)
        self.assertEqual(self.archive.read_bytes(), b"existing file")

    def test_invalid_arguments_never_echo_private_values(self):
        for argv in ([self.url()], ["--unexpected", "synthetic-sensitive-value"],
                     ["--method", self.url()]):
            with self.subTest(case=len(argv)):
                output, errors = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    code = transfer.main(argv, connection_factory=self.factory)
                self.assertEqual(code, 1)
                self.assertEqual(json.loads(output.getvalue())["reason"], "invalid_arguments")
                self.assertEqual(errors.getvalue(), "")
                self.assertNotIn("synthetic-sensitive", output.getvalue())
                self.assertNotIn("X-Goog", output.getvalue())
        self.assertFalse(self.calls)

    def test_absolute_network_deadline_interrupts_headers_and_restores_handler(self):
        previous = signal.getsignal(signal.SIGALRM)
        def blocked_headers():
            self.assertGreater(signal.getitimer(signal.ITIMER_REAL)[0], 0)
            signal.getsignal(signal.SIGALRM)(signal.SIGALRM, None)
        self.connection.getresponse = blocked_headers
        code, result = self.run_entry("put")
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "transfer_deadline")
        self.assertEqual(result["remoteOutcome"], "unknown")
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual(signal.getsignal(signal.SIGALRM), previous)
        self.assertTrue(self.connection.closed)

    def test_late_response_cannot_be_claimed_success(self):
        now = [NOW]
        def late_response():
            now[0] += 601
            return self.connection.response
        self.connection.getresponse = late_response
        code, result = self.run_entry("put", clock=lambda: now[0])
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "transfer_deadline")

    def test_get_deadline_and_duplicate_generation_headers_are_refused(self):
        self.get_setup()
        def expired_body(size):
            signal.getsignal(signal.SIGALRM)(signal.SIGALRM, None)
        self.connection.response.read = expired_body
        code, result = self.run_entry("get")
        self.assertEqual(code, 1)
        self.assertEqual(result["reason"], "transfer_deadline")
        self.assertTrue(self.archive.exists())
        self.archive = self.root / "second-download.tar"
        self.receipt = self.root / "second-receipt.json"
        self.connection = Connection(Response(self.body, headers=[("x-goog-generation", "1234"),
                                                                 ("x-goog-generation", "1234")]))
        self.assertEqual(self.run_entry("get")[1]["reason"], "response_headers")


if __name__ == "__main__":
    unittest.main()

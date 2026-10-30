"""Synthetic-only diagnostics regression: no network, token file or candidate."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
import urllib.error

HERE = Path(__file__).resolve().parent
# Root local scratch supplies unchanged import dependencies; published CI uses
# these same-directory owners already present in its reviewed code closure.
DEPENDENCIES = HERE.parents[2]
if str(DEPENDENCIES) not in sys.path:
    sys.path.insert(0, str(DEPENDENCIES))
spec = importlib.util.spec_from_file_location("admission_diagnostic_under_test", HERE / "source_validation_v109.py")
runtime = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = runtime
spec.loader.exec_module(runtime)


class Response:
    def __init__(self, raw=b'{}', url="https://api.github.com/repos/fr-meyer/openclaw/actions/runs/1/jobs?filter=all&per_page=100&page=1", error=None):
        self.raw, self.url, self.error = raw, url, error
    def __enter__(self): return self
    def __exit__(self, *args): return None
    def geturl(self): return self.url
    def read(self, cap):
        if self.error: raise self.error
        return self.raw[:cap] if type(self.raw) is bytes else self.raw


class Opener:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.calls = response or Response(), error, 0
    def open(self, request, timeout):
        self.calls += 1
        if self.error: raise self.error
        return self.response


class Diagnostics(unittest.TestCase):
    PATH = "/repos/fr-meyer/openclaw/actions/runs/1/jobs?filter=all&per_page=100&page=1"
    def setUp(self): runtime._FAILURE_PHASE = "closed_historical_native"
    def capture_failure(self, error, *, response=None):
        opener = Opener(response, None if response else error)
        api = runtime.API("SYNTHETIC_BEARER_NEVER_PRINT", runtime.time.time() + 60, opener)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            with self.assertRaises(type(error)) as raised:
                api(self.PATH)
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        facts = json.loads(lines[0])
        self.assertEqual(facts["readOrdinal"], 1)
        self.assertEqual(facts["callFamily"], "run_jobs")
        self.assertEqual(facts["phase"], "closed_historical_native")
        self.assertEqual(facts["status"], "refused")
        self.assertFalse(facts["imageBuilt"])
        self.assertFalse(facts["productionAuthorized"])
        for forbidden in ("SYNTHETIC_BEARER", "private-error", "https://", "endpoint", "stderr", "body", "reason"):
            self.assertNotIn(forbidden, output.getvalue())
        self.assertEqual(api.cache, {})
        self.assertEqual(opener.calls, 1)
        return raised.exception, facts
    def test_http_status_preserved_without_text_or_retry(self):
        error = urllib.error.HTTPError("https://private-error", 403, "private-error", {"X-RateLimit-Limit":"1000", "X-RateLimit-Remaining":"0", "X-RateLimit-Reset":"1793380000", "Private-Header":"private-error"}, io.BytesIO(b"private-error"))
        raised, facts = self.capture_failure(error)
        self.assertIs(raised, error)
        self.assertEqual(facts["exceptionCategory"], "http_error")
        self.assertEqual(facts["httpStatus"], 403)
        self.assertEqual(facts["operation"], "open")
        self.assertEqual(facts["rateLimitLimit"], 1000)
        self.assertEqual(facts["rateLimitRemaining"], 0)
        self.assertEqual(facts["rateLimitReset"], 1793380000)
    def test_untrusted_rate_headers_not_printed_or_coerced(self):
        error = urllib.error.HTTPError("https://private-error", 403, "private-error", {
            "X-RateLimit-Limit":"private-error", "X-RateLimit-Remaining":False,
            "X-RateLimit-Reset":"999999999999999999999999999999999"}, io.BytesIO(b"private-error"))
        _, facts = self.capture_failure(error)
        self.assertFalse(any(name.startswith("rateLimit") for name in facts))
    def test_url_error_not_reinterpreted_as_http_status(self):
        raised, facts = self.capture_failure(urllib.error.URLError("private-error"))
        self.assertEqual(facts["exceptionCategory"], "url_error")
        self.assertNotIn("httpStatus", facts)
    def test_open_timeout_distinct(self):
        raised, facts = self.capture_failure(TimeoutError("private-error"))
        self.assertEqual(facts["exceptionCategory"], "timeout")
    def test_read_os_error_distinct(self):
        error = OSError("private-error")
        raised, facts = self.capture_failure(error, response=Response(error=error))
        self.assertIs(raised, error)
        self.assertEqual(facts["exceptionCategory"], "os_error")
        self.assertEqual(facts["operation"], "read")
    def test_malformed_json_still_refused(self):
        raised, facts = self.capture_failure(runtime.policy.Refusal("v9.invalid_json"), response=Response(b'{"private-error":'))
        self.assertEqual(facts["exceptionCategory"], "owned_refusal")
        self.assertEqual(facts["operation"], "parse")
    def test_duplicate_json_keys_still_refused(self):
        raised, facts = self.capture_failure(runtime.policy.Refusal("v9.invalid_json"), response=Response(b'{"same":1,"same":2}'))
        self.assertEqual(facts["exceptionCategory"], "owned_refusal")
    def test_wrong_native_input_type_remains_guard_refusal(self):
        raised, facts = self.capture_failure(runtime.policy.Refusal("v9.bounded_json"), response=Response(None))
        self.assertEqual(facts["exceptionCategory"], "owned_refusal")
    def test_redirect_is_guard_refusal_no_new_transport(self):
        raised, facts = self.capture_failure(runtime.policy.Refusal("v9.api_redirect"), response=Response(url="https://private-error"))
        self.assertEqual(facts["exceptionCategory"], "owned_refusal")
        self.assertEqual(facts["operation"], "open")
    def test_success_cache_and_ordinal_unchanged(self):
        opener = Opener(Response(b'{"safe":1}'))
        api = runtime.API("SYNTHETIC_BEARER", runtime.time.time() + 60, opener)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(api(self.PATH), {"safe":1})
            self.assertEqual(api(self.PATH), {"safe":1})
        self.assertEqual(opener.calls, 1)
        self.assertEqual(api.read_ordinal, 1)
        self.assertEqual(output.getvalue(), "")
    def test_later_read_failure_reports_actual_ordinal(self):
        opener = Opener(Response(b'{}'))
        api = runtime.API("SYNTHETIC_BEARER", runtime.time.time() + 60, opener)
        api(self.PATH)
        opener.error = OSError("private-error")
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(OSError):
            api(self.PATH.replace('/1/', '/2/'))
        self.assertEqual(json.loads(out.getvalue())["readOrdinal"], 2)
        self.assertEqual(opener.calls, 2)
    def test_diagnostic_write_failure_never_replaces_original(self):
        error = OSError("private-error")
        api = runtime.API("SYNTHETIC_BEARER", runtime.time.time() + 60, Opener(error=error))
        with patch.object(runtime, "emit", side_effect=OSError("diagnostic write")):
            with self.assertRaises(OSError) as raised: api(self.PATH)
        self.assertIs(raised.exception, error)
    def test_nonzero_subprocess_does_not_publish_streams(self):
        error = subprocess.CalledProcessError(1, ["private-error"], b"private-error", b"private-error")
        out = io.StringIO()
        with contextlib.redirect_stdout(out): runtime.emit_failure_diagnostic(error)
        value = json.loads(out.getvalue())
        self.assertEqual(value["exceptionCategory"], "process_nonzero")
        self.assertNotIn("private-error", out.getvalue())
        self.assertEqual(runtime.safe_refusal_code(error), "v9.runtime_refused")
    def test_exception_and_label_allowlists(self):
        categories = [(KeyError("private-error"), "key_error"), (TypeError("private-error"), "type_error"),
            (ValueError("private-error"), "value_error"),
            (subprocess.TimeoutExpired(["private-error"], 1, output=b"private-error"), "process_timeout")]
        runtime._FAILURE_PHASE = "private-error"
        for error, expected in categories:
            with self.subTest(expected=expected):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    runtime.emit_failure_diagnostic(error, family="private-error", ordinal=True, operation="private-error")
                value = json.loads(out.getvalue())
                self.assertEqual(value["exceptionCategory"], expected)
                self.assertEqual(value["phase"], "unclassified")
                self.assertNotIn("readOrdinal", value)
                self.assertNotIn("callFamily", value)
                self.assertNotIn("operation", value)
                self.assertNotIn("private-error", out.getvalue())
    def test_call_families_never_return_paths(self):
        prefix = "/repos/fr-meyer/openclaw"
        paths = {"/actions/runs?branch=public": "history", "/actions/runs/2": "run_header",
            "/actions/runs/2/artifacts?per_page=100&page=1": "run_artifacts", "/pulls/28": "pull_request",
            "/git/ref/heads/task/public": "branch_ref", "/contents/public?ref=abc": "public_content"}
        for path, family in paths.items(): self.assertEqual(runtime.provider_call_family(prefix + path), family)


if __name__ == "__main__": unittest.main()

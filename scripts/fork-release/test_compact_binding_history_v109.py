"""One authentic historical binding exception; current delivery stays bounded."""
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch, mock_open
import base64
import socket
import os
import re
import textwrap
import time
import subprocess
import unittest
import urllib.request

import bounded_run_contract_v109 as allowance
import source_validation_contract_v109 as policy
import source_validation_v109 as runtime

HERE = Path(__file__).resolve().parent
HEAD = "3ee51f984a005af08e16e510724b579a96a86774"
BODY_SHA256 = "24815ef47fad29f0580bc7fd400f35f61f16c4ef146224056a7ac1485a910a52"
REQUEST_SHA256 = "6b136615d12015cd237a6eac497244c67362116cda3ba7deca13c657018306f9"


class CompactBindingHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (HERE / "fixtures/v109-gen6-prep17-ci-bindings.json").read_bytes()
        cls.request_raw = (HERE / "fixtures/v109-gen6-prep17-source-request.json").read_bytes()
        if len(cls.raw) != 133856 or policy.digest(cls.raw) != BODY_SHA256 or policy.digest(cls.request_raw) != REQUEST_SHA256:
            raise AssertionError("authenticated published historical fixture")
        cls.now = policy.utc("2026-11-06T02:28:52Z").timestamp()

    def setUp(self):
        for owner, name in ((subprocess, "Popen"), (socket, "socket"),
                (urllib.request, "urlopen"), (urllib.request, "build_opener")):
            guard = patch.object(owner, name, side_effect=AssertionError("process/network/application forbidden"))
            guard.start(); self.addCleanup(guard.stop)

    def api(self, raw, head=HEAD, size=None):
        def read(route):
            self.assertEqual(route, "/repos/" + policy.REPOSITORY + "/contents/" + runtime.BINDINGS + "?ref=" + head)
            return {"type": "file", "encoding": "base64", "size": len(raw) if size is None else size,
                "content": base64.b64encode(raw).decode("ascii")}
        return read

    def test_exact_published_body_authenticates_only_through_known_history_selector(self):
        self.assertEqual(runtime.source_history_binding_content(self.api(self.raw), HEAD), self.raw)
        with self.assertRaisesRegex(ValueError, "public_content_metadata"):
            runtime.content(self.api(self.raw), runtime.BINDINGS, HEAD)
        other = "a" * 40
        with self.assertRaisesRegex(ValueError, "public_content_metadata"):
            runtime.source_history_binding_content(self.api(self.raw, other), other)

    def test_wrong_size_hash_and_semantically_identical_reencoding_refuse(self):
        compact = policy.canonical(policy.parse(self.raw)) + b"\n"
        for label, raw in (("short", self.raw[:-1]), ("long", self.raw + b"\n"),
                ("same-size-tamper", self.raw[:-1] + b" "), ("compact-old-object", compact)):
            with self.subTest(label=label), self.assertRaises(ValueError):
                runtime.source_history_binding_content(self.api(raw), HEAD)
        with self.assertRaisesRegex(ValueError, "public_content_size"):
            runtime.source_history_binding_content(self.api(self.raw[:-1], size=len(self.raw)), HEAD)

    def test_all_other_heads_keep_default_current_limit_and_compact_semantics(self):
        compact = policy.canonical(policy.parse(self.raw)) + b"\n"
        other = "b" * 40
        self.assertLess(len(compact), 131072)
        self.assertEqual(runtime.source_history_binding_content(self.api(compact, other), other), compact)
        self.assertEqual(policy.canonical(policy.parse(compact)), policy.canonical(policy.parse(self.raw)))
        oversized = compact + b" " * (131073 - len(compact))
        with self.assertRaisesRegex(ValueError, "public_content_metadata"):
            runtime.source_history_binding_content(self.api(oversized, other), other)

    def test_current_physical_metadata_reader_still_refuses_even_the_known_old_body(self):
        with TemporaryDirectory(prefix="historical-binding-cap-") as temporary:
            root = Path(temporary).resolve()
            candidate = root / runtime.CANDIDATE
            candidate.mkdir(parents=True)
            (candidate / "ci-bindings.json").write_bytes(self.raw)
            (candidate / "source-request.json").write_bytes(self.request_raw)
            with self.assertRaisesRegex(ValueError, "regular_bounded_input"):
                runtime.load_metadata(root, active=True, now=self.now)
            compact = policy.canonical(policy.parse(self.raw)) + b"\n"
            (candidate / "ci-bindings.json").write_bytes(compact)
            bindings, request, rraw = runtime.load_metadata(root, active=True, now=self.now)
            self.assertEqual(bindings, policy.parse(self.raw))
            self.assertEqual(request["executionSequence"], 25)
            self.assertEqual(rraw, self.request_raw)

    def test_full_policy_reviewed_request_and_native_role_checks_remain_required(self):
        raw = runtime.source_history_binding_content(self.api(self.raw), HEAD)
        bindings = policy.validate_bindings(policy.parse(raw))
        request = policy.validate_request(policy.parse(self.request_raw), bindings)
        grant = policy.run_grant(bindings)
        allowance.validate_grant(grant, bindings["authorization"], active=True, now=self.now)
        self.assertEqual(policy.digest(self.request_raw), grant["nextExecution"]["requestSha256"])
        run = {"id": 42150524188, "head_sha": HEAD, "run_attempt": 1,
            "repository": {"full_name": policy.REPOSITORY, "private": False},
            "actor": {"login": "fr-meyer"}, "triggering_actor": {"login": "fr-meyer"},
            "event": "pull_request", "head_branch": policy.PIPELINE_BRANCH, "path": policy.WORKFLOW,
            "name": policy.CAMPAIGN, "display_title": policy.CAMPAIGN}
        self.assertEqual(runtime.role(run, request), {"lock-preparation": 45})
        for key, value in (("event", "push"), ("head_branch", "main"), ("run_attempt", 2)):
            bad = deepcopy(run); bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): runtime.role(bad, request)
        bad = deepcopy(bindings); bad["ciRunGrant"]["nextExecution"]["reviewSha256"] = None
        with self.assertRaises(ValueError):
            allowance.validate_grant(bad["ciRunGrant"], bad["authorization"], active=True, now=self.now)
        bad_request = deepcopy(request); bad_request["executionSequence"] = 26
        with self.assertRaises(ValueError): policy.validate_request(bad_request, bindings)

    def test_time_only_projection_keeps_old_scope_and_every_resource_field(self):
        old = allowance.vendor_repair_combined_source_allocation()
        self.assertEqual(allowance.digest(old), "ef97529a1e252a4cc9777762b199abdb860e7f40b2c8e6a0cae77bdb77db0e36")
        new = allowance.vendor_repair_combined_source_deadline_extension()
        expected = deepcopy(old)
        expected.update(expiresAt="2026-11-09T03:14:21Z", latestWholePlanAdmission="2026-11-08T07:04:21Z")
        expected["deadlineExtension"] = {"schema": "openclaw.v109.time-only-deadline-extension.v1",
            "authorizationSha256": "8350ab78bfeaaef2779c94f725e0fbb030f454261903192c5c180585c8d73337",
            "previousExpiresAt": "2026-11-07T03:14:21Z", "expiresAt": "2026-11-09T03:14:21Z",
            "resourceScopeChanged": False}
        self.assertEqual(new, expected)
        self.assertIs(allowance.validate_vendor_repair_continuation(new), new)
        self.assertEqual(allowance.vendor_continuation_from_digest(allowance.digest(new)), new)
        for label in ("wrong-supplement", "changed-pool", "changed-family", "unknown-field", "nonboolean-scope"):
            bad = deepcopy(new)
            if label == "wrong-supplement": bad["deadlineExtension"]["authorizationSha256"] = "a" * 64
            if label == "changed-pool": bad["stagePools"]["preparation"] += 1
            if label == "changed-family": bad["maximumMaterialSourceGenerations"] = 8
            if label == "unknown-field": bad["newAccess"] = True
            if label == "nonboolean-scope": bad["deadlineExtension"]["resourceScopeChanged"] = 0
            with self.subTest(label=label), self.assertRaises(ValueError): allowance.validate_vendor_repair_continuation(bad)

    def test_prospective_descriptor_and_request_bind_exact_time_extension(self):
        from test_combined_source_repair_v109 import bindings
        b = bindings()
        grant = b["ciRunGrant"]
        old = allowance.h3_stage_descriptor(True, True)
        new = allowance.h3_stage_descriptor(True, True, True)
        self.assertEqual({k: v for k, v in old.items() if k != "expiresAt"},
            {k: v for k, v in new.items() if k != "expiresAt"})
        self.assertEqual((old["expiresAt"], new["expiresAt"]), ("2026-11-07T03:14:21Z", "2026-11-09T03:14:21Z"))
        grant["sourceSuccessorAmendment"].update(new)
        grant["sourceSuccessorAmendment"]["vendorRepairContinuation"] = allowance.vendor_repair_combined_source_deadline_extension()
        grant["expiresAt"] = new["expiresAt"]
        request = policy.request_for(b, "lock-preparation", 17)
        self.assertIs(policy.validate_request(request, b), request)
        self.assertEqual(policy.h3_stage_contract(b, request), new)
        self.assertEqual(policy.source_authorization_window(b)[1], new["expiresAt"])
        self.assertEqual((grant["maximumAdditionalAttempts"], grant["maximumNewRunnerMinutes"], grant["moneyCeilingUSD"]),
            (1000, 25000, "25.00"))
        grant["sourceSuccessorAmendment"]["expiresAt"] = old["expiresAt"]
        with self.assertRaises(ValueError): policy.validate_bindings(b)

    def test_prospective_four_inline_workflow_clocks_require_exact_nov9_end(self):
        blocks = []
        for name in ("v109-h3-lock-preparation.yml", "v109-h3-source-validation.yml"):
            text = (HERE / "fixtures" / name).read_text()
            blocks.extend(textwrap.dedent(body) for body in re.findall(r"python3 - <<'PY'\n(.*?)          PY", text, re.S) if "def utc(v):" in body)
        self.assertEqual(len(blocks), 4)
        now = policy.utc("2026-11-07T04:00:00Z").timestamp()
        env = {"V109_APPROVED_AT": "2026-10-30T03:14:21Z", "V109_EXPIRES_AT": "2026-11-09T03:14:21Z", "GITHUB_ENV": "/synthetic/not-opened"}
        for block in blocks:
            writer = mock_open()
            with patch.dict(os.environ, env, clear=True), patch.object(time, "time", return_value=now), patch("builtins.open", writer):
                exec(compile(block, "<time-only-clock>", "exec"), {})
            writer.assert_called_once_with("/synthetic/not-opened", "a")
            for end, clock in (("2026-11-07T03:14:21Z", now), ("2026-11-10T03:14:21Z", now),
                    (env["V109_EXPIRES_AT"], policy.utc(env["V109_EXPIRES_AT"]).timestamp())):
                writer = mock_open()
                with patch.dict(os.environ, {**env, "V109_EXPIRES_AT": end}, clear=True), patch.object(time, "time", return_value=clock), patch("builtins.open", writer), self.assertRaises(SystemExit):
                    exec(compile(block, "<time-only-clock>", "exec"), {})
                writer.assert_not_called()

    def test_public_history_exception_is_exact_not_a_default_limit_change(self):
        self.assertEqual(runtime.HISTORICAL_OVERSIZE_BINDINGS_HEAD, HEAD)
        self.assertEqual(runtime.HISTORICAL_OVERSIZE_BINDINGS_BYTES, 133856)
        self.assertEqual(runtime.HISTORICAL_OVERSIZE_BINDINGS_SHA256, BODY_SHA256)
        self.assertEqual(len(policy.parse(self.raw)["ciRunGrant"]["bookedAdditionalAttempts"]), 459)
        self.assertEqual(len(policy.parse(self.raw)["ciRunGrant"]["sourceSuccessorAmendment"]["bookedArtifacts"]), 34)


if __name__ == "__main__": unittest.main()

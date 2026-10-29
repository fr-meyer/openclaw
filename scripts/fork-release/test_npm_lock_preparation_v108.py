"""Trusted Python contract tests only; never launches Node, pnpm or a network call."""
import contextlib
import copy
from datetime import datetime, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("npm_lock_preparation_contract", HERE / "npm_lock_prepare_v108.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
HEAD = "a" * 40
RID = "40720000000"
NOW = int(datetime(2026, 10, 29, 1, 0, tzinfo=timezone.utc).timestamp())


def pr():
    repo = {"full_name": M.REPOSITORY, "private": False}
    return {"number": 28, "state": "open", "draft": True,
            "head": {"repo": repo, "ref": M.BRANCH, "sha": HEAD},
            "base": {"repo": repo, "ref": M.BASE_BRANCH, "sha": M.BASE}}


def event():
    return {"action": "synchronize", "number": 28, "pull_request": pr()}


def run():
    repo = {"full_name": M.REPOSITORY, "private": False}
    return {"id": int(RID), "run_attempt": 1, "event": "pull_request", "path": M.WORKFLOW,
            "head_branch": M.BRANCH, "head_sha": HEAD, "status": "in_progress",
            "actor": {"login": "fr-meyer"}, "repository": repo, "head_repository": repo}


def history():
    rows = [{"id": rid, "head_sha": head, "run_attempt": 1, "status": "completed", "path": M.WORKFLOW}
            for rid, head in M.PRIOR_SOURCE_RUNS.items()]
    return {"total_count": 9, "workflow_runs": [*rows, run()]}


def jobs():
    return {"total_count": 1, "jobs": [{"id": 1234, "name": "lock-preparation", "run_id": int(RID),
        "head_sha": HEAD, "run_attempt": 1, "status": "in_progress", "runner_id": 88,
        "labels": ["ubuntu-24.04"]}]}


def context():
    return {"schema": "openclaw.v108.npm-lock-admission.v1", "sourceSha": M.SOURCE,
        "sourceTree": M.TREE, "pipelineHead": HEAD, "runId": RID, "runAttempt": 1,
        "jobId": 1234, "checkedAtEpoch": NOW - 30, "expiresAtEpoch": NOW + 570,
        "deadlineEpoch": NOW - 100 + 45 * 60 - 60, "startedEpoch": NOW - 100}


def synthetic_lock():
    return ("lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n"
            "      npm:\n        specifier: 12.2.0\n        version: 12.2.0\n"
            "packages:\n  npm@12.2.0:\n    resolution: {integrity: " + M.OLD_NPM_SRI + "}\n"
            "    engines: {node: stable}\nsnapshots:\n  npm@12.2.0: {}\n").encode()


def generated_lock(before):
    return before.replace(b"specifier: 12.2.0", b"specifier: 12.2.1").replace(
        b"version: 12.2.0", b"version: 12.2.1").replace(b"npm@12.2.0:", b"npm@12.2.1:").replace(
        M.OLD_NPM_SRI.encode(), M.NPM_SRI.encode())


class Contracts(unittest.TestCase):
    def test_exact_event_and_environment_scope(self):
        self.assertEqual(M.event_binding(event(), {}), HEAD)
        mutations = [lambda x: x.update(number=27), lambda x: x.update(action="edited"),
                     lambda x: x["pull_request"].update(draft=False),
                     lambda x: x["pull_request"]["head"].update(ref="main"),
                     lambda x: x["pull_request"]["base"].update(sha="b" * 40),
                     lambda x: x["pull_request"]["head"]["repo"].update(private=True)]
        for mutate in mutations:
            value = copy.deepcopy(event()); mutate(value)
            with self.subTest(value=value), self.assertRaises(M.Refusal):
                M.event_binding(value, {})

    def test_full_job_clock_and_overall_deadline(self):
        self.assertEqual(M.clock_deadline({"NPM_LOCK_STARTED_EPOCH": str(NOW - 100)}, NOW), NOW - 100 + 2640)
        for start in ("", "-1", str(NOW + 1), str(NOW - 2640)):
            with self.subTest(start=start), self.assertRaises(M.Refusal):
                M.clock_deadline({"NPM_LOCK_STARTED_EPOCH": start}, NOW)
        absolute = int(datetime.fromisoformat(M.DEADLINE.replace("Z", "+00:00")).timestamp())
        with self.assertRaises(M.Refusal):
            M.clock_deadline({"NPM_LOCK_STARTED_EPOCH": str(absolute - 2699)}, absolute - 2698)

    def test_current_run_is_exact_public_actor_and_attempt(self):
        M.checked_public_run(run(), RID, HEAD)
        for key, value in (("run_attempt", 2), ("head_sha", "b" * 40), ("event", "workflow_dispatch"),
                           ("status", "queued"), ("actor", {"login": "other"})):
            item = run(); item[key] = value
            with self.subTest(key=key), self.assertRaises(M.Refusal):
                M.checked_public_run(item, RID, HEAD)
        item = run(); item["repository"] = {"full_name": M.REPOSITORY, "private": True}
        with self.assertRaises(M.Refusal): M.checked_public_run(item, RID, HEAD)

    def test_unique_closed_source_history_refuses_duplicate_or_pending(self):
        M.checked_history(history(), RID, HEAD)
        for mutate in (lambda t: t["workflow_runs"].append(run()),
                       lambda t: t["workflow_runs"][0].update(status="in_progress"),
                       lambda t: t["workflow_runs"][0].update(head_sha="b" * 40),
                       lambda t: t["workflow_runs"][0].update(id=999),
                       lambda t: t.update(total_count=10)):
            table = history(); mutate(table)
            with self.assertRaises(M.Refusal): M.checked_history(table, RID, HEAD)

    def test_one_acquired_hosted_job_only(self):
        self.assertEqual(M.checked_jobs(jobs(), RID, HEAD), 1234)
        for key, value in (("name", "source (dependency)"), ("runner_id", None),
                           ("labels", ["self-hosted", "ubuntu-24.04"]), ("run_attempt", 2)):
            table = jobs(); table["jobs"][0][key] = value
            with self.assertRaises(M.Refusal): M.checked_jobs(table, RID, HEAD)
        table = jobs(); table["jobs"].append(copy.deepcopy(table["jobs"][0])); table["total_count"] = 2
        with self.assertRaises(M.Refusal): M.checked_jobs(table, RID, HEAD)

    def test_timeout_cannot_pass_with_zero_or_valid_output(self):
        success = subprocess.CompletedProcess(["synthetic"], 0)
        success.timed_out = False
        M.successful_phase(success)
        for code, timed in ((0, True), (1, False), (None, False), (0, None)):
            result = subprocess.CompletedProcess(["synthetic"], code, stdout=b'{"valid":true}')
            result.timed_out = timed
            with self.subTest(code=code, timed=timed), self.assertRaises(M.Refusal):
                M.successful_phase(result)

    def test_package_patch_is_exact_and_single(self):
        old = b'{"dependencies":{"npm": "12.2.0","other":"1.0.0"}}\n'
        new = old.replace(b'"npm": "12.2.0"', b'"npm": "12.2.1"')
        with patch.object(M, "PACKAGE_SHA", M.digest(old)), patch.object(M, "NEW_PACKAGE_SHA", M.digest(new)):
            self.assertEqual(M.patched_package(old), new)
            with self.assertRaises(M.Refusal): M.patched_package(old + b" ")
        duplicate = old + b'"npm": "12.2.0"'
        with patch.object(M, "PACKAGE_SHA", M.digest(duplicate)), self.assertRaises(M.Refusal):
            M.patched_package(duplicate)

    def test_actual_resolver_bytes_need_exact_npm_only_lock_delta(self):
        old = synthetic_lock(); new = generated_lock(old)
        with patch.object(M, "LOCK_SHA", M.digest(old)):
            M.validate_generated_lock(old, new)
            for value in (old, new.replace(b"stable", b"unexpected"), new.replace(M.NPM_SRI.encode(), b"sha512-fake"),
                          new + b"unrelated: 1\n"):
                with self.subTest(value=value[-60:]), self.assertRaises(M.Refusal):
                    M.validate_generated_lock(old, value)

    def test_lock_comparison_never_writes_or_returns_a_replacement(self):
        old = synthetic_lock(); new = generated_lock(old)
        with patch.object(M, "LOCK_SHA", M.digest(old)), patch.object(Path, "write_bytes") as write:
            self.assertIsNone(M.validate_generated_lock(old, new))
            write.assert_not_called()

    def test_duplicate_and_nonfinite_json_refuse(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
            with self.assertRaises(M.Refusal): M.parse(raw)

    def test_regular_input_symlinks_and_caps_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); source = root / "plain"; source.write_bytes(b"abcd")
            link = root / "link"; link.symlink_to(source)
            self.assertEqual(M.regular(source, 4, M.digest(b"abcd")), b"abcd")
            for p, cap in ((link, 4), (source, 3)):
                with self.assertRaises(M.Refusal): M.regular(p, cap)

    def test_private_write_is_exclusive_and_600(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp).resolve() / "proof"; M.private_write(p, b"proof")
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError): M.private_write(p, b"replacement")
            self.assertEqual(p.read_bytes(), b"proof")

    def test_admission_hash_fieldset_and_freshness_are_positive(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp).resolve() / "context"; value = context(); raw = M.encode(value); M.private_write(p, raw)
            self.assertEqual(M.read_admission(p, M.digest(raw), RID, NOW, value["deadlineEpoch"]), value)
            with self.assertRaises(M.Refusal): M.read_admission(p, "0" * 64, RID, NOW, value["deadlineEpoch"])
            with self.assertRaises(M.Refusal): M.read_admission(p, M.digest(raw), RID, NOW + 600, value["deadlineEpoch"])
            del value["jobId"]; p.unlink(); raw = M.encode(value); M.private_write(p, raw)
            with self.assertRaises(M.Refusal): M.read_admission(p, M.digest(raw), RID, NOW, NOW + 2540)

    def test_artifact_closed_regular_subset_and_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); output = root / "artifact"; output.mkdir(); target = root / "github-output"; target.touch()
            M.private_write(output / "generation.json", b"{}")
            M.artifact_ready({"GITHUB_OUTPUT": str(target)}, output)
            self.assertIn("artifact_ready=true", target.read_text())
            (output / "extra").write_bytes(b"unselected")
            with self.assertRaises(M.Refusal): M.artifact_ready({"GITHUB_OUTPUT": str(target)}, output)

    def failure_state(self, root, result=None):
        source = root / "source"; source.mkdir(); (source / "pnpm-lock.yaml").write_bytes(b"public-lock: changed\n")
        return {"source": source, "output": root / "artifact", "rid": RID, "head": HEAD,
                "phase": "validate_lock", "source_bound": True, "generated_attempt": True, "result": result}

    def test_scope_failure_keeps_actual_public_material_before_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); out = root / "github-output"; out.touch()
            result = subprocess.CompletedProcess(["synthetic"], 0); result.timed_out = False
            result.cleanup_settled = None; result.actual_returncode = 0
            state = self.failure_state(root, result)
            diff = b"diff --git a/pnpm-lock.yaml b/pnpm-lock.yaml\n+public-lock: changed\n"
            with patch.object(M, "git", return_value=diff):
                M.preserve_failure(state, M.Refusal("lock.unrelated_resolution_or_format_change"), {"GITHUB_OUTPUT": str(out)})
            folder = state["output"]
            self.assertEqual({p.name for p in folder.iterdir()}, {"pnpm-lock.yaml", "npm-lock.diff", "generation.json"})
            self.assertEqual((folder / "npm-lock.diff").read_bytes(), diff)
            receipt = json.loads((folder / "generation.json").read_text())
            self.assertEqual(receipt["status"], "refused")
            self.assertEqual(receipt["refusalCode"], "lock.unrelated_resolution_or_format_change")
            self.assertFalse(receipt["qualified"])
            self.assertIn("artifact_ready=true", out.read_text())

    def test_unsettled_or_unknown_writer_exports_metadata_only(self):
        for missing in (False, True):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve(); out = root / "github-output"; out.touch()
                result = None if missing else subprocess.CompletedProcess(["synthetic"], 124)
                if result:
                    result.timed_out = True; result.cleanup_settled = False; result.actual_returncode = None
                state = self.failure_state(root, result)
                with patch.object(M, "git") as command, patch.object(M, "regular") as read:
                    M.preserve_failure(state, M.Refusal("process.nonzero_or_timeout"), {"GITHUB_OUTPUT": str(out)})
                command.assert_not_called(); read.assert_not_called()
                self.assertEqual([p.name for p in state["output"].iterdir()], ["generation.json"])
                receipt = json.loads((state["output"] / "generation.json").read_text())
                self.assertEqual(receipt["missingFileReasons"]["pnpm-lock.yaml"], "writer_unsettled")

    def test_unknown_or_credential_like_failure_material_stays_metadata_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); out = root / "github-output"; out.touch()
            result = subprocess.CompletedProcess(["synthetic"], 1); result.timed_out = False
            state = self.failure_state(root, result)
            (state["source"] / "pnpm-lock.yaml").write_bytes(b"tarball: https://user:secret@example.test/file\n")
            with patch.object(M, "git", return_value=b"safe diff\n"):
                M.preserve_failure(state, M.Refusal("lock.unrelated_resolution_or_format_change"), {"GITHUB_OUTPUT": str(out)})
            self.assertEqual([p.name for p in state["output"].iterdir()], ["generation.json"])
            self.assertNotIn("secret", (state["output"] / "generation.json").read_text())

    def test_oversize_failure_records_structure_without_reading_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); out = root / "github-output"; out.touch()
            result = subprocess.CompletedProcess(["synthetic"], 1); result.timed_out = False
            state = self.failure_state(root, result)
            with (state["source"] / "pnpm-lock.yaml").open("wb") as stream:
                stream.truncate(M.CAP + 1)
            with patch.object(M, "git") as command:
                M.preserve_failure(state, M.Refusal("lock.unrelated_resolution_or_format_change"), {"GITHUB_OUTPUT": str(out)})
            command.assert_not_called()
            self.assertEqual([p.name for p in state["output"].iterdir()], ["generation.json"])
            receipt = json.loads((state["output"] / "generation.json").read_text())
            fact = receipt["fileFacts"]["pnpm-lock.yaml"]
            self.assertEqual((fact["entryType"], fact["bytes"], fact["hashComplete"], fact["sha256"]),
                             ("regular", M.CAP + 1, False, None))

    def test_api_redirects_are_refused_without_an_alternate_request(self):
        opened = {}
        class Opener:
            def open(self, request, timeout):
                opened["request"] = request
                raise OSError("synthetic transport refusal")
        def factory(handler):
            self.assertIsNone(handler.redirect_request(None, None, 302, "moved", {}, "https://other.invalid"))
            return Opener()
        with patch.object(M.urllib.request, "build_opener", side_effect=factory), \
             patch.object(M.time, "time", return_value=NOW), contextlib.redirect_stdout(io.StringIO()), \
             self.assertRaises(M.Refusal):
            M.public_api("/repos/" + M.REPOSITORY + "/pulls/28", "SYNTHETIC_TOKEN", NOW + 10)
        self.assertEqual(opened["request"].full_url, "https://api.github.com/repos/" + M.REPOSITORY + "/pulls/28")

    def test_each_api_failure_position_keeps_safe_kind_status_and_quota(self):
        prefix = "/repos/" + M.REPOSITORY
        routes = [(prefix + "/actions/runs/" + RID, "current_run", 0),
                  (prefix + "/pulls/28", "pr28", 1),
                  (prefix + "/git/ref/heads/prep/v2026.10.8-remediation", "source_ref", 2),
                  (prefix + "/actions/workflows/future-v108-source-validation.yml/runs?fixed=synthetic", "source_history", 3),
                  (prefix + "/actions/runs/" + RID + "/jobs?filter=all&per_page=100", "current_jobs", 4)]
        body = b'SYNTHETIC_PRIVATE_BODY token=NEVER_PRINT_THIS'
        for route, kind, ordinal in routes:
            with self.subTest(kind=kind):
                class Opener:
                    def open(self, request, timeout):
                        raise M.urllib.error.HTTPError(request.full_url, 403, "synthetic private message",
                            {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1793236000",
                             "Retry-After": "3", "Location": "https://never-print.invalid/private"}, io.BytesIO(body))
                capture = io.StringIO()
                with patch.object(M.urllib.request, "build_opener", return_value=Opener()), \
                     patch.object(M.time, "time", return_value=NOW), contextlib.redirect_stdout(capture), \
                     self.assertRaises(M.Refusal):
                    M.public_api(route, "NEVER_PRINT_TOKEN", NOW + 10)
                record = json.loads(capture.getvalue())
                self.assertEqual((record["phase"], record["ordinal"], record["httpStatus"]), (kind, ordinal, 403))
                self.assertEqual((record["rateLimitRemaining"], record["rateLimitResetEpoch"], record["retryAfterSeconds"]),
                                 (0, 1793236000, 3))
                self.assertEqual((record["responseBodyBytes"], record["responseBodySha256"], record["responseBodyComplete"]),
                                 (len(body), M.digest(body), True))
                self.assertFalse(record["rawBodyReturned"])
                for private in ("PRIVATE_BODY", "NEVER_PRINT", "private message", "never-print.invalid"):
                    self.assertNotIn(private, capture.getvalue())

    def test_api_parse_and_cap_refusals_keep_original_response_facts(self):
        for body, status in ((b'{"duplicate":1,"duplicate":2}', "response_json_refused"),
                             (b"[1,2]", "response_json_refused"), (b"not JSON", "response_json_refused"),
                             (b"x" * (M.CAP + 1), "response_cap_refused")):
            with self.subTest(status=status, bytes=len(body)):
                class Response:
                    status = 200
                    headers = {"X-RateLimit-Remaining": "7"}
                    def __enter__(self): return self
                    def __exit__(self, *args): return None
                    def read(self, count): return body[:count]
                class Opener:
                    def open(self, request, timeout): return Response()
                capture = io.StringIO()
                with patch.object(M.urllib.request, "build_opener", return_value=Opener()), \
                     patch.object(M.time, "time", return_value=NOW), contextlib.redirect_stdout(capture), \
                     self.assertRaises(M.Refusal):
                    M.public_api("/repos/" + M.REPOSITORY + "/pulls/28", "SYNTHETIC_TOKEN", NOW + 10)
                record = json.loads(capture.getvalue())
                self.assertEqual((record["phase"], record["httpStatus"], record["status"]), ("pr28", 200, status))
                self.assertEqual(record["responseBodySha256"], M.digest(body))
                self.assertEqual(record["responseBodyComplete"], len(body) <= M.CAP)

    def test_internal_bootstrap_refuses_ordinary_linux_without_ci_admission(self):
        with patch.object(M.sys, "platform", "linux"), patch.dict(M.os.environ, {}, clear=True), \
             patch.object(M, "load_driver") as driver:
            with self.assertRaises(M.Refusal): M.internal_bootstrap(Path("/synthetic/private/context"))
            driver.assert_not_called()

    def test_internal_bootstrap_binds_admission_then_strips_public_ci_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); workspace = root / "workspace"; temporary = root / "temporary"
            workspace.mkdir(); temporary.mkdir(); pipeline = workspace / "pipeline"; source = workspace / "source"
            pipeline.mkdir(); source.mkdir(); home = temporary / ("v108-npm-lock-home-" + RID); home.mkdir(mode=0o700)
            admission = context(); raw = M.encode(admission)
            M.private_write(temporary / ("v108-npm-lock-admission-" + RID + ".json"), raw)
            context_path = home / "bootstrap-context.json"
            M.private_write(context_path, M.encode({"schema": "openclaw.v108.npm-lock-bootstrap.v1", "home": str(home),
                "pipeline": str(pipeline), "runId": RID, "admissionSha256": M.digest(raw)}))
            request = pipeline / M.CANDIDATE / "source-request.json"; request.parent.mkdir(parents=True)
            request_raw = b'{"sourceSha":"synthetic-source-identity"}'; request.write_bytes(request_raw)
            env = {"PATH": "/usr/bin:/bin", "GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux",
                "GITHUB_WORKSPACE": str(workspace), "RUNNER_TEMP": str(temporary), "GITHUB_RUN_ID": RID,
                "GITHUB_RUN_ATTEMPT": "1", "GITHUB_REPOSITORY": M.REPOSITORY, "GITHUB_EVENT_NAME": "pull_request",
                "GITHUB_ACTOR": "fr-meyer", "NPM_LOCK_STARTED_EPOCH": str(NOW - 100)}
            calls = []
            class Driver:
                def clean_env(self, actual_home, parent):
                    self_parent = dict(parent)
                    self.assert_public = self_parent.get("GITHUB_RUN_ID")
                    return {"PATH": parent["PATH"], "HOME": str(actual_home)}
                def bootstrap_pnpm(self, actual_home, child_env, request):
                    calls.append((actual_home, child_env, request))
            fake = Driver()
            with patch.object(M.sys, "platform", "linux"), patch.dict(M.os.environ, env, clear=True), \
                 patch.object(M.time, "time", return_value=NOW), patch.object(M, "REQUEST_SHA", M.digest(request_raw)), \
                 patch.object(M, "code_binding") as code, patch.object(M, "clean_source") as clean, \
                 patch.object(M, "load_driver", return_value=fake):
                M.internal_bootstrap(context_path)
            self.assertEqual(fake.assert_public, RID)
            code.assert_called_once_with(pipeline, source, HEAD); clean.assert_called_once_with(source)
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0], (home, {"PATH": "/usr/bin:/bin", "HOME": str(home)},
                                        {"sourceSha": "synthetic-source-identity"}))

    def test_existing_failure_artifact_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); state = self.failure_state(root); state["output"].mkdir()
            original = state["output"] / "generation.json"; original.write_bytes(b"original")
            M.preserve_failure(state, M.Refusal("test.failed"), {})
            self.assertEqual(original.read_bytes(), b"original")

    def test_disarmed_local_derive_has_no_host_process_or_artifact_action(self):
        with patch.object(M.sys, "platform", "darwin"), patch.object(M, "git") as command, \
             patch.object(M, "load_driver") as driver, patch.object(M, "private_write") as write:
            with self.assertRaises(M.Refusal): M.derive({}, "0" * 64)
            command.assert_not_called(); driver.assert_not_called(); write.assert_not_called()

    def test_first_clock_accepts_full_job_before_writing_output(self):
        workflow = (HERE.parents[1] / ".github/workflows/future-v108-source-validation.yml").read_text()
        first = workflow.split("    steps:\n", 1)[1].split("      - name: Checkout exact reviewed pipeline", 1)[0]
        self.assertTrue(first.startswith("      - name: Observe the shared45-minute job clock before checkouts\n"))
        raw = first.split("        run: |\n", 1)[1]
        lines = [line[10:] for line in raw.splitlines()]
        self.assertEqual(lines[0], "/usr/bin/python3 -I -B - <<'PY'")
        self.assertEqual(lines[-1], "PY")
        self.assertNotIn("${{", raw)
        script = "\n".join(lines[1:-1]) + "\n"
        deadline = datetime(2026, 10, 30, 0, 3, 19, tzinfo=timezone.utc).timestamp()
        started = deadline - 45 * 60
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp).resolve() / "github-output"
            with patch.object(M.time, "time", return_value=started), \
                 patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}, clear=True):
                exec(compile(script, "<actual-workflow-first-clock>", "exec"), {})
            self.assertEqual(output.read_text(), "started_epoch=" + str(int(started)) + "\n")

    def test_first_clock_expiry_writes_nothing_before_checkouts(self):
        workflow = (HERE.parents[1] / ".github/workflows/future-v108-source-validation.yml").read_text()
        first = workflow.split("    steps:\n", 1)[1].split("      - name: Checkout exact reviewed pipeline", 1)[0]
        raw = first.split("        run: |\n", 1)[1]
        lines = [line[10:] for line in raw.splitlines()]
        self.assertEqual((lines[0], lines[-1]), ("/usr/bin/python3 -I -B - <<'PY'", "PY"))
        script = "\n".join(lines[1:-1]) + "\n"
        deadline = datetime(2026, 10, 30, 0, 3, 19, tzinfo=timezone.utc).timestamp()
        # A fractional overrun must refuse before flooring the stored epoch.
        started = deadline - 45 * 60 + 0.25
        for name in ("Checkout exact reviewed pipeline", "Checkout exact immutable sourceB"):
            block = workflow.split("      - name: " + name, 1)[1].split("      - name: ", 1)[0]
            self.assertNotIn("        if:", block)  # Default success() gate after first-step failure.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); output = root / "github-output"; checkouts = []
            with patch.object(M.time, "time", return_value=started), \
                 patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}, clear=True):
                with self.assertRaises(SystemExit):
                    exec(compile(script, "<actual-workflow-first-clock>", "exec"), {})
                    checkouts.append("would_start_after_success")
            self.assertFalse(output.exists())
            self.assertEqual(checkouts, [])
            self.assertEqual(list(root.iterdir()), [])

    def test_admission_token_never_enters_context_or_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); pipeline = root / "pipeline"; source = root / "source"; pipeline.mkdir(); source.mkdir()
            ep = root / "event.json"; ep.write_bytes(M.encode(event())); output = root / "github-output"; output.touch()
            env = {"GITHUB_EVENT_PATH": str(ep), "GITHUB_OUTPUT": str(output),
                   "GH_SOURCE_READ_TOKEN": "SYNTHETIC_READ_TOKEN", "NPM_LOCK_STARTED_EPOCH": str(NOW - 100)}
            def api(route, token, deadline):
                self.assertEqual(token, "SYNTHETIC_READ_TOKEN")
                if "/actions/workflows/" in route: return history()
                if route.endswith("/jobs?filter=all&per_page=100"): return jobs()
                if "/git/ref/" in route: return {"object": {"sha": M.SOURCE}}
                if route.endswith("/pulls/28"): return pr()
                return run()
            capture = io.StringIO()
            with patch.object(M, "exact_paths", return_value=(pipeline, source, root, RID)), \
                 patch.object(M, "code_binding"), patch.object(M, "clean_source"), \
                 patch.object(M.time, "time", return_value=NOW), contextlib.redirect_stdout(capture):
                M.admit(env, api)
            raw = (root / ("v108-npm-lock-admission-" + RID + ".json")).read_bytes()
            self.assertNotIn(b"SYNTHETIC_READ_TOKEN", raw)
            self.assertNotIn("SYNTHETIC_READ_TOKEN", capture.getvalue())
            self.assertIn(M.digest(raw), output.read_text())


if __name__ == "__main__":
    unittest.main()

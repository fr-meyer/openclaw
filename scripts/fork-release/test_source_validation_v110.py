"""Synthetic operator-boundary proof; never runs candidate code or network."""
from copy import deepcopy
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import bounded_run_contract_v109 as budget
import source_contract_v110 as policy
import source_validation_v108 as core
import source_validation_v110 as caller


def observation():
    return {"minutes": {"preparation": 0, "validation": 0, "incidental": 0},
        "executions": {"preparation": 0, "validation": 0}, "currentRunMinutes": 0, "currentRunArtifactBytes": 0,
        "currentRunIncluded": False, "stageRunRecords": 0,
        "source109NeededAttemptsUsed": 251, "artifactBytes": 783765}


def completed(code=0, settled=True, timeout=False):
    value = subprocess.CompletedProcess(["synthetic"], code)
    value.cleanup_settled, value.timed_out = settled, timeout
    return value


class StageBookingTests(unittest.TestCase):
    def test_other_stage_reservation_is_not_relabelled_spending(self):
        value = budget.book_stage_v110(observation(), {"role": "preparation", "maximumMinutes": 45})
        self.assertEqual(value["settledOriginalMinutes"], 2215)
        self.assertEqual(value["reservedOther109StageMinutes"], 3700)
        self.assertEqual(value["globalBookedMinutes"], 5960)
        self.assertEqual(value["fullReservationGlobalUpperBound"], 8315)
        self.assertTrue(value["otherReservationIsNotSpent"])

    def test_current_native_minutes_are_covered_without_refund_or_double_charge(self):
        row = observation()
        row.update(currentRunIncluded=True, currentRunMinutes=7, stageRunRecords=1)
        row["minutes"]["preparation"], row["executions"]["preparation"] = 7, 1
        value = budget.book_stage_v110(row, {"role": "preparation", "maximumMinutes": 45})
        self.assertEqual(value["observed110Minutes"]["preparation"], 7)
        self.assertEqual(value["projected110Minutes"]["preparation"], 45)
        self.assertEqual(value["projectedExecutions"]["preparation"], 1)

    def test_third_preparation_is_not_a_fresh_allowance(self):
        row = observation()
        row["executions"]["preparation"] = 2
        with self.assertRaisesRegex(budget.Refusal, "v110_execution_ceiling"):
            budget.book_stage_v110(row, {"role": "preparation", "maximumMinutes": 45})

    def test_actual_failed_debits_can_exhaust_pool_before_second_round(self):
        row = observation()
        row["minutes"]["preparation"] = 46
        row["executions"]["preparation"] = 1
        with self.assertRaisesRegex(budget.Refusal, "v110_stage_ceiling"):
            budget.book_stage_v110(row, {"role": "preparation", "maximumMinutes": 45})

    def test_original_attempts_and_artifacts_are_not_reset(self):
        for field, value, code in (("source109NeededAttemptsUsed", 1000, "original_attempt"),
                                    ("artifactBytes", 67108865, "artifact_ceiling")):
            with self.subTest(field=field):
                row = observation(); row[field] = value
                with self.assertRaisesRegex(budget.Refusal, code):
                    budget.book_stage_v110(row, {"role": "validation", "maximumMinutes": 1105})

    def test_wrong_role_cap_and_boolean_usage_refuse(self):
        with self.assertRaisesRegex(budget.Refusal, "role_scope"):
            budget.book_stage_v110(observation(), {"role": "validation", "maximumMinutes": 1075})
        row = observation(); row["minutes"]["incidental"] = False
        with self.assertRaisesRegex(budget.Refusal, "native_usage"):
            budget.book_stage_v110(row, {"role": "preparation", "maximumMinutes": 45})

    def test_preparation_reserves_both_bounded_artifacts_before_effect(self):
        row = observation(); row["artifactBytes"] = 67108864 - 4 * 1024 * 1024
        result = budget.book_stage_v110(row, {"role": "preparation", "maximumMinutes": 45})
        self.assertEqual(result["projectedArtifactBytes"], 67108864)
        self.assertEqual(result["currentArtifactReservedBytes"], 4 * 1024 * 1024)
        row["artifactBytes"] += 1
        with self.assertRaisesRegex(budget.Refusal, "artifact_reservation_ceiling"):
            budget.book_stage_v110(row, {"role": "preparation", "maximumMinutes": 45})

    def test_current_artifact_bytes_cover_existing_reservation_without_refund(self):
        row = observation()
        row.update(currentRunIncluded=True, stageRunRecords=1, currentRunArtifactBytes=1000,
            artifactBytes=67108864 - 65536 + 1000)
        row["executions"]["validation"] = 1
        result = budget.book_stage_v110(row, {"role": "validation", "maximumMinutes": 1105})
        self.assertEqual(result["projectedArtifactBytes"], 67108864)
        self.assertEqual(result["observedArtifactBytes"], row["artifactBytes"])
        self.assertEqual(result["currentArtifactReservedBytes"], 64536)
        row["artifactBytes"] += 1
        with self.assertRaisesRegex(budget.Refusal, "artifact_reservation_ceiling"):
            budget.book_stage_v110(row, {"role": "validation", "maximumMinutes": 1105})


class OwnedProcessTests(unittest.TestCase):
    def identity(self, campaign=policy.CAMPAIGN):
        return {"campaignId": campaign, "sourceSha": "a" * 40, "sourceTree": "b" * 40}

    def phase(self, campaign, absent=True):
        class Child:
            pid, returncode = 123456, 0
            def communicate(self, timeout):
                return None, None
        context = {"deadlineEpoch": 104, "profile": "synthetic", "operationIdentity": self.identity(campaign)}
        with patch.object(core.subprocess, "Popen", return_value=Child()), patch.object(core.time, "time", return_value=100), \
                patch.object(core, "summarize"), patch.object(core, "wait_owned_group_absent", return_value=absent) as wait, \
                patch.object(core, "settle_owned_timeout_group") as signal:
            result = core.phase_process(["never-executed"], Path("/synthetic"), {}, context, "synthetic", 0)
        signal.assert_not_called()
        return result, wait

    def test_honest_110_identity_and_109_identity_are_supported(self):
        self.assertEqual(core.operation_identity_for(operation_identity=self.identity())[2], policy.CAMPAIGN)
        self.assertEqual(core.operation_identity_for(operation_identity=self.identity(
            "future-v109-grouped-validation-20261030"))[2], "future-v109-grouped-validation-20261030")
        with self.assertRaises(core.release.Refusal):
            core.operation_identity_for(operation_identity=self.identity("arbitrary-campaign"))

    def test_110_normal_settlement_requires_positive_absence_within_remaining_time(self):
        result, wait = self.phase(policy.CAMPAIGN)
        wait.assert_called_once_with(123456, 4)
        self.assertTrue(result.cleanup_settled)
        caller.settled(result)

    def test_leftover_or_unknown_group_never_becomes_accepted_receipt(self):
        result, _ = self.phase(policy.CAMPAIGN, absent=False)
        self.assertFalse(result.cleanup_settled)
        with self.assertRaisesRegex(policy.Refusal, "not_successfully_settled"):
            caller.settled(result)
        with patch.object(core.os, "killpg", side_effect=PermissionError) as probe:
            self.assertFalse(core.wait_owned_group_absent(123456, 0))
        probe.assert_called_once_with(123456, 0)

    def test_existing_109_normal_behavior_is_unchanged(self):
        result, wait = self.phase("future-v109-grouped-validation-20261030")
        wait.assert_not_called()
        self.assertIsNone(result.cleanup_settled)

    def test_zero_exit_after_timeout_or_unknown_settlement_is_not_success(self):
        for value in (completed(timeout=True), completed(settled=None)):
            with self.assertRaisesRegex(policy.Refusal, "not_successfully_settled"):
                caller.settled(value)


class CallerBoundaryTests(unittest.TestCase):
    def test_nonhosted_cli_performs_no_api_or_process_action(self):
        with patch.object(caller.native, "API") as api, patch.object(caller, "git_read") as git, \
                patch.object(core, "phase_process") as run, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(caller.main(["admit"], env={}), 1)
        api.assert_not_called(); git.assert_not_called(); run.assert_not_called()

    def test_final_success_needs_every_fresh_profile_not_needs_flags_alone(self):
        request = {"phase": "validation", "source": {"sourceSha": "a" * 40, "sourceTree": "b" * 40}, "generation": 1}
        env = {"GITHUB_RUN_ID": "123"}
        jobs = [{"name": name, "status": "completed", "conclusion": "success"}
            for name in caller.CURRENT_JOBS["validation"]]
        record = caller.result_record(request, b"{}", env, "c" * 40, "success", "success", jobs)
        self.assertEqual(record["status"], "passed")
        self.assertFalse(record["qualified"])
        for changed in (jobs[:-1], [dict(j, conclusion="skipped") if j["name"] == "source (sqlite)" else j for j in jobs]):
            with self.assertRaisesRegex(policy.Refusal, "all_fresh_profiles"):
                caller.result_record(request, b"{}", env, "c" * 40, "success", "success", changed)
        self.assertEqual(caller.result_record(request, b"{}", env, "c" * 40, "failure", "skipped")["status"], "failed")

    def test_late_worker_refuses_instead_of_shortening_approved_job_budget(self):
        start = int(policy.utc(policy.PACKAGE_NOT_BEFORE).timestamp()) + 60
        request = {"phase": "validation"}
        env = {"V110_JOB_STARTED_EPOCH": str(start)}
        bindings = {"ownerWindow": {"expiresAt": caller.now_utc(start + 80 * 60)}}
        with patch.object(caller.time, "time", return_value=start + 1):
            with self.assertRaisesRegex(policy.Refusal, "full_job_window_required"):
                caller.deadline(env, bindings, request, "sqlite")

    def test_finite_fetch_is_fixed_single_acquisition_per_root_group(self):
        bindings = {"pipeline": {"codeCommit": "c" * 40}, "generations": [
            {"material": {"sourceSha": "a" * 40}, "validation": None}]}
        request = {"source": {"sourceSha": "a" * 40}}
        with tempfile.TemporaryDirectory() as temp:
            env = {"GITHUB_SHA": "d" * 40, "RUNNER_TEMP": temp, "PATH": "/usr/bin:/bin"}
            def read(_root, *args, **_kwargs):
                return (policy.UPSTREAM["commit"] + "\n").encode() if args[0] == "rev-parse" else (
                    b"tag\n" if args[-1] == policy.UPSTREAM["tagObject"] else b"commit\n")
            with patch.object(core, "phase_process", return_value=completed()) as run, \
                    patch.object(caller, "git_read", side_effect=read):
                caller.finite_fetch(Path("/pipeline"), Path("/source"), bindings, request, env,
                    {"deadlineEpoch": 123}, "e" * 40)
            self.assertEqual(run.call_count, 2)
            for call in run.call_args_list:
                argv = call.args[0]
                self.assertIn("https://github.com/fr-meyer/openclaw.git", argv)
                self.assertIn("--no-write-fetch-head", argv)
                self.assertNotIn("--all", argv)
                self.assertNotIn("GH_TOKEN", call.args[2])

    def test_fetch_failure_has_no_alternate_route_or_retry(self):
        bindings = {"pipeline": {"codeCommit": "c" * 40}, "generations": [
            {"material": {"sourceSha": "a" * 40}, "validation": None}]}
        with tempfile.TemporaryDirectory() as temp:
            env = {"GITHUB_SHA": "d" * 40, "RUNNER_TEMP": temp, "PATH": "/usr/bin:/bin"}
            with patch.object(core, "phase_process", return_value=completed(1)) as run:
                with self.assertRaisesRegex(policy.Refusal, "not_successfully_settled"):
                    caller.finite_fetch(Path("/pipeline"), Path("/source"), bindings,
                        {"source": {"sourceSha": "a" * 40}}, env, {"deadlineEpoch": 123}, "e" * 40)
            self.assertEqual(run.call_count, 1)

    def test_annotated_tag_must_resolve_to_the_reviewed_commit(self):
        bindings = {"pipeline": {"codeCommit": "c" * 40}, "generations": [
            {"material": {"sourceSha": "a" * 40}, "validation": None}]}
        def read(_root, *args, **_kwargs):
            return b"f" * 40 + b"\n" if args[0] == "rev-parse" else (
                b"tag\n" if args[-1] == policy.UPSTREAM["tagObject"] else b"commit\n")
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(core, "phase_process", return_value=completed()), \
                    patch.object(caller, "git_read", side_effect=read):
                with self.assertRaisesRegex(policy.Refusal, "upstream_annotated_target"):
                    caller.finite_fetch(Path("/pipeline"), Path("/source"), bindings, {},
                        {"GITHUB_SHA": "d" * 40, "RUNNER_TEMP": temporary, "PATH": "/usr/bin:/bin"},
                        {"deadlineEpoch": 123}, "e" * 40)

    def test_bootstrap_uses_same_owned_session_and_secretless_environment(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp).resolve(strict=True); package = home / "toolchain/node_modules/pnpm"
            package.mkdir(parents=True); binary = package / "pnpm"; binary.write_bytes(b"synthetic")
            (home / "toolchain/node_modules/.bin").mkdir()
            (home / "toolchain/node_modules/.bin/pnpm").symlink_to(binary)
            env = core.clean_env(home, {"PATH": "/usr/bin:/bin", "GH_TOKEN": "credential-canary"})
            context = {"operationIdentity": {"campaignId": policy.CAMPAIGN, "sourceSha": "a" * 40, "sourceTree": "b" * 40}}
            with patch.object(core, "phase_process", return_value=completed()) as run:
                self.assertEqual(caller.bootstrap(home, env, Path("/reviewed-pipeline"), context, "c" * 64), binary)
            call = run.call_args
            self.assertEqual(call.args[0][1:3], ["-I", "-c"])
            self.assertIn("source_validation_v108", call.args[0][3])
            self.assertNotIn("credential-canary", str(call.args))
            self.assertTrue(env["PATH"].startswith(str(home / "toolchain/node_modules/.bin")))


class BootstrapImportTests(unittest.TestCase):
    def fixture(self, root):
        pipeline, home = root / "pipeline", root / "private-home"
        home.mkdir(); folder = pipeline / "scripts/fork-release"; folder.mkdir(parents=True)
        maintained = Path(__file__).parent
        names = ("verified_imports_v110.py", "source_validation_v108.py", "preflight.py", "release.py",
            "composite_closed_usage.py")
        # Import the complete maintained operator core. Replace only its final
        # bootstrap call in this synthetic copy so no npm/package action exists.
        synthetic_override = b'''\ndef bootstrap_pnpm(home, env, operation_identity=None):
    import argparse, json
    assert 'GH_TOKEN' not in env
    (home / 'observed.json').write_text(json.dumps({'coreFile': __file__,
        'argparseFile': argparse.__file__, 'identity': operation_identity}))
'''
        files = {}
        for name in names:
            raw = (maintained / name).read_bytes()
            if name == "source_validation_v108.py":
                raw += synthetic_override
            path = "scripts/fork-release/" + name
            (pipeline / path).write_bytes(raw)
            files[path] = {"sha256": policy.digest(raw), "bytes": len(raw)}
        # This unlisted sibling must never be imported by either the child or
        # any captured maintained operator module.
        (folder / "argparse.py").write_bytes(b"raise RuntimeError('unlisted sibling executed')\n")
        manifest = policy.encode({"schema": "openclaw.v110.code-manifest.v1", "codeFiles": files})
        target = pipeline / caller.CODE_MANIFEST; target.parent.mkdir(parents=True); target.write_bytes(manifest)
        identity = {"campaignId": policy.CAMPAIGN, "sourceSha": "a" * 40, "sourceTree": "b" * 40}
        return pipeline, home, manifest, identity

    def invoke(self, pipeline, home, manifest, identity):
        return subprocess.run([sys.executable, "-I", "-c", caller._BOOTSTRAP_CHILD,
            str(pipeline), str(home), json.dumps(identity), policy.digest(manifest)],
            env=core.clean_env(home, {"PATH": "/usr/bin:/bin"}), cwd=home,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)

    def test_actual_core_import_uses_captured_helpers_and_ignores_unlisted_argparse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            pipeline, home, manifest, identity = self.fixture(root)
            result = self.invoke(pipeline, home, manifest, identity)
            self.assertEqual(result.returncode, 0, result.stderr)
            value = json.loads((home / "observed.json").read_bytes())
            self.assertEqual(value["coreFile"], str(pipeline / "scripts/fork-release/source_validation_v108.py"))
            self.assertFalse(value["argparseFile"].startswith(str(pipeline)))
            self.assertEqual(value["identity"], identity)

    def test_changed_captured_core_refuses_before_synthetic_bootstrap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            pipeline, home, manifest, identity = self.fixture(root)
            (pipeline / "scripts/fork-release/source_validation_v108.py").write_bytes(b"raise RuntimeError('drift')")
            result = self.invoke(pipeline, home, manifest, identity)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"v110.bootstrap_code_file_digest", result.stderr)
            self.assertFalse((home / "observed.json").exists())


class TrackedChangesTests(unittest.TestCase):
    def read(self, complete=b"", staged=b""):
        def reader(*args):
            if args == ("diff", "--name-only", "HEAD", "--"):
                return complete
            if args == ("diff", "--cached", "--name-only", "HEAD", "--"):
                return staged
            raise AssertionError(args)
        return reader

    def test_staged_arbitrary_and_staged_lock_refuse_even_if_worktree_reverts(self):
        for complete, staged, allow in ((b"arbitrary.ts\n", b"arbitrary.ts\n", False),
                (b"pnpm-lock.yaml\n", b"pnpm-lock.yaml\n", True),
                (b"", b"arbitrary.ts\n", True)):
            with self.subTest(complete=complete, staged=staged):
                with self.assertRaisesRegex(policy.Refusal, "source_index_delta"):
                    caller.tracked_changes(self.read(complete, staged), changed_lock=allow)

    def test_only_unstaged_lock_is_allowed_during_derivation(self):
        self.assertEqual(caller.tracked_changes(self.read(b"pnpm-lock.yaml\n"), changed_lock=True), ["pnpm-lock.yaml"])
        for complete in (b"pnpm-lock.yaml\n", b"arbitrary.ts\n"):
            with self.assertRaisesRegex(policy.Refusal, "source_tracked_delta"):
                caller.tracked_changes(self.read(complete))


class WorkflowBindingTests(unittest.TestCase):
    def fixture(self, root):
        import source_validation_selection_v110 as selection
        entry = "scripts/fork-release/source_validation_v110.py"
        template = selection.LOCK_PREPARATION_TEMPLATE
        fixture_raw = (Path(__file__).parent.parent.parent / template).read_bytes()
        files = {entry: {"sha256": "a" * 64, "bytes": 100},
            template: {"sha256": policy.digest(fixture_raw), "bytes": len(fixture_raw)}}
        manifest = policy.encode({"schema": "openclaw.v110.code-manifest.v1", "codeFiles": files})
        bindings = {"pipeline": {"codeFiles": files}, "draftPr": {"number": 71}}
        request = {"phase": "lock-preparation", "source": {"sourceSha": "b" * 40}}
        env = {"V110_ARMED": "true", "V110_BOUND_PR": "71", "V110_SOURCE_SHA": "b" * 40,
            "V110_ENTRY_SHA256": "a" * 64, "V110_CODE_MANIFEST_SHA256": policy.digest(manifest),
            "V110_EFFECTIVE_AT": policy.APPROVAL_RECORDED_AT, "V110_EXPIRES_AT": policy.EXPIRES_AT}
        for path, raw in ((template, fixture_raw), (caller.CODE_MANIFEST, manifest),
                (policy.WORKFLOW, selection.render_workflow(fixture_raw, pr_number=71,
                    source_sha="b" * 40, entry_sha256="a" * 64,
                    code_manifest_sha256=policy.digest(manifest), effective_at=policy.APPROVAL_RECORDED_AT))):
            target = root / path; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)
        return bindings, request, env

    def test_complete_rendered_workflow_and_frontloader_map_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            caller.workflow_role_binding(root, *self.fixture(root))

    def test_changed_workflow_and_wrong_role_fail_before_effect(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True); bindings, request, env = self.fixture(root)
            target = root / policy.WORKFLOW; target.write_bytes(target.read_bytes() + b"# drift\n")
            with self.assertRaisesRegex(policy.Refusal, "reviewed_role_workflow"):
                caller.workflow_role_binding(root, bindings, request, env)

    def test_frontloader_map_and_fixed_env_cannot_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True); bindings, request, env = self.fixture(root)
            env["V110_ENTRY_SHA256"] = "f" * 64
            with self.assertRaisesRegex(policy.Refusal, "same_workflow_env"):
                caller.workflow_role_binding(root, bindings, request, env)
            env["V110_ENTRY_SHA256"] = "a" * 64
            env["V110_CODE_MANIFEST_SHA256"] = "f" * 64
            with self.assertRaisesRegex(policy.Refusal, "same_preimport_code_map"):
                caller.workflow_role_binding(root, bindings, request, env)


class NativeAccountingTests(unittest.TestCase):
    def fixtures(self):
        clock = policy.utc(policy.PACKAGE_NOT_BEFORE).timestamp() + 120
        job = {"id": 1001, "name": "admission", "run_attempt": 1, "status": "in_progress", "conclusion": None,
            "runner_id": 12, "runner_name": "Hosted", "runner_group_name": "GitHub Actions", "labels": ["ubuntu-24.04"],
            "started_at": caller.now_utc(clock - 30), "completed_at": None}
        current = {"id": 11, "path": policy.WORKFLOW, "name": policy.CAMPAIGN, "head_sha": "a" * 40}
        bindings = {"ownerWindow": {"source109Released": True, "source109NeededAttemptsUsed": 251,
            "source109BookedArtifactBytes": 783765, "source109LatestLedgerSha256": "b" * 64}}
        return clock, job, current, bindings

    def invoke(self, old, old_artifacts, bindings=None):
        clock, job, current, default = self.fixtures()
        bindings = default if bindings is None else bindings
        def runs(_api, branch, maximum=749):
            return [current] if branch == policy.PIPELINE_BRANCH else old if branch == "task/v107-source-binding" else []
        with patch.object(caller, "_runs", side_effect=runs), \
                patch.object(caller.native, "jobs_for", return_value=[job]), \
                patch.object(caller.native, "artifacts_for", side_effect=lambda _api, r: old_artifacts if r["id"] != 11 else []):
            return caller.collect_stage(object(), bindings, {"phase": "validation"}, {"GITHUB_RUN_ID": "11"}, clock)

    def test_positive_release_is_required_even_when_no_109_jobs_are_visible(self):
        *_, bindings = self.fixtures(); bindings["ownerWindow"]["source109Released"] = False
        with self.assertRaisesRegex(policy.Refusal, "source_window_required"):
            self.invoke([], [], bindings)

    def test_current_run_is_measured_and_other_stage_full_reservation_is_preserved(self):
        value = self.invoke([], [])
        self.assertEqual(value["observed110Minutes"]["validation"], 1)
        self.assertEqual(value["projected110Minutes"]["validation"], 1105)
        self.assertEqual(value["globalBookedMinutes"], 7020)

    def test_old_active_or_understated_usage_refuses_without_synthesizing_release(self):
        with self.assertRaisesRegex(policy.Refusal, "source109_still_active"):
            self.invoke([{"id": 22, "status": "in_progress"}], [])
        old = [{"id": 22, "status": "completed", "conclusion": "failure"}]
        *_, bindings = self.fixtures(); bindings["ownerWindow"]["source109NeededAttemptsUsed"] = 252
        with self.assertRaisesRegex(policy.Refusal, "booking_understated"):
            self.invoke(old, [{"size_in_bytes": 1000, "expired": True}], bindings)
        bindings["ownerWindow"]["source109BookedArtifactBytes"] += 1000
        value = self.invoke(old, [{"size_in_bytes": 1000, "expired": True}], bindings)
        self.assertEqual(value["observed110Minutes"]["validation"], 1)

    def test_missing_current_run_is_not_normalized_to_zero(self):
        clock, _job, _current, bindings = self.fixtures()
        with patch.object(caller, "_runs", return_value=[]):
            with self.assertRaisesRegex(policy.Refusal, "current_native_run_missing"):
                caller.collect_stage(object(), bindings, {"phase": "validation"}, {"GITHUB_RUN_ID": "11"}, clock)

    def test_current_run_cannot_change_role_or_exceed_three_source_jobs(self):
        clock, job, current, bindings = self.fixtures()
        def runs(_api, branch, maximum=749):
            return [current] if branch == policy.PIPELINE_BRANCH else []
        for jobs in ([dict(job, name="lock-preparation")],
                [job, *[dict(job, id=2000 + n, name="source (" + profile + ")")
                    for n, profile in enumerate(policy.PROFILES[:4])]]):
            with self.subTest(names=[j["name"] for j in jobs]):
                with patch.object(caller, "_runs", side_effect=runs), \
                        patch.object(caller.native, "jobs_for", return_value=jobs), \
                        patch.object(caller.native, "artifacts_for", return_value=[]):
                    with self.assertRaisesRegex(policy.Refusal, "current_role_or_parallelism"):
                        caller.collect_stage(object(), bindings, {"phase": "validation"}, {"GITHUB_RUN_ID": "11"}, clock)


class RefusedLockCustodyTests(unittest.TestCase):
    def test_generated_bytes_are_retained_before_security_refusal(self):
        import lockfile_policy_v110 as lock_policy
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True); source = root / "source"; source.mkdir()
            (source / "pnpm-lock.yaml").write_bytes(b"unqualified-original")
            pipeline = root / "pipeline"; pipeline.mkdir()
            request = {"phase": "lock-preparation", "source": {"sourceSha": "a" * 40, "sourceTree": "b" * 40,
                "fileSha256": {policy.LEDGER: "c" * 64}}}
            env = {"RUNNER_TEMP": str(root), "PATH": "/usr/bin:/bin", "GITHUB_RUN_ID": "55",
                "V110_CODE_MANIFEST_SHA256": "c" * 64}
            def read(*args):
                if args == ("diff", "--name-only", "HEAD", "--"): return b"pnpm-lock.yaml\n"
                if args == ("diff", "--cached", "--name-only", "HEAD", "--"): return b""
                if args[0] == "ls-files": return b""
                if args == ("diff", "--no-ext-diff", "--no-textconv", "--binary", "HEAD", "--", "pnpm-lock.yaml"):
                    return b"synthetic lock diff"
                raise AssertionError(args)
            def produce(*args):
                (source / "pnpm-lock.yaml").write_bytes(b"refused-generated-lock")
                return completed()
            with patch.object(caller, "source_binding", return_value=(read, {})), \
                    patch.object(caller, "source_inputs", return_value={"package.json": b"{}", "pnpm-workspace.yaml": b"x"}), \
                    patch.object(lock_policy, "validate_source_inputs"), patch.object(lock_policy, "PublicRegistry"), \
                    patch.object(lock_policy, "verify_bootstrap_age"), \
                    patch.object(lock_policy, "verify_generated_lock", side_effect=ValueError("security-refused")), \
                    patch.object(caller, "fresh_guard"), patch.object(core, "resource_check"), \
                    patch.object(caller, "bootstrap"), patch.object(core, "phase_process", side_effect=produce):
                with self.assertRaisesRegex(ValueError, "security-refused"):
                    caller.derive(pipeline, source, {}, request, b"{}", {}, env, {"deadlineEpoch": 9999999999}, "d" * 40)
            diagnostic = root / "v110-lock-diagnostic"
            self.assertEqual((diagnostic / "pnpm-lock.yaml").read_bytes(), b"refused-generated-lock")
            self.assertEqual((diagnostic / "lock.diff").read_bytes(), b"synthetic lock diff")
            self.assertEqual((diagnostic / "lock-diagnostic.json").stat().st_mode & 0o777, 0o600)
            self.assertFalse((root / "v110-lock-artifact").exists())


if __name__ == "__main__":
    unittest.main()

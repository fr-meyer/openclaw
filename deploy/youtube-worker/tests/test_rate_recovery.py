"""Bounded GCP recovery owner flow; synthetic clocks, no provider or node RPC."""
import copy
import contextlib
import datetime as dt
import io
import json
import unittest

import test_coordinator_recovery as fixture

wc, sv, gp = fixture.wc, fixture.sv, fixture.gp
CANARY, LEASE, IDS, DIGEST = fixture.CANARY, fixture.LEASE, fixture.IDS, fixture.DIGEST
UTC = dt.timezone.utc
OCCURRENCE = dt.datetime(2026, 10, 10, 0, 0, tzinfo=UTC)
FIRST_APPROVAL = "human-approval-fixture-first"
SECOND_APPROVAL = "human-approval-fixture-second"


def timestamp(value):
    return value.isoformat().replace("+00:00", "Z")


def instant(value):
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


class RateRecoveryTests(unittest.TestCase):
    # Reuse only fixture helpers. Inheriting its class or importing the class
    # into this module would make unittest rerun its unrelated recovery tests.
    patch = fixture.CoordinatorRecoveryTests.patch
    write = fixture.CoordinatorRecoveryTests.write

    def setUp(self):
        fixture.CoordinatorRecoveryTests.setUp(self)
        # The fixture has synthetic paths/assets. Managed release verification
        # is exercised against real candidate inventories in deployment tests.
        self.sources = self.patch(wc, "_verify_recovery_sources", return_value=None)
        self.remote["status"].update({
            "state": "waiting_network_cooldown",
            "updated_at": timestamp(OCCURRENCE),
            "current_video_id": IDS[1],
            "circuit_open": True,
            "circuit_reason": "rate_limited",
            "counts": {"archived": 1, "waiting_network_cooldown": 1, "pending": 2},
            "items": {
                video: {
                    "video_id": video, "url": gp.canonical_url(video),
                    "state": "archived" if i == 0 else "waiting_network_cooldown" if i == 1 else "pending",
                    "attempts": 1 if i < 2 else 0,
                    "failure_class": "rate_limited" if i == 1 else None,
                }
                for i, video in enumerate(IDS)
            },
        })
        folder = self.archive / IDS[0]
        folder.mkdir()
        (folder / "report.md").write_text("previously archived captions\n")
        (folder / "manifest.json").write_text(json.dumps({"video_id": IDS[0], "files": ["report.md", "manifest.json"]}))

    def invoke_adapter(self, action, **kwargs):
        self.calls.append(action)
        result = copy.deepcopy(self.remote)
        if action == "Resume":
            self.assertEqual(kwargs["checkpoint_sha256"], self.remote["statusSha256"])
            result["workerAlive"] = True
            result["status"]["state"] = "running"
        return wc._normalise_probe(result) if action == "Probe" else result

    def arm(self, *, at=OCCURRENCE, approval=FIRST_APPROVAL, retry_after_at=None):
        return wc.arm_rate_recovery(
            CANARY, expected_checkpoint_sha256=self.remote["statusSha256"],
            approval_reference=approval, retry_after_at=retry_after_at, now=at,
        )

    def continue_at(self, at):
        return wc.continue_rate_recovery(CANARY, now=at)

    def request(self):
        return wc.read_json(self.root / "resume-requests" / (self.remote["statusSha256"] + ".json"))

    def protected_bytes(self):
        paths = [self.store.leases_dir / (LEASE + ".json"), self.root / "chunks/0001.tsv"]
        paths.extend(sorted(self.store.items_dir.glob("*.json")))
        paths.extend(sorted((self.archive / IDS[0]).iterdir()))
        return {str(path): path.read_bytes() for path in paths}

    def assert_no_resume(self):
        self.assertNotIn("Resume", self.calls)

    def new_occurrence(self, *, at, digest="d" * 64, video=IDS[1], attempts=2):
        self.remote["statusSha256"] = digest
        self.remote["workerAlive"] = False
        self.remote["status"].update(updated_at=timestamp(at), current_video_id=video)
        for key, item in self.remote["status"]["items"].items():
            if key != IDS[0]:
                item.update(state="waiting_network_cooldown" if key == video else "pending", failure_class="rate_limited" if key == video else None)
        self.remote["status"]["items"][video]["attempts"] = attempts
        manifest = wc.read_json(self.root / "manifest.json")
        manifest["state"] = "blocked"
        self.write(self.root / "manifest.json", manifest)

    def supervisor_fixture(self):
        self.patch(sv, "WC", wc)
        self.patch(sv, "POOL_ROOT", self.pool)
        self.patch(sv, "LOCK_PATH", self.pool / "locks/rate-supervisor.lock")
        self.patch(sv, "STATE_PATH", self.pool / "rate-supervisor.json")
        self.patch(sv, "active_runs", side_effect=lambda: [(CANARY, wc.read_json(self.root / "manifest.json"))])
        self.patch(sv, "validate_cutover", return_value={})
        self.patch(wc, "validate_host", return_value={"state": "passed"})

    def test_unarmed_elapsed_wait_never_dispatches(self):
        before = self.protected_bytes()
        self.assertEqual(self.continue_at(OCCURRENCE + dt.timedelta(days=3))["state"], "recovery_unarmed")
        self.assert_no_resume()
        self.assertFalse((self.root / "resume-requests").exists())
        self.assertEqual(self.protected_bytes(), before)

    def test_first_due_is_four_hours_from_occurrence_and_dispatches_once(self):
        self.assertEqual(self.arm(at=OCCURRENCE + dt.timedelta(hours=1))["state"], "recovery_armed")
        request = self.request()
        self.assertEqual(request["schema"], "openclaw.youtube.windows-resume.v2")
        self.assertEqual(request["policy_version"], "gcp-rate-recovery-v1")
        self.assertEqual(request["recovery_ordinal"], 1)
        self.assertEqual(request["state"], "armed")
        self.assertEqual(instant(request["due_at"]), OCCURRENCE + dt.timedelta(hours=4))
        before = self.protected_bytes()
        self.assertEqual(self.continue_at(OCCURRENCE + dt.timedelta(hours=4, microseconds=-1))["state"], "recovery_waiting")
        self.assert_no_resume()
        self.continue_at(OCCURRENCE + dt.timedelta(hours=4))
        self.continue_at(OCCURRENCE + dt.timedelta(hours=4, minutes=5))
        self.assertEqual(self.calls.count("Resume"), 1)
        self.assertEqual(self.request()["state"], "acknowledged")
        self.assertEqual(self.protected_bytes(), before)
        self.assertEqual(self.remote["status"]["items"][IDS[0]]["attempts"], 1)
        self.assertEqual(self.remote["status"]["items"][IDS[1]]["attempts"], 1)

    def test_rearming_same_checkpoint_does_not_extend_or_replace_grant(self):
        self.arm()
        original = self.request()
        self.arm(at=OCCURRENCE + dt.timedelta(hours=1))
        self.assertEqual(self.request(), original)
        self.assert_no_resume()

    def test_expiry_is_absolute_and_polling_cannot_renew_it(self):
        self.arm()
        before = self.protected_bytes()
        self.assertEqual(self.continue_at(OCCURRENCE + dt.timedelta(hours=24))["state"], "recovery_expired")
        expired = self.request()
        self.assertEqual(expired["state"], "expired")
        self.continue_at(OCCURRENCE + dt.timedelta(hours=25))
        self.assertEqual(self.request()["grant_expires_at"], expired["grant_expires_at"])
        self.assert_no_resume()
        self.assertEqual(self.protected_bytes(), before)

    def test_retry_after_never_shortens_the_policy_wait(self):
        self.arm(retry_after_at=timestamp(OCCURRENCE + dt.timedelta(hours=2)))
        self.assertEqual(instant(self.request()["due_at"]), OCCURRENCE + dt.timedelta(hours=4))
        self.assert_no_resume()

    def test_retry_after_later_than_backoff_is_respected(self):
        self.arm(retry_after_at=timestamp(OCCURRENCE + dt.timedelta(hours=6)))
        self.assertEqual(instant(self.request()["due_at"]), OCCURRENCE + dt.timedelta(hours=6))
        self.continue_at(OCCURRENCE + dt.timedelta(hours=5))
        self.assert_no_resume()
        self.continue_at(OCCURRENCE + dt.timedelta(hours=6))
        self.assertEqual(self.calls.count("Resume"), 1)

    def test_retry_after_beyond_horizon_never_gets_clamped_to_dispatch(self):
        with self.assertRaises(gp.PoolError):
            self.arm(retry_after_at=timestamp(OCCURRENCE + dt.timedelta(hours=25)))
        self.continue_at(OCCURRENCE + dt.timedelta(hours=23))
        self.assertIsNone(self.request())
        self.assert_no_resume()

    def test_due_at_grant_expiry_is_a_hold(self):
        with self.assertRaises(gp.PoolError):
            self.arm(retry_after_at=timestamp(OCCURRENCE + dt.timedelta(hours=24)))
        self.continue_at(OCCURRENCE + dt.timedelta(hours=24))
        self.assert_no_resume()
        self.assertIsNone(self.request())

    def test_readiness_failures_before_intent_do_not_consume_a_slot(self):
        self.arm()
        original = self.request()
        self.remote["workerLockFree"] = False
        self.assertEqual(self.continue_at(OCCURRENCE + dt.timedelta(hours=4))["state"], "recovery_waiting")
        self.assert_no_resume()
        self.assertEqual(self.request(), original)
        self.remote["workerLockFree"] = True
        self.continue_at(OCCURRENCE + dt.timedelta(hours=4, minutes=5))
        self.assertEqual(self.calls.count("Resume"), 1)

    def test_resume_rpc_failure_is_uncertain_and_restart_does_not_replay(self):
        self.arm()
        invoke = self.invoke_adapter
        def lost(action, **kwargs):
            if action == "Resume":
                self.calls.append(action)
                self.assertEqual(self.request()["state"], "intent")
                raise wc.YC.NodeUnavailable("fixture-node", "synthetic lost reply")
            return invoke(action, **kwargs)
        self.adapter.side_effect = lost
        try:
            self.continue_at(OCCURRENCE + dt.timedelta(hours=4))
        except gp.PoolError:
            pass
        self.assertEqual(self.request()["state"], "uncertain")
        self.adapter.side_effect = invoke
        self.continue_at(OCCURRENCE + dt.timedelta(hours=5))
        self.assertEqual(self.calls.count("Resume"), 1)

    def test_durable_intent_without_reply_also_cannot_be_replayed(self):
        self.arm()
        request = self.request()
        request["state"] = "intent"
        request["dispatched_at"] = timestamp(OCCURRENCE + dt.timedelta(hours=4))
        self.write(self.root / "resume-requests" / (DIGEST + ".json"), request)
        self.continue_at(OCCURRENCE + dt.timedelta(hours=5))
        self.assert_no_resume()

    def test_second_recovery_requires_distinct_approval_and_new_occurrence(self):
        self.arm()
        self.continue_at(OCCURRENCE + dt.timedelta(hours=4))
        self.new_occurrence(at=OCCURRENCE + dt.timedelta(hours=5))
        with self.assertRaises(gp.PoolError):
            self.arm(at=OCCURRENCE + dt.timedelta(hours=5), approval=FIRST_APPROVAL)
        self.arm(at=OCCURRENCE + dt.timedelta(hours=5), approval=SECOND_APPROVAL)
        self.assertEqual(self.request()["recovery_ordinal"], 2)
        self.assertEqual(instant(self.request()["due_at"]), OCCURRENCE + dt.timedelta(hours=13))
        self.continue_at(OCCURRENCE + dt.timedelta(hours=12))
        self.assertEqual(self.calls.count("Resume"), 1)
        self.continue_at(OCCURRENCE + dt.timedelta(hours=13))
        self.assertEqual(self.calls.count("Resume"), 2)

    def test_changed_checkpoint_is_not_proof_of_another_429(self):
        self.arm()
        self.continue_at(OCCURRENCE + dt.timedelta(hours=4))
        self.remote["statusSha256"] = "d" * 64
        with self.assertRaises(gp.PoolError):
            self.arm(at=OCCURRENCE + dt.timedelta(hours=5), approval=SECOND_APPROVAL)
        self.assertEqual(self.calls.count("Resume"), 1)

    def test_changing_failed_video_does_not_refill_two_dispatch_budget(self):
        self.arm()
        self.continue_at(OCCURRENCE + dt.timedelta(hours=4))
        self.new_occurrence(at=OCCURRENCE + dt.timedelta(hours=5), video=IDS[2], attempts=1)
        self.arm(at=OCCURRENCE + dt.timedelta(hours=5), approval=SECOND_APPROVAL)
        self.continue_at(OCCURRENCE + dt.timedelta(hours=13))
        self.new_occurrence(at=OCCURRENCE + dt.timedelta(hours=14), digest="e" * 64, video=IDS[3], attempts=1)
        with self.assertRaises(gp.PoolError):
            self.arm(at=OCCURRENCE + dt.timedelta(hours=14), approval="human-approval-fixture-third")
        self.assertEqual(self.calls.count("Resume"), 2)

    def test_legacy_v1_intents_count_toward_run_budget_without_mutation(self):
        binding = {key: self.manifest.get(key) for key in ("canary_id", "lease_id", "binding_sha256", "worker_sha256", "adapter_sha256", "urls_sha256")}
        paths = []
        for digest, state in [("a" * 64, "uncertain"), ("b" * 64, "acknowledged")]:
            path = self.root / "resume-requests" / (digest + ".json")
            self.write(path, {"schema": "openclaw.youtube.windows-resume.v1", "binding": binding, "checkpoint_sha256": digest, "state": state, "created_at": timestamp(OCCURRENCE - dt.timedelta(hours=1))})
            paths.append(path)
        before = {str(path): path.read_bytes() for path in paths}
        with self.assertRaises(gp.PoolError):
            self.arm()
        self.assertEqual(before, {str(path): path.read_bytes() for path in paths})
        self.assert_no_resume()

    def test_exhausted_rate_item_does_not_skip_ahead_to_pending_items(self):
        self.remote["status"]["items"][IDS[1]]["attempts"] = 3
        before = self.protected_bytes()
        with self.assertRaises(gp.PoolError):
            self.arm()
        self.assert_no_resume()
        self.assertEqual(self.protected_bytes(), before)
        self.assertEqual(self.remote["status"]["items"][IDS[2]]["attempts"], 0)

    def test_non_rate_circuits_cannot_arm_rate_timers(self):
        for reason, state in [("auth_required", "blocked_auth_required"), ("bot_check", "blocked_bot_check"), ("configuration", "blocked_configuration"), ("worker_session_interrupted", "blocked_interrupted"), ("unknown", "blocked_error")]:
            with self.subTest(reason=reason):
                self.remote["status"].update(state=state, circuit_reason=reason)
                self.remote["status"]["items"][IDS[1]].update(state=state, failure_class=reason)
                with self.assertRaises(gp.PoolError):
                    self.arm()
        self.assert_no_resume()

    def test_explicit_resume_has_no_rate_policy_bypass(self):
        with self.assertRaises(gp.PoolError):
            wc.resume_canary(CANARY, expected_checkpoint_sha256=DIGEST)
        self.assert_no_resume()

    def test_future_invalid_or_missing_occurrence_refuses_arm(self):
        for value in [timestamp(OCCURRENCE + dt.timedelta(seconds=1)), "not-a-timestamp", None]:
            with self.subTest(value=value):
                self.remote["status"]["updated_at"] = value
                with self.assertRaises(gp.PoolError):
                    self.arm()
        self.assert_no_resume()

    def test_missing_or_corrupt_attempt_map_refuses_arm(self):
        original = copy.deepcopy(self.remote["status"]["items"])
        cases = [
            {video: item for video, item in original.items() if video != IDS[2]},
            {**original, IDS[1]: {**original[IDS[1]], "attempts": True}},
            {**original, IDS[1]: {**original[IDS[1]], "attempts": "1"}},
            {**original, IDS[1]: {**original[IDS[1]], "attempts": -1}},
            {**original, IDS[1]: {**original[IDS[1]], "attempts": 4}},
            {**original, IDS[1]: {**original[IDS[1]], "video_id": IDS[2]}},
            {**original, IDS[1]: {**original[IDS[1]], "url": gp.canonical_url(IDS[2])}},
            {**original, IDS[2]: {**original[IDS[2]], "state": "unknown-checkpoint-state"}},
        ]
        for items in cases:
            with self.subTest(items=items):
                self.remote["status"]["items"] = items
                with self.assertRaises(gp.PoolError):
                    self.arm()
        self.assert_no_resume()

    def test_empty_or_unbounded_approval_reference_is_not_authority(self):
        for approval in [None, "", " ", "approval" * 32]:
            with self.subTest(approval=approval):
                with self.assertRaises(gp.PoolError):
                    self.arm(approval=approval)
        self.assert_no_resume()
        self.assertIsNone(self.request())

    def test_checkpoint_drift_after_arming_holds_without_consuming_an_intent(self):
        self.arm()
        self.remote["statusSha256"] = "d" * 64
        result = self.continue_at(OCCURRENCE + dt.timedelta(hours=4))
        self.assertEqual(result["state"], "recovery_held")
        self.assertEqual(wc.read_json(self.root / "resume-requests" / (DIGEST + ".json"))["state"], "held")
        self.assert_no_resume()

    def test_authoritative_binding_drift_after_arming_holds_without_rpc(self):
        self.arm()
        item = self.store.load_item(IDS[2])
        item["active_lease_id"] = "00000000-0000-4000-8000-000000000002"
        self.store.save_item(item)
        before = self.protected_bytes()
        self.assertEqual(self.continue_at(OCCURRENCE + dt.timedelta(hours=4))["state"], "recovery_held")
        self.assertEqual(self.request()["state"], "held")
        self.assertEqual(before, self.protected_bytes())
        self.assert_no_resume()

    def test_other_circuit_after_arming_cannot_use_the_due_timer(self):
        self.arm()
        self.remote["status"].update(state="blocked_auth_required", circuit_reason="auth_required")
        self.remote["status"]["items"][IDS[1]].update(state="blocked_auth_required", failure_class="auth_required")
        self.assertEqual(self.continue_at(OCCURRENCE + dt.timedelta(hours=4))["state"], "recovery_held")
        self.assert_no_resume()

    def test_offline_due_tick_keeps_the_original_grant_for_a_later_tick(self):
        self.arm()
        original = self.request()
        self.node_mock.side_effect = wc.YC.NodeUnavailable("fixture-node", "synthetic node offline")
        self.assertEqual(self.continue_at(OCCURRENCE + dt.timedelta(hours=4))["state"], "recovery_waiting")
        self.assertEqual(self.request(), original)
        self.node_mock.side_effect = None
        self.continue_at(OCCURRENCE + dt.timedelta(hours=4, minutes=5))
        self.assertEqual(self.calls.count("Resume"), 1)

    def test_grant_expiring_during_final_node_check_creates_no_intent(self):
        self.arm()
        clock = {"now": OCCURRENCE + dt.timedelta(hours=4)}
        self.patch(wc, "_recovery_now", side_effect=lambda now: clock["now"])
        self.node_mock.reset_mock()
        def node_with_delay():
            if self.node_mock.call_count == 2:
                clock["now"] = OCCURRENCE + dt.timedelta(hours=24)
            return {"nodeId": self.node["node_id"]}
        self.node_mock.side_effect = node_with_delay
        wc.continue_rate_recovery(CANARY)
        self.assertEqual(self.node_mock.call_count, 2)
        self.assert_no_resume()
        inventory = wc.resume_request_inventory(self.root, self.manifest)
        self.assertEqual(sum(row["state"] in {"intent", "uncertain", "acknowledged"} for row in inventory.values()), 0)

    def test_lease_drift_during_final_node_check_creates_no_intent(self):
        self.arm()
        self.node_mock.reset_mock()
        def node_with_drift():
            if self.node_mock.call_count == 2:
                item = self.store.load_item(IDS[2])
                item["active_lease_id"] = "00000000-0000-4000-8000-000000000002"
                self.store.save_item(item)
            return {"nodeId": self.node["node_id"]}
        self.node_mock.side_effect = node_with_drift
        self.assertEqual(self.continue_at(OCCURRENCE + dt.timedelta(hours=4))["state"], "recovery_held")
        self.assertEqual(self.node_mock.call_count, 2)
        self.assert_no_resume()
        self.assertEqual(self.request()["state"], "held")
        inventory = wc.resume_request_inventory(self.root, self.manifest)
        self.assertEqual(sum(row["state"] in {"intent", "uncertain", "acknowledged"} for row in inventory.values()), 0)

    def test_managed_source_drift_during_final_check_creates_no_intent(self):
        self.arm()
        self.sources.reset_mock()
        self.sources.side_effect = [None, gp.PoolError("synthetic managed source drift")]
        self.assertEqual(self.continue_at(OCCURRENCE + dt.timedelta(hours=4))["state"], "recovery_held")
        self.assertEqual(self.sources.call_count, 2)
        self.assert_no_resume()
        self.assertEqual(self.request()["state"], "held")

    def test_managed_source_drift_refuses_to_arm(self):
        self.sources.side_effect = gp.PoolError("synthetic managed source drift")
        with self.assertRaises(gp.PoolError):
            self.arm()
        self.assertIsNone(self.request())
        self.assert_no_resume()

    def test_cancel_revokes_only_an_undispatched_grant(self):
        self.arm()
        original = self.request()
        before = self.protected_bytes()
        result = wc.cancel_rate_recovery(CANARY, expected_checkpoint_sha256=DIGEST)
        self.assertEqual(result["state"], "recovery_held")
        cancelled = self.request()
        self.assertEqual(cancelled["state"], "held")
        self.assertEqual(cancelled["hold_reason"], "operator_cancelled")
        self.assertEqual(cancelled["grant_expires_at"], original["grant_expires_at"])
        self.continue_at(OCCURRENCE + dt.timedelta(hours=4))
        self.assert_no_resume()
        self.assertEqual(self.protected_bytes(), before)

    def test_cancel_after_intent_does_not_erase_consumed_budget(self):
        self.arm()
        self.continue_at(OCCURRENCE + dt.timedelta(hours=4))
        receipt = self.root / "resume-requests" / (DIGEST + ".json")
        original = receipt.read_bytes()
        self.assertEqual(wc.cancel_rate_recovery(CANARY, expected_checkpoint_sha256=DIGEST)["state"], "already_requested")
        self.assertEqual(receipt.read_bytes(), original)
        self.assertEqual(self.calls.count("Resume"), 1)

    def test_cli_arm_requires_approval_and_routes_grant_fields_to_owner(self):
        argv = ["arm-rate", "--canary-id", CANARY, "--checkpoint-sha256", DIGEST]
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as refused:
            wc.build_parser().parse_args(argv)
        self.assertEqual(refused.exception.code, 2)
        self.patch(wc, "_recovery_now", return_value=OCCURRENCE)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(wc.main(argv + ["--approval-reference", FIRST_APPROVAL, "--retry-after-at", timestamp(OCCURRENCE + dt.timedelta(hours=6))]), 0)
        request = self.request()
        self.assertEqual(request["state"], "armed")
        self.assertEqual(request["approval_reference"], FIRST_APPROVAL)
        self.assertEqual(instant(request["due_at"]), OCCURRENCE + dt.timedelta(hours=6))
        self.assert_no_resume()

    def test_cli_resume_propagates_explicit_grant_and_retains_policy_wait(self):
        clock = {"now": OCCURRENCE + dt.timedelta(hours=4)}
        self.patch(wc, "_recovery_now", side_effect=lambda now: clock["now"])
        argv = ["resume", "--canary-id", CANARY, "--checkpoint-sha256", DIGEST, "--approval-reference", FIRST_APPROVAL, "--retry-after-at", timestamp(OCCURRENCE + dt.timedelta(hours=6))]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(wc.main(argv), 0)
        self.assertEqual(self.request()["state"], "armed")
        self.assert_no_resume()
        clock["now"] = OCCURRENCE + dt.timedelta(hours=6)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(wc.main(argv), 0)
        self.assertEqual(self.request()["state"], "acknowledged")
        self.assertEqual(self.calls.count("Resume"), 1)

    def test_cli_status_and_cancel_do_not_probe_or_extract(self):
        self.arm()
        calls = list(self.calls)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(wc.main(["recovery-status", "--canary-id", CANARY]), 0)
        self.assertEqual(json.loads(output.getvalue())["requests"][DIGEST]["state"], "armed")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(wc.main(["cancel-rate", "--canary-id", CANARY, "--checkpoint-sha256", DIGEST]), 0)
        self.assertEqual(self.request()["state"], "held")
        self.assertEqual(self.calls, calls)

    def test_cli_status_for_missing_canary_creates_no_state_or_lock(self):
        missing = "windows-canary-fixture-nonexistent"
        before = sorted(str(path.relative_to(self.pool)) for path in self.pool.rglob("*"))
        lock = self.patch(wc.GP, "FileLock", wraps=wc.GP.FileLock)
        with self.assertRaises(gp.PoolError):
            wc.main(["recovery-status", "--canary-id", missing])
        self.assertFalse((self.pool / "windows-canaries" / missing).exists())
        self.assertEqual(sorted(str(path.relative_to(self.pool)) for path in self.pool.rglob("*")), before)
        lock.assert_not_called()
        self.assertEqual(self.calls, [])

    def test_shared_reader_stops_rereads_before_the_operation_byte_limit(self):
        self.arm()
        path = self.root / "resume-requests" / (DIGEST + ".json")
        raw = path.read_bytes()
        path.write_bytes(raw + b" " * (65536 - len(raw)))
        reader = wc._recovery_receipt_reader()
        opened = self.patch(wc.os, "open", wraps=wc.os.open)
        for _ in range(16):
            inventory = wc.resume_request_inventory(self.root, self.manifest, read_raw=reader)
            self.assertEqual(inventory[DIGEST]["state"], "armed")
        self.assertEqual(opened.call_count, 16)
        with self.assertRaises(gp.PoolError):
            wc.resume_request_inventory(self.root, self.manifest, read_raw=reader)
        # Refusal happens before opening/reading the seventeenth 64 KiB file.
        self.assertEqual(opened.call_count, 16)
        self.assert_no_resume()

    def test_continuation_shares_one_reader_across_authority_rereads(self):
        self.arm()
        inventory = self.patch(wc, "resume_request_inventory", wraps=wc.resume_request_inventory)
        self.continue_at(OCCURRENCE + dt.timedelta(hours=4))
        self.assertGreaterEqual(inventory.call_count, 3)
        callbacks = [call.kwargs.get("read_raw") for call in inventory.call_args_list]
        self.assertIsNotNone(callbacks[0])
        self.assertTrue(all(callback is callbacks[0] for callback in callbacks))
        self.assertEqual(self.calls.count("Resume"), 1)

    def test_concurrent_caller_cannot_cross_existing_reconcile_lock(self):
        self.arm()
        with gp.FileLock(self.root / "reconcile.lock", blocking=False):
            with self.assertRaises(gp.PoolLockError):
                self.continue_at(OCCURRENCE + dt.timedelta(hours=4))
        self.assertEqual(self.request()["state"], "armed")
        self.assert_no_resume()

    def test_inventory_rejects_corrupt_oversized_and_symlink_receipts(self):
        requests = self.root / "resume-requests"
        requests.mkdir()
        path = requests / (DIGEST + ".json")
        for raw in [b"{", b" " * (65536 + 1)]:
            with self.subTest(size=len(raw)):
                path.write_bytes(raw)
                with self.assertRaises(gp.PoolError):
                    wc.resume_request_inventory(self.root, self.manifest)
        path.unlink()
        target = self.root / "unowned-receipt.json"
        target.write_text("{}")
        path.symlink_to(target)
        with self.assertRaises(gp.PoolError):
            wc.resume_request_inventory(self.root, self.manifest)
        self.assert_no_resume()

    def test_inventory_enforces_entry_count_and_total_bytes(self):
        requests = self.root / "resume-requests"
        requests.mkdir()
        binding = {key: self.manifest.get(key) for key in ("canary_id", "lease_id", "binding_sha256", "worker_sha256", "adapter_sha256", "urls_sha256")}
        for index in range(65):
            digest = f"{index:064x}"
            self.write(requests / (digest + ".json"), {"schema": "openclaw.youtube.windows-resume.v1", "binding": binding, "checkpoint_sha256": digest, "state": "intent", "created_at": timestamp(OCCURRENCE)})
        with self.assertRaises(gp.PoolError):
            wc.resume_request_inventory(self.root, self.manifest)
        for path in requests.iterdir():
            path.unlink()
        for index in range(17):
            digest = f"{index:064x}"
            raw = json.dumps({"schema": "openclaw.youtube.windows-resume.v1", "binding": binding, "checkpoint_sha256": digest, "state": "intent", "created_at": timestamp(OCCURRENCE)}).encode()
            (requests / (digest + ".json")).write_bytes(raw + b" " * (65536 - len(raw)))
        with self.assertRaises(gp.PoolError):
            wc.resume_request_inventory(self.root, self.manifest)
        self.assert_no_resume()

    def test_duplicate_consumed_ordinal_is_corrupt_not_a_fresh_slot(self):
        self.arm()
        self.continue_at(OCCURRENCE + dt.timedelta(hours=4))
        request = self.request()
        digest = "d" * 64
        self.write(self.root / "resume-requests" / (digest + ".json"), {**request, "checkpoint_sha256": digest, "occurrence_checkpoint_sha256": digest})
        with self.assertRaises(gp.PoolError):
            wc.resume_request_inventory(self.root, self.manifest)
        self.assertEqual(self.calls.count("Resume"), 1)

    def test_both_scheduled_tick_paths_are_read_only_without_a_grant(self):
        self.supervisor_fixture()
        before = self.protected_bytes()
        for launch in (False, True):
            with self.subTest(launch=launch):
                sv.tick(launch=launch)
        self.assert_no_resume()
        self.assertEqual(self.protected_bytes(), before)

    def test_both_scheduled_tick_paths_share_due_owner_and_never_replay(self):
        self.supervisor_fixture()
        self.arm()
        continue_operation = wc.continue_rate_recovery
        self.patch(wc, "continue_rate_recovery", side_effect=lambda canary_id, **kwargs: continue_operation(canary_id, now=OCCURRENCE + dt.timedelta(hours=4)))
        before = self.protected_bytes()
        sv.tick(launch=False)
        sv.tick(launch=True)
        self.assertEqual(self.calls.count("Resume"), 1)
        self.assertEqual(self.protected_bytes(), before)


if __name__ == "__main__":
    unittest.main()

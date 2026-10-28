"""One-shot verifier control flow; cloud transport is deliberately unbound.

Only synthetic backends are executable in this local source revision. A future
activation needs a reviewed binding to the existing sole lifecycle owner, exact
runtime authorities and a new scope. JSON cannot arm this controller.
"""
from __future__ import annotations

import datetime as dt
import re
from pathlib import Path

import probe
from copier import closure_sha
from custody import Custody
from protocol import (CONSUMER, INDEX, MIN_BOOT_FREE, REPORT_BYTES, REPORT_SHA,
                      SCANNER, SOURCE, Budget, Refusal, canonical, closed, decode,
                      identity, require, sha, stamp, utc, write_once)

ARMED = False
ACTIVATION_SCOPE_SHA256 = None
LIFECYCLE_BINDING_SHA256 = None
VM_ID = '1'
DISK_IDS = ['11', '12']


class Journal:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700)
        self.count = 0

    def record(self, phase, state, facts=None):
        require(re.fullmatch(r"[a-z][a-z0-9_]{0,47}", phase) is not None, "journal_phase")
        value = {"schema": "openclaw.nonroot-controller-event.v1", "phase": phase,
                 "state": state, "facts": facts or {}}
        require(len(canonical(value)) <= 16384, "journal_cap")
        write_once(self.directory / ("%03d-" % self.count + phase + ".private.json"), canonical(value))
        self.count += 1


def unit_binding(actual, expected, context, properties_sha):
    closed(actual, {"unitName", "DynamicUser", "User", "Group", "MainPID", "UID", "GID",
                    "InvocationID", "ControlGroup", "propertiesSha256", "staticNameAbsent", "MountFlags"}, "unit_schema")
    require(actual["unitName"] == context["unitName"] and actual["DynamicUser"] is True and
            actual["User"] == actual["Group"] == context["identityName"] and
            actual["staticNameAbsent"] is True and actual["propertiesSha256"] == properties_sha and
            type(actual["MountFlags"]) is int and actual["MountFlags"] == 262144 and
            context["mountPropagation"] == "private",
            "unit_properties_binding")
    require(actual["MainPID"] == expected["pid"] and actual["UID"] == expected["uid"] and
            actual["GID"] == expected["gid"] and actual["InvocationID"] == expected["invocationId"] and
            actual["ControlGroup"] == expected["cgroupPath"] and expected["sessionId"] == context["sessionId"] and
            expected["bootId"] == context["bootId"] and expected["unitName"] == context["unitName"] and
            expected["identityName"] == context["identityName"] and
            expected["profileSha256"] == context["profileSha256"], "unit_process_join")


def gate(context, context_raw, proof, now):
    require(proof["sessionId"] == context["sessionId"] and proof["bootId"] == context["bootId"] and
            proof["unitName"] == context["unitName"] and proof["profileSha256"] == context["profileSha256"],
            "gate_proof_join")
    clean = {k: v for k, v in proof.items() if k != "factsSha256"}
    require(proof["factsSha256"] == sha(canonical(clean)), "gate_proof_hash")
    expires = min(now + dt.timedelta(seconds=30), utc(context["workerDeadlineUtc"]))
    require(expires > now, "gate_deadline")
    joined = ("sessionId", "unitName", "bootId", "vmId", "identityName", "workerDeadlineUtc", "profileSha256",
              "entrySha256", "workerSha256", "runtimeManifestSha256", "inputManifestSha256", "mountPropagation", "sourceSha",
              "scannerSha", "indexDigest", "privacySha256", "privacyBytes", "consumerCode")
    value = {k: context[k] for k in joined}
    value.update(schema="openclaw.retained-verifier-admission.v1", contextSha256=sha(context_raw),
                 pid=proof["pid"], startTimeTicks=proof["startTimeTicks"], uid=proof["uid"], gid=proof["gid"],
                 invocationId=proof["invocationId"], checkedAt=stamp(now), expiresAt=stamp(expires),
                 proofSha256=proof["factsSha256"], status="passed", inputReleased=True)
    require(len(canonical(value)) <= 16384, "gate_size")
    return value


def ready_binding(raw, context, context_raw, expected):
    value = closed(decode(raw, 4096), {"schema", "status", "pid", "uid", "gid", "contextSha256", "workerSha256"},
                   "controller_ready_schema")
    require(value == {"schema": "openclaw.retained-verifier-ready.v1", "status": "ready",
                      "pid": expected["pid"], "uid": expected["uid"], "gid": expected["gid"],
                      "contextSha256": sha(context_raw), "workerSha256": context["workerSha256"]},
            "controller_ready_binding")


def validate_context_shape(context, *, synthetic):
    import worker
    closed(context, worker.CONTEXT_KEYS, "controller_context_schema")
    name, unit = identity(context["sessionId"])
    require(context["identityName"] == name and context["unitName"] == unit and
            context["vmId"] == VM_ID and context["maxJobSeconds"] == 300 and
            context["operation"] == "retained-report-only" and context["mountPropagation"] == "private",
            "controller_context_identity")
    if not synthetic:
        require(context["sourceSha"] == SOURCE and context["scannerSha"] == SCANNER and
                context["indexDigest"] == INDEX and context["privacySha256"] == REPORT_SHA and
                context["privacyBytes"] == REPORT_BYTES and context["consumerCode"] == CONSUMER,
                "controller_content_pins")


class Controller:
    """Backend owns the exact effect implementation; no retry loops exist here.

    Required backend methods are exercised together in test_controller.py.
    An operational backend is NOT supplied by this local-only revision. The
    frozen old cloud/SSH owner must later be bound explicitly, never substituted
    with ambient credentials or a newly invented connection.
    """
    def __init__(self, backend, directory, *, monotonic, utc_now, synthetic=False):
        require(synthetic is True and getattr(backend, "evidence_kind", None) == "synthetic_contract",
                "activation_unbound")
        self.backend, self.utc_now = backend, utc_now
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700)
        self.journal = Journal(self.directory / "journal")
        self.custody = Custody(self.directory / "custody")
        self.budget = Budget(300, monotonic)
        self.synthetic = synthetic
        self.used = False

    def run(self, context_raw):
        require(not self.used, "controller_attempt_consumed")
        self.used = True
        submitted = False
        phase, result, cleanup = "context", None, []
        context = None
        staged = None
        custody_errors = []
        report_attempted = False
        try:
            context = decode(context_raw, 16384)
            validate_context_shape(context, synthetic=self.synthetic)
            self.journal.record("context", "accepted", {"contextSha256": sha(context_raw)})
            phase = "preparation"
            self.budget.remaining()
            pre = self.backend.preflight(context)
            require(pre["fresh"] is True and pre["vmId"] == VM_ID and pre["testReadOnly"] is True and
                    pre["bootFreeBytes"] >= MIN_BOOT_FREE and pre["diskIds"] == DISK_IDS and
                    pre["noOtherOwner"] is True and pre["runtimeAuthoritiesBound"] is True,
                    "controller_preflight")
            staged = self.backend.prepare(context)
            content = {k: v for k, v in staged["inputManifest"].items() if k != "manifestSha256"}
            require(staged["inputManifestSha256"] == sha(canonical(content)) and
                    staged["inputManifest"]["manifestSha256"] == staged["inputManifestSha256"] and
                    staged["runtimeManifestSha256"] == context["runtimeManifestSha256"] and
                    staged["copiesRootOwned"] is True and
                    staged["inputMode"] == 0, "controller_staging_join")
            # Physical copied-file inode identities are known only after the
            # one staging pass. Bind the resulting public context then, before
            # starting the worker; do not demand a guessed pre-copy inode hash.
            require(context["inputManifestSha256"] in (None, staged["inputManifestSha256"]),
                    "controller_input_manifest_pin")
            context = dict(context, inputManifestSha256=staged["inputManifestSha256"])
            context_raw = canonical(context)
            self.backend.write_public_context_once(context_raw)
            self.journal.record("worker_context", "written", {"contextSha256": sha(context_raw)})
            self.custody.preserve("staging-manifest", canonical(staged["inputManifest"]))
            phase = "unmount"
            self.journal.record("unmount", "intent")
            self.backend.unmount_test_normally()
            require(self.backend.test_is_unmounted() is True, "controller_test_still_mounted")
            phase = "unit_submit"
            self.budget.remaining()
            self.journal.record("unit_submit", "intent", {"unitName": context["unitName"]})
            submitted = True  # Intent precedes effect; an ambiguous error is never redispatched.
            self.backend.start_worker_once(context)
            phase = "admission"
            reader, expected, unit = self.backend.worker_observation(context)
            unit_binding(unit, expected, context, staged["propertiesSha256"])
            ready_binding(self.backend.read_ready_once(), context, context_raw, expected)
            proof = probe.collect_and_validate(reader, expected)
            self.custody.preserve("host-result", canonical(proof))
            self.budget.remaining()
            record = gate(context, context_raw, proof, self.utc_now())
            self.journal.record("gate", "intent", {"gateSha256": sha(canonical(record))})
            self.backend.release_copied_inputs_then_gate(record)
            phase = "consumer"
            allowed = min(240, self.budget.remaining() - 30)
            require(allowed > 0, "controller_completion_reserve")
            outcome = self.backend.wait_worker_once(allowed)
            self.budget.remaining()
            require(isinstance(outcome, dict), "controller_outcome_missing")
            # Preserve evidence on EVERY downstream path, before status judgement.
            self.custody.preserve("worker-stdout", outcome["stdout"])
            self.custody.preserve("worker-stderr", outcome["stderr"])
            report_attempted = True
            report = self.backend.read_exact_copied_report()
            require(len(report) == context["privacyBytes"] and sha(report) == context["privacySha256"],
                    "controller_report_pin")
            self.custody.preserve("report", report)
            proof = self.custody.accept_consumer(outcome["stdout"], outcome["stderr"],
                    returncode=outcome["returncode"], timed_out=outcome["timedOut"], context_sha=sha(context_raw),
                    report_sha=context["privacySha256"],
                    expected_closure_sha=closure_sha(staged["inputManifest"], context["sourceSha"], context["indexDigest"]),
                    pid=expected["pid"], uid=expected["uid"], gid=expected["gid"],
                    expected_worker_sha=context["workerSha256"])
            result = {"status": "passed", "phase": "consumer", "reason": None, "proof": proof}
        except BaseException as error:
            code = error.code if isinstance(error, Refusal) else "controller_unclassified_failure"
            facts = error.facts if isinstance(error, Refusal) else {
                "exceptionType": type(error).__name__,
                "errno": error.errno if isinstance(error, OSError) else None}
            try:
                self.custody.preserve("host-diagnostics", canonical({"phase": phase, "reason": code, "facts": facts}))
            except BaseException:
                code = "controller_custody_failure"
            result = {"status": "refused", "phase": phase, "reason": code, "proof": None}
        finally:
            # Each effect attempted once. A failure preserves state and requests
            # normal outer STOP, never a force operation or repeated mutation.
            if submitted:
                try:
                    self.backend.stop_owned_unit_normally(context["unitName"])
                    require(self.backend.owned_cgroup_empty(context["unitName"]) is True, "controller_cgroup_not_empty")
                    cleanup.append("owned_unit_empty")
                except BaseException:
                    cleanup.append("owned_unit_uncertain_preserve")
                # A spawn/wait/timeout failure must not discard the very bytes
                # needed to explain it. Collect fixed owned outputs after stop,
                # independently from consumer success. Never rerun the worker.
                if not {"worker-stdout", "worker-stderr"} <= set(self.custody.rows):
                    try:
                        recovered = self.backend.collect_owned_evidence()
                        require(isinstance(recovered, dict) and set(recovered) == {"stdout", "stderr"},
                                "controller_recovery_schema")
                        for role, key in (("worker-stdout", "stdout"), ("worker-stderr", "stderr")):
                            if role not in self.custody.rows:
                                self.custody.preserve(role, recovered[key])
                    except BaseException:
                        custody_errors.append("owned_output_recovery_failed")
            if staged is not None and not report_attempted:
                try:
                    report_attempted = True
                    report = self.backend.read_exact_copied_report()
                    require(len(report) == context["privacyBytes"] and sha(report) == context["privacySha256"],
                            "controller_report_pin")
                    self.custody.preserve("report", report)
                except BaseException:
                    custody_errors.append("report_custody_failed")
            try:
                require(self.backend.test_is_unmounted() is True, "controller_test_mount_uncertain")
                cleanup.append("test_unmounted")
            except BaseException:
                cleanup.append("test_mount_uncertain_preserve")
            required_roles = {"staging-manifest", "report"}
            if submitted:
                required_roles.update({"worker-stdout", "worker-stderr"})
            required_roles.add("host-result" if result["status"] == "passed" else "host-diagnostics")
            complete_custody = (staged is not None and not custody_errors and
                                required_roles <= set(self.custody.rows) and
                                all(self.custody.rows[role]["truncated"] is False for role in required_roles))
            if (not submitted or "owned_unit_empty" in cleanup) and "test_unmounted" in cleanup and complete_custody:
                try:
                    self.backend.remove_only_copied_session_files_after_custody()
                    cleanup.append("copied_files_removed")
                except BaseException:
                    cleanup.append("copied_files_retained")
            elif staged is not None:
                cleanup.append("custody_or_ownership_incomplete_preserve_copies")
            # Final cloud STOP/retained-disk/transport result belongs to existing
            # outer lifecycle owner and is independent of consumer acceptance.
            try:
                closeout = self.backend.normal_outer_stop_and_verify()
                require(closeout == {"vmState": "TERMINATED", "diskIds": DISK_IDS,
                                     "retained": True, "transportClosed": True}, "controller_closeout_binding")
            except BaseException:
                closeout = {"status": "uncertain", "requiresOwnedReconciliation": True}
            if result["status"] == "passed" and custody_errors:
                result.update(status="refused", reason="controller_custody_failure")
            result.update(schema="openclaw.nonroot-controller-result.v1", evidenceKind="synthetic_contract",
                          cleanup=cleanup, closeout=closeout, custodyErrors=custody_errors,
                          reportCustody="report" in self.custody.rows, productionQualified=False)
            self.journal.record("closeout", "settled", result)
        return result


def main():
    require(ARMED is True and ACTIVATION_SCOPE_SHA256 is not None and LIFECYCLE_BINDING_SHA256 is not None,
            "activation_unbound")
    raise Refusal("operational_backend_not_bound")


if __name__ == "__main__":
    main()

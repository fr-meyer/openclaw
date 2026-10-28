"""Private evidence is retained before parsing, exit or timeout acceptance."""
from __future__ import annotations
import re
from pathlib import Path
from protocol import RAW_CUSTODY_MAX, Refusal, canonical, closed, decode, require, sha, write_once

SLOTS = {"report": 86000, "host-result": 12288, "staging-manifest": 12288,
         "worker-stdout": 4096, "worker-stderr": 4096, "host-diagnostics": 8192}
assert sum(SLOTS.values()) <= RAW_CUSTODY_MAX


def bounded(raw, cap):
    require(isinstance(raw, bytes), "custody_bytes")
    n = min(len(raw), cap)
    if len(raw) <= cap:
        view = raw
    else:
        first = (cap + 1) // 2
        view = raw[:first] + raw[-(cap - first):]
    return {"bytes": len(raw), "sha256": sha(raw), "truncated": len(raw) > cap,
            "viewBytes": n, "viewSha256": sha(view)}, view


class Custody:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700)
        self.rows = {}

    def preserve(self, role, raw):
        require(role in SLOTS and role not in self.rows, "custody_role")
        facts, view = bounded(raw, SLOTS[role])
        write_once(self.directory / (role + ".private.bin"), view)
        write_once(self.directory / (role + ".private.json"), canonical(facts))
        self.rows[role] = facts
        return facts

    def accept_consumer(self, stdout, stderr, *, returncode, timed_out, context_sha,
                        report_sha, expected_closure_sha, pid, uid, gid, expected_worker_sha):
        # Always called after preservation of raw views; no JSON parse before this join.
        require("worker-stdout" in self.rows and "worker-stderr" in self.rows, "custody_missing")
        require(self.rows["worker-stdout"]["sha256"] == sha(stdout) and
                self.rows["worker-stderr"]["sha256"] == sha(stderr), "custody_changed")
        require(not self.rows["worker-stdout"]["truncated"] and
                not self.rows["worker-stderr"]["truncated"], "custody_proof_truncated")
        require(timed_out is False and type(returncode) is int and returncode == 0,
                "consumer_exit")
        proof = closed(decode(stdout, 4096), {"status", "privacyReceiptSha256", "ociClosureSha256"},
                       "consumer_proof_schema")
        require(proof["status"] == "passed" and proof["privacyReceiptSha256"] == report_sha and
                proof["ociClosureSha256"] == expected_closure_sha and
                isinstance(expected_closure_sha, str) and
                re.fullmatch(r"[0-9a-f]{64}", expected_closure_sha), "consumer_proof_binding")
        records = [decode(line, 4096) for line in stderr.splitlines() if line]
        require(len(records) == 2, "worker_frames")
        ready, final = records
        closed(ready, {"schema", "status", "pid", "uid", "gid", "contextSha256", "workerSha256"},
               "worker_ready_schema")
        closed(final, {"schema", "status", "pid", "contextSha256", "readyEmitted", "consumerExitCode",
                       "timedOut", "reasonCode", "elapsedMilliseconds"}, "worker_result_schema")
        require(ready.get("schema") == "openclaw.retained-verifier-ready.v1" and ready["status"] == "ready" and
                ready.get("pid") == pid and ready.get("uid") == uid and ready.get("gid") == gid and
                ready.get("contextSha256") == context_sha and ready["workerSha256"] == expected_worker_sha,
                "worker_ready_binding")
        require(final.get("schema") == "openclaw.retained-verifier-worker-final.v1" and
                final.get("status") == "consumer_returned" and type(final.get("consumerExitCode")) is int and
                final["consumerExitCode"] == 0 and final["reasonCode"] is None and
                final["pid"] == pid and final["readyEmitted"] is True and
                type(final["elapsedMilliseconds"]) is int and 0 <= final["elapsedMilliseconds"] <= 300000 and
                final.get("timedOut") is False and final.get("contextSha256") == context_sha,
                "worker_result_binding")
        return proof


if __name__ == "__main__":
    raise SystemExit("disarmed_local_source_only")

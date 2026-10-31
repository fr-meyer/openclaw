"""Exact Git identities and coverage for the 10.9 fork-carry source proof.

This validates source bookkeeping, not review judgments, CI, or runtime behavior.
The R9 controller separately authenticates lock-generation receipts and bounds
correction/derivation operations. No path from the ledger is opened on the host.
"""

import hashlib
import json
import os
import re
import subprocess


SCHEMA = "openclaw.v109.fork-carry-reconciliation.v1"
MERGE_SCHEMA = "openclaw.fork-source-merge.v4"
PROOF_PATH = "custom-patches/reconciliation-2026.10.9.json"
HISTORICAL_PROOF_PATH = "custom-patches/reconciliation-2026.10.8.json"
LOCK_PATH = "pnpm-lock.yaml"
SHA = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
PATH = re.compile(r"[A-Za-z0-9_./@+-]+\Z")
MODES = {"100644", "100755", "120000"}
DISPOSITIONS = {
    "CARRIED_EXACT", "MERGED_SOURCE_REVIEWED", "ADAPTED_RELEASE_BINDING",
    "ADAPTED_SECURITY_TEST", "LOCK_CONTROLLED_DERIVATION",
}


def _matches(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def _path(value):
    return (_matches(PATH, value) and not value.startswith("/")
            and not any(part in ("", ".", "..") for part in value.split("/")))


def _strict_json(raw, need):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "10.9 ledger duplicate JSON key")
            result[key] = value
        return result

    def constant(_value):
        need(False, "10.9 ledger non-finite JSON constant")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, TypeError):
        need(False, "10.9 ledger JSON is malformed")


def _raw_blob(source_dir, oid, need, *, maximum=4194304):
    need(_matches(SHA, oid), "10.9 raw blob identity is invalid")
    # Only a validated object ID reaches this fixed pure-Git operation. Raw bytes
    # are required: release.git() strips trailing whitespace and cannot hash locks.
    try:
        command = ["git", "--no-replace-objects", "-c", "protocol.allow=never", "-C", str(source_dir)]
        environment = {**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_OPTIONAL_LOCKS": "0"}
        size = subprocess.run(command + ["cat-file", "-s", oid],
                              capture_output=True, check=True, timeout=30, env=environment).stdout
        need(re.fullmatch(rb"(?:0|[1-9][0-9]*)\n", size) is not None
             and int(size) <= maximum, "10.9 pinned blob exceeds its bounded input size")
        child = subprocess.run(
            command + ["cat-file", "blob", oid],
            capture_output=True, check=True, timeout=30,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError):
        need(False, "10.9 pinned blob is unavailable")
    need(len(child.stdout) == int(size), "10.9 pinned blob size changed")
    return child.stdout


def _names(source_dir, before, after, git, need):
    raw = git(source_dir, "diff", "--no-ext-diff", "--no-textconv", "--name-only",
              "--no-renames", "-z", before, after)
    names = [name for name in raw.split("\0") if name]
    need(len(names) == len(set(names)) and all(_path(name) for name in names),
         "10.9 Git delta contains invalid or repeated paths")
    return set(names)


def _tree(source_dir, commit, names, git, need):
    raw = git(source_dir, "--literal-pathspecs", "ls-tree", "-r", "-z", commit,
              "--", *sorted(names))
    result = {}
    for entry in filter(None, raw.split("\0")):
        parts = entry.split("\t", 1)
        need(len(parts) == 2, "10.9 Git tree entry is malformed")
        header, name = parts
        fields = header.split()
        need(len(fields) == 3 and name in names and name not in result,
             "10.9 Git tree selection changed")
        mode, kind, oid = fields
        need(kind == "blob" and mode in MODES and _matches(SHA, oid),
             "10.9 Git tree entry is not an allowed mode/blob")
        result[name] = {"mode": mode, "blob": oid}
    return result


def check_v109_reconciliation(source, source_dir, ledger=None, *, git, need):
    """Check the actual tip, all four origin/result trees, and full path coverage."""
    source_fields = {"baseCommit", "baseTree", "patches", "commit", "tree", "merge"}
    need(type(source) is dict and set(source) == source_fields, "invalid 10.9 source fields")
    need(all(_matches(SHA, source[key]) for key in ("baseCommit", "baseTree", "commit", "tree")),
         "invalid 10.9 source identity")
    merge = source["merge"]
    need(type(merge) is dict and set(merge) == {
        "schema", "commonCommit", "commonTree", "forkCommit", "forkTree", "reconciliation",
        "integration", "successors", "securitySource"} and merge["schema"] == MERGE_SCHEMA,
        "invalid 10.9 merge fields or schema")
    need(all(_matches(SHA, merge[key]) for key in (
        "commonCommit", "commonTree", "forkCommit", "forkTree")), "invalid 10.9 merge identity")
    for name in ("integration", "securitySource"):
        item = merge[name]
        need(type(item) is dict and set(item) == {"commit", "tree"}
             and all(_matches(SHA, item[key]) for key in ("commit", "tree")),
             "invalid 10.9 merge " + name)
    need(merge["securitySource"] == {"commit": merge["forkCommit"], "tree": merge["forkTree"]},
         "10.9 security source differs from the pinned fork")
    successors = merge["successors"]
    need(type(successors) is list and len(successors) <= 3, "invalid 10.9 successor count")
    for item in successors:
        need(type(item) is dict and set(item) == {"commit", "tree"}
             and all(_matches(SHA, item[key]) for key in ("commit", "tree")),
             "invalid 10.9 successor identity")
    lineage = [merge["integration"]] + successors
    need(len({item["commit"] for item in lineage}) == len(lineage)
         and lineage[-1] == {"commit": source["commit"], "tree": source["tree"]}
         and source["patches"] == [{"commit": source["commit"], "tree": source["tree"]}],
         "10.9 source tip or applied result changed")

    origins = {"base108": (merge["commonCommit"], merge["commonTree"]),
               "fork108": (merge["forkCommit"], merge["forkTree"]),
               "upstream109": (source["baseCommit"], source["baseTree"]),
               "result": (source["commit"], source["tree"])}
    for commit, tree in list(origins.values()) + [(x["commit"], x["tree"]) for x in lineage]:
        need(git(source_dir, "rev-parse", commit + "^{tree}") == tree, "10.9 source tree changed")
    need(git(source_dir, "show", "-s", "--format=%P", lineage[0]["commit"]).split() ==
         [merge["forkCommit"], source["baseCommit"]], "10.9 integration ordered parents changed")
    parent = lineage[0]["commit"]
    for item in successors:
        need(git(source_dir, "show", "-s", "--format=%P", item["commit"]) == parent,
             "10.9 successor is not a single-parent continuation")
        parent = item["commit"]
    need(git(source_dir, "merge-base", "--all", merge["forkCommit"], source["baseCommit"]).splitlines()
         == [merge["commonCommit"]], "10.9 unique common ancestor changed or unavailable")

    proof = merge["reconciliation"]
    need(type(proof) is dict and set(proof) == {"path", "blob", "sha256"}
         and proof["path"] == PROOF_PATH and _matches(SHA, proof["blob"])
         and _matches(SHA256, proof["sha256"]), "invalid 10.9 fixed reconciliation identity")
    proof_entry = _tree(source_dir, source["commit"], {PROOF_PATH}, git, need).get(PROOF_PATH)
    need(proof_entry == {"mode": "100644", "blob": proof["blob"]},
         "10.9 reconciliation mode/blob changed")
    raw = _raw_blob(source_dir, proof["blob"], need)
    need(hashlib.sha256(raw).hexdigest() == proof["sha256"], "10.9 reconciliation digest changed")
    committed = _strict_json(raw, need)
    need(type(committed) is dict and (ledger is None or (type(ledger) is dict and ledger == committed)),
         "10.9 ledger differs from committed proof")
    ledger = committed
    fields = {"schema", "upstream108", "fork108", "upstream109", "qualificationTransferred",
              "selfExclusion", "forkDeltaPathCount", "upstreamChangedPathCount", "overlapPathCount",
              "lockState", "sourcePaths"}
    need(type(ledger) is dict and ledger.get("lockState") in ("pending_ci_derivation", "ci_derived"),
         "invalid 10.9 lock state")
    expected_fields = fields | ({"lockDerivation"} if ledger["lockState"] == "ci_derived" else set())
    need(set(ledger) == expected_fields and ledger["schema"] == SCHEMA
         and ledger["qualificationTransferred"] is False, "invalid 10.9 ledger fields or qualification")
    need((ledger["upstream108"], ledger["fork108"], ledger["upstream109"]) ==
         (merge["commonCommit"], merge["forkCommit"], source["baseCommit"]),
         "10.9 ledger origin commits changed")
    need(ledger["selfExclusion"] == {"path": PROOF_PATH, "reason": "result-blob self-reference excluded"},
         "invalid 10.9 ledger self-exclusion")
    rows = ledger["sourcePaths"]
    need(type(rows) is list and 1 <= len(rows) <= 4096, "invalid 10.9 source path list")
    names = []
    for row in rows:
        need(type(row) is dict and set(row) == {
            "path", "base108", "fork108", "upstream109", "result", "disposition"},
            "invalid 10.9 source path fields")
        name = row["path"]
        need(_path(name) and name != PROOF_PATH, "invalid 10.9 source path")
        for key in origins:
            entry = row[key]
            need(entry is None or (type(entry) is dict and set(entry) == {"mode", "blob"}
                 and type(entry["mode"]) is str and entry["mode"] in MODES
                 and _matches(SHA, entry["blob"])),
                 "invalid 10.9 source mode/blob")
        need(type(row["disposition"]) is str and row["disposition"] in DISPOSITIONS,
             "invalid 10.9 disposition")
        names.append(name)
    need(len(names) == len(set(names)), "10.9 source path is repeated")
    names = set(names)
    fork_delta = _names(source_dir, merge["commonCommit"], merge["forkCommit"], git, need)
    upstream_delta = _names(source_dir, merge["commonCommit"], source["baseCommit"], git, need)
    result_delta = _names(source_dir, source["baseCommit"], source["commit"], git, need)
    need(PROOF_PATH in result_delta and names == fork_delta | (result_delta - {PROOF_PATH}),
         "10.9 source coverage differs from fork/result delta")
    for field, actual in (("forkDeltaPathCount", len(fork_delta)),
                          ("upstreamChangedPathCount", len(upstream_delta)),
                          ("overlapPathCount", len(fork_delta & upstream_delta))):
        need(type(ledger[field]) is int and ledger[field] == actual, "10.9 derived path count changed")
    trees = {key: _tree(source_dir, commit, names | {PROOF_PATH}, git, need)
             for key, (commit, _tree_id) in origins.items()}
    need(all(PROOF_PATH not in trees[key] for key in ("base108", "fork108", "upstream109")),
         "10.9 self-excluded proof already existed in an origin")
    by_name = {row["path"]: row for row in rows}
    for row in rows:
        name, disposition = row["path"], row["disposition"]
        for key in origins:
            need(row[key] == trees[key].get(name), "10.9 actual mode/blob changed: " + name)
        if disposition == "CARRIED_EXACT":
            # Exact absence carries a deliberately retired fork file as well.
            need(row["result"] == row["fork108"], "10.9 exact fork carry changed: " + name)
        elif disposition == "LOCK_CONTROLLED_DERIVATION":
            need(name == LOCK_PATH and row["result"] is not None
                 and row["result"]["mode"] == "100644", "10.9 lock derivation path/mode changed")
        else:
            need(row["result"] is not None and row["result"]["mode"] in ("100644", "100755"),
                 "10.9 reviewed source path was retired or changed type")
            if disposition == "ADAPTED_SECURITY_TEST":
                need(re.fullmatch(r".+\.test\.[cm]?[jt]s", name) is not None
                     or name == "test/scripts/a2ui-zod-bounds.regression.mjs",
                     "10.9 security test disposition names a non-test")
    historical = by_name.get(HISTORICAL_PROOF_PATH)
    need(historical is not None and historical["fork108"] is not None
         and historical["disposition"] == "CARRIED_EXACT"
         and historical["result"] == historical["fork108"], "10.9 historical 10.8 proof changed")
    lock = by_name.get(LOCK_PATH)
    need(lock is not None and lock["disposition"] == "LOCK_CONTROLLED_DERIVATION",
         "10.9 lock is not controlled derivation")
    if ledger["lockState"] == "pending_ci_derivation":
        need(lock["fork108"] is not None and lock["result"] == lock["fork108"],
             "10.9 pending lock differs from the pinned fork")
    else:
        receipt = ledger["lockDerivation"]
        need(type(receipt) is dict and set(receipt) == {
            "runId", "attempt", "artifactSha256", "generatedLockSha256", "receiptSha256"}
            and type(receipt["runId"]) is int and receipt["runId"] > 0
            and type(receipt["attempt"]) is int and receipt["attempt"] == 1
            and all(_matches(SHA256, receipt[key]) for key in (
                "artifactSha256", "generatedLockSha256", "receiptSha256")),
            "invalid 10.9 lock derivation receipt")
        need(hashlib.sha256(_raw_blob(source_dir, lock["result"]["blob"], need, maximum=2097152)).hexdigest()
             == receipt["generatedLockSha256"], "10.9 generated lock digest differs from actual tip")

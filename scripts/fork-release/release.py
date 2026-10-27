#!/usr/bin/env python3
"""Exact-source fork release checks and private, resumable deployment state."""

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENT = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
TEST_PATH = re.compile(r"[A-Za-z0-9_./-]+\.test\.[cm]?[jt]s\Z")
PHASES = ("backup", "restore", "rehearsal", "deploy", "health", "rollback", "cleanup")


class Refusal(RuntimeError):
    pass


def need(ok, message):
    if not ok:
        raise Refusal(message)


def matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def manifest_at(path):
    raw = Path(path).read_bytes()
    manifest = json.loads(raw)
    base_fields = {"schema", "repository", "candidate", "productionEligible", "source", "gates", "image"}
    need(type(manifest) is dict and set(manifest) in (base_fields, base_fields | {"review"}), "invalid manifest fields")
    need(manifest.get("schema") == "openclaw.fork-release.v1", "wrong release manifest schema")
    need(manifest.get("repository") == "fr-meyer/openclaw", "wrong fork repository")
    need(matches(IDENT, manifest.get("candidate")), "invalid candidate name")
    need(type(manifest.get("productionEligible")) is bool, "missing production decision")
    source = manifest.get("source", {})
    source_fields = {"baseCommit", "baseTree", "patches", "commit", "tree"}
    need(type(source) is dict and set(source) in (source_fields, source_fields | {"merge"}), "invalid source fields")
    for name in ("baseCommit", "baseTree", "commit", "tree"):
        need(matches(SHA, source.get(name)), f"invalid source {name}")
    patches = source.get("patches")
    need(type(patches) is list and 1 <= len(patches) <= 64, "invalid patch chain length")
    for patch in patches:
        need(type(patch) is dict and set(patch) == {"commit", "tree"}, "invalid patch entry")
        need(matches(SHA, patch["commit"]) and matches(SHA, patch["tree"]), "invalid patch identity")
    need(patches[-1] == {"commit": source["commit"], "tree": source["tree"]}, "final patch differs from source")
    if "merge" in source:
        validate_merge_shape(source)
    gates = manifest.get("gates", {})
    need(type(gates) is dict and set(gates) == {"patchLifecycle", "producerConsumer"}, "missing focused gate")
    all_tests = []
    for lane in ("patchLifecycle", "producerConsumer"):
        tests = gates[lane]
        need(type(tests) is list and 1 <= len(tests) <= 24, f"invalid {lane} gate")
        for test in tests:
            need(matches(TEST_PATH, test) and not test.startswith("/") and ".." not in test.split("/"), "invalid test path")
            all_tests.append(test)
    need(len(all_tests) == len(set(all_tests)), "duplicate gate test")
    image = manifest.get("image", {})
    need(type(image) is dict and set(image) == {"architecture", "extensions"}, "invalid image fields")
    need(image.get("architecture") == "amd64", "only hosted linux/amd64 is staged")
    need(matches(re.compile(r"[a-z0-9,-]{1,128}\Z"), image.get("extensions")), "invalid extension selection")
    review = manifest.get("review")
    need(not manifest["productionEligible"] or review is not None, "production candidate requires PR review binding")
    if review is not None:
        need(type(review) is dict and set(review) == {"prNumber", "baseSha", "changedDiffSha256"}, "invalid review binding")
        need(type(review["prNumber"]) is int and review["prNumber"] > 0, "invalid PR number")
        need(matches(SHA, review["baseSha"]), "invalid PR base SHA")
        need(matches(re.compile(r"[0-9a-f]{64}\Z"), review["changedDiffSha256"]), "invalid changed diff digest")
    return manifest, sha256(raw)


def git(source_dir, *args):
    result = subprocess.run(["git", "--no-replace-objects", "-C", str(source_dir), *args], capture_output=True, text=True, check=True,
                            env={**os.environ, "GIT_NO_LAZY_FETCH": "1"})
    return result.stdout.strip()


def validate_merge_shape(source):
    """Only an explicitly pinned integration and bounded, declared successors."""
    merge = source["merge"]
    fields = {"commonCommit", "commonTree", "forkCommit", "forkTree", "reconciliation"}
    versioned = type(merge) is dict and "schema" in merge
    need(type(merge) is dict and set(merge) == (fields | {
        "schema", "integration", "successors", "securitySource"} if versioned else fields),
        "invalid merge proof fields")
    if versioned:
        need(merge["schema"] in ("openclaw.fork-source-merge.v2", "openclaw.fork-source-merge.v3"),
             "unsupported merge proof schema")
        for name in ("integration", "securitySource"):
            item = merge[name]
            need(type(item) is dict and set(item) == {"commit", "tree"}
                 and all(matches(SHA, item[key]) for key in ("commit", "tree")),
                 "invalid merge " + name)
        successors = merge["successors"]
        minimum = 0 if merge["schema"] == "openclaw.fork-source-merge.v3" else 1
        need(type(successors) is list and minimum <= len(successors) <= 16,
             "invalid merge successor count")
        for item in successors:
            need(type(item) is dict and set(item) == {"commit", "tree"}
                 and all(matches(SHA, item[key]) for key in ("commit", "tree")),
                 "invalid merge successor")
        commits = [merge["integration"]["commit"]] + [item["commit"] for item in successors]
        tip = successors[-1] if successors else merge["integration"]
        need(len(set(commits)) == len(commits) and tip == {
            "commit": source["commit"], "tree": source["tree"]}, "merge successor tip changed")
    for name in ("commonCommit", "commonTree", "forkCommit", "forkTree"):
        need(matches(SHA, merge[name]), "invalid merge " + name)
    proof = merge["reconciliation"]
    need(type(proof) is dict and set(proof) == {"path", "blob", "sha256"},
         "invalid merge reconciliation fields")
    path = proof["path"]
    need(isinstance(path, str) and re.fullmatch(r"[A-Za-z0-9_./-]+\.json", path)
         and not path.startswith("/") and not any(part in ("", ".", "..") for part in path.split("/")),
         "invalid merge reconciliation path")
    need(matches(SHA, proof["blob"]) and matches(re.compile(r"[0-9a-f]{64}\Z"), proof["sha256"]),
         "invalid merge reconciliation identity")
    need(source["patches"] == [{"commit": source["commit"], "tree": source["tree"]}],
         "merge proof requires exactly one applied result")


def check_merge_reconciliation(source, source_dir):
    """Verify the committed 10.6 carry ledger against all four exact Git trees.

    Disposition reasons and conflict resolutions remain review judgments. Hashes,
    complete path coverage, exact carries and derived counts are checked here.
    """
    merge, proof = source["merge"], source["merge"]["reconciliation"]
    observed = git(source_dir, "ls-tree", source["commit"], "--", proof["path"])
    need(observed.split("\t", 1)[0] == "100644 blob " + proof["blob"],
         "merge reconciliation blob or mode changed")
    raw = subprocess.run(["git", "--no-replace-objects", "-C", str(source_dir), "cat-file", "blob", proof["blob"]],
                         capture_output=True, check=True, env={**os.environ, "GIT_NO_LAZY_FETCH": "1"}).stdout
    need(sha256(raw) == proof["sha256"], "merge reconciliation digest changed")
    ledger = json.loads(raw)
    if merge.get("schema") == "openclaw.fork-source-merge.v3":
        check_v108_reconciliation(source, source_dir, ledger)
        return
    if "schema" in merge:
        check_v107_reconciliation(source, source_dir, ledger)
        return
    need(type(ledger) is dict and set(ledger) == {
        "schema", "method", "upstream105", "fork105", "upstream106", "qualificationTransferred",
        "summary", "carryForwardCommits", "conflictPaths", "paths"}, "invalid merge ledger fields")
    need(isinstance(ledger["method"], str) and bool(ledger["method"].strip()), "invalid merge ledger method")
    need(ledger["schema"] == "openclaw-v106-fork-patch-reconciliation-v1"
         and ledger["qualificationTransferred"] is False, "unsupported merge ledger schema or qualification")
    need(ledger["upstream105"] == merge["commonCommit"] and ledger["fork105"] == merge["forkCommit"]
         and ledger["upstream106"] == source["baseCommit"], "merge ledger source binding changed")
    history = git(source_dir, "rev-list", "--reverse",
                  merge["commonCommit"] + ".." + merge["forkCommit"]).splitlines()
    need(1 <= len(history) <= 64 and ledger["carryForwardCommits"] == history,
         "merge carry history is incomplete")
    parent = merge["commonCommit"]
    for commit in history:
        need(git(source_dir, "show", "-s", "--format=%P", commit) == parent,
             "merge carry history is not linear")
        parent = commit
    need(parent == merge["forkCommit"], "merge carry history has wrong tip")
    paths = ledger["paths"]
    need(type(paths) is list and 1 <= len(paths) <= 4096, "invalid merge ledger paths")
    names = []
    for item in paths:
        need(type(item) is dict and set(item) == {"path", "upstream105Blob", "fork105Blob",
             "upstream106Blob", "resultBlob", "upstreamChanged", "disposition", "reason"},
             "invalid merge ledger path fields")
        name = item["path"]
        need(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_./@+-]+", name)
             and not name.startswith("/") and not any(part in ("", ".", "..") for part in name.split("/")),
             "invalid merge ledger path")
        need(type(item["upstreamChanged"]) is bool and isinstance(item["reason"], str)
             and bool(item["reason"].strip()), "invalid merge ledger decision")
        names.append(name)
    changed = git(source_dir, "diff", "--name-only", "--no-renames", "-z",
                  merge["commonCommit"], merge["forkCommit"]).split("\0")
    need(len(names) == len(set(names)) and set(names) == set(filter(None, changed)),
         "merge ledger coverage differs from fork delta")
    # Literal pathspecs prevent a ledger path from changing the selection. Compare
    # mode/type too: matching blob bytes alone cannot prove an exact carry.
    trees = {}
    for key, commit in (("upstream105Blob", merge["commonCommit"]), ("fork105Blob", merge["forkCommit"]),
                        ("upstream106Blob", source["baseCommit"]), ("resultBlob", source["commit"])):
        entries = git(source_dir, "--literal-pathspecs", "ls-tree", "-r", "-z", commit, "--", *names)
        trees[key] = dict((name, header.split()) for entry in entries.split("\0") if entry
                          for header, name in [entry.split("\t", 1)])
    dispositions, overlap = {}, 0
    allowed = {"CARRIED_EXACT", "MERGED_SOURCE_REVIEWED", "ADAPTED_RELEASE_BINDING", "ADAPTED_COMPATIBILITY_TESTS"}
    for item in paths:
        name = item["path"]
        for key, tree in trees.items():
            entry = tree.get(name)
            need((entry[2] if entry else None) == item[key], "merge ledger blob changed: " + name)
        upstream_changed = trees["upstream105Blob"].get(name) != trees["upstream106Blob"].get(name)
        need(item["upstreamChanged"] == upstream_changed, "merge upstream overlap changed: " + name)
        overlap += upstream_changed
        disposition = item["disposition"]
        need(isinstance(disposition, str) and disposition in allowed, "unresolved merge disposition")
        need(item["resultBlob"] is not None, "merge ledger cannot silently retire a path")
        if disposition == "CARRIED_EXACT":
            need(trees["fork105Blob"].get(name) == trees["resultBlob"].get(name),
                 "merge exact carry changed: " + name)
        dispositions[disposition] = dispositions.get(disposition, 0) + 1
    conflicts = ledger["conflictPaths"]
    need(type(conflicts) is list and all(isinstance(path, str) for path in conflicts)
         and len(conflicts) == len(set(conflicts)) and set(conflicts) <= set(names),
         "invalid merge conflict paths")
    need(ledger["summary"] == {"paths": len(paths), "upstreamOverlap": overlap,
         "textualConflictsResolved": len(conflicts), "dispositions": dispositions,
         "upstreamedExact": 0, "retired": 0}, "merge ledger summary changed")


def check_v107_reconciliation(source, source_dir, ledger):
    """Consume the committed 10.7 security-union ledger without rewriting it.

    Dispositions remain independent source-review judgments. This validates the
    exact source objects, complete result coverage and claimed byte-for-byte
    carries, never transfers an older runtime qualification.
    """
    merge = source["merge"]
    need(type(ledger) is dict and set(ledger) == {
        "schema", "method", "upstream106", "fork106", "fork106Security", "upstream107",
        "approvedSecuritySource", "previousInventory", "qualificationTransferred", "summary",
        "paths", "devDependencyRefresh", "focusedTestSuccessor"}, "invalid 10.7 merge ledger fields")
    need(ledger["schema"] == "openclaw-v107-fork-patch-reconciliation-v1"
         and ledger["qualificationTransferred"] is False, "unsupported 10.7 ledger or qualification")
    need(isinstance(ledger["method"], str) and bool(ledger["method"].strip()), "invalid 10.7 ledger method")
    need(ledger["upstream106"] == merge["commonCommit"]
         and ledger["fork106Security"] == merge["forkCommit"]
         and ledger["upstream107"] == source["baseCommit"]
         and ledger["approvedSecuritySource"] == merge["securitySource"]["commit"],
         "10.7 ledger source binding changed")
    need(matches(SHA, ledger["fork106"]) and git(source_dir, "merge-base", "--all",
         ledger["fork106"], merge["forkCommit"]).splitlines() == [ledger["fork106"]],
         "10.7 prior fork is not an ancestor")
    need(ledger["previousInventory"] == "custom-patches/reconciliation-2026.10.6.json"
         and git(source_dir, "cat-file", "-t", ledger["fork106"] + ":" + ledger["previousInventory"]) == "blob",
         "10.7 prior inventory changed or missing")
    proof_path = "custom-patches/reconciliation-2026.10.7.json"
    need(merge["reconciliation"]["path"] == proof_path, "unsupported 10.7 ledger path")
    support = {proof_path, "custom-patches/NEXT-RELEASE-2026.10.7.md"}
    paths = ledger["paths"]
    need(type(paths) is list and 1 <= len(paths) <= 4096, "invalid 10.7 ledger paths")
    names = []
    for item in paths:
        need(type(item) is dict and set(item) == {
            "path", "upstream106Blob", "fork106SecurityBlob", "upstream107Blob",
            "approvedSecuritySourceBlob", "resultBlob", "upstream107Changed", "disposition", "reason"},
            "invalid 10.7 ledger path fields")
        name = item["path"]
        need(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_./@+-]+", name)
             and not name.startswith("/") and not any(part in ("", ".", "..") for part in name.split("/")),
             "invalid 10.7 ledger path")
        need(type(item["upstream107Changed"]) is bool and isinstance(item["reason"], str)
             and bool(item["reason"].strip()), "invalid 10.7 ledger decision")
        names.append(name)
    changed = set(filter(None, git(source_dir, "diff", "--name-only", "--no-renames", "-z",
                                  source["baseCommit"], source["commit"]).split("\0")))
    fork_changed = set(filter(None, git(source_dir, "diff", "--name-only", "--no-renames", "-z",
                                      merge["commonCommit"], merge["forkCommit"]).split("\0")))
    need(len(names) == len(set(names)) and set(names) == changed - support
         and support <= changed and fork_changed <= set(names), "10.7 ledger coverage changed")
    trees = {}
    for key, commit in (("upstream106Blob", merge["commonCommit"]),
                        ("fork106SecurityBlob", merge["forkCommit"]),
                        ("upstream107Blob", source["baseCommit"]),
                        ("approvedSecuritySourceBlob", merge["securitySource"]["commit"]),
                        ("resultBlob", source["commit"])):
        entries = git(source_dir, "--literal-pathspecs", "ls-tree", "-r", "-z", commit, "--", *names)
        trees[key] = dict((name, header.split()) for entry in entries.split("\0") if entry
                          for header, name in [entry.split("\t", 1)])
    allowed = {"CARRIED_EXACT", "ADAPTED_RELEASE_BINDING", "SECURITY_MERGED_SOURCE",
               "SECURITY_CARRIED_EXACT", "ADAPTED_DEV_DEPENDENCY_AND_TEST_BINDING",
               "ADDED_FOCUSED_CONTRACT_TEST", "MERGED_SOURCE_REVIEWED",
               "ADDED_DEV_DEPENDENCY_COMPATIBILITY_TEST", "ADAPTED_FOCUSED_TEST_OWNERSHIP",
               "ADAPTED_COMPATIBILITY_TESTS"}
    dispositions, overlaps, security_count = {}, [], 0
    for item in paths:
        name, disposition = item["path"], item["disposition"]
        need(disposition in allowed, "unsupported 10.7 disposition")
        for key, tree in trees.items():
            # Null in the security column means this path was not selected for
            # security carry, rather than asserting absence from that source.
            if key == "approvedSecuritySourceBlob" and item[key] is None:
                continue
            entry = tree.get(name)
            need((entry[2] if entry else None) == item[key], "10.7 ledger blob changed: " + name)
        need(item["resultBlob"] is not None, "10.7 ledger cannot retire a path")
        overlap = (name in trees["fork106SecurityBlob"] and trees["upstream106Blob"].get(name) !=
                   trees["upstream107Blob"].get(name))
        need(item["upstream107Changed"] == overlap, "10.7 upstream overlap changed: " + name)
        if disposition == "CARRIED_EXACT":
            need(trees["fork106SecurityBlob"].get(name) == trees["resultBlob"].get(name),
                 "10.7 exact fork carry changed: " + name)
        if disposition.startswith("SECURITY_"):
            need(item["approvedSecuritySourceBlob"] is not None, "10.7 security carry has no source")
        if disposition == "SECURITY_CARRIED_EXACT":
            need(trees["approvedSecuritySourceBlob"].get(name) == trees["resultBlob"].get(name),
                 "10.7 exact security carry changed: " + name)
        security_count += item["approvedSecuritySourceBlob"] is not None
        if disposition == "MERGED_SOURCE_REVIEWED":
            need(overlap, "10.7 reviewed overlap is not an upstream change")
            overlaps.append(name)
        dispositions[disposition] = dispositions.get(disposition, 0) + 1
    summary = ledger["summary"]
    need(type(summary) is dict and set(summary) == {
        "paths", "previousForkPaths", "newUpstreamOverlapPaths", "securityCarryPaths",
        "textualConflicts", "dispositions", "upstreamedClaimed", "retired"}
         and summary["paths"] == len(paths) and summary["previousForkPaths"] == len(fork_changed)
         and summary["newUpstreamOverlapPaths"] == sorted(overlaps)
         and summary["securityCarryPaths"] == security_count and summary["dispositions"] == dispositions
         and type(summary["textualConflicts"]) is int and summary["textualConflicts"] >= 0
         and summary["upstreamedClaimed"] == 0 and summary["retired"] == 0,
         "10.7 ledger summary changed")
    successor = ledger["focusedTestSuccessor"]
    need(type(successor) is dict and successor.get("base") in
         [item["commit"] for item in merge["successors"][:-1]]
         and successor.get("runtimeChanged") is False and successor.get("dependenciesChanged") is False,
         "10.7 focused-test successor binding changed")
    focused_paths = git(source_dir, "diff", "--name-only", "--no-renames",
                        successor["base"], source["commit"]).splitlines()
    need(all(matches(TEST_PATH, name) or name.startswith("test/") or name in support
             for name in focused_paths), "10.7 focused successor changed runtime or dependencies")



def check_v108_metadata_carry(source_dir, name, fork_entry, upstream_entry, result_entry):
    """Only release metadata may change in a claimed dependency-security carry.

    This preserves the reviewed fork's dependency selections, overrides, scripts
    and plugin configuration. It does not evaluate dependency vulnerability or
    transfer the historical security source's qualification.
    """
    documents = [json.loads(git(source_dir, "cat-file", "blob", entry["blob"]))
                 for entry in (fork_entry, upstream_entry, result_entry)]
    need(all(type(item) is dict for item in documents), "invalid 10.8 package metadata: " + name)
    fork, upstream, result = documents
    # These exact fields are the release metadata that changed from 10.7 to 10.8.
    # Copy their values from the pinned upstream; every other fork field is kept.
    expected = json.loads(json.dumps(fork))
    for keys in (("version",), ("peerDependencies", "openclaw"),
                 ("openclaw", "compat", "pluginApi"),
                 ("openclaw", "build", "openclawVersion")):
        target, incoming = expected, upstream
        for key in keys[:-1]:
            target = target.get(key) if type(target) is dict else None
            incoming = incoming.get(key) if type(incoming) is dict else None
        if type(target) is dict and type(incoming) is dict and keys[-1] in incoming:
            target[keys[-1]] = incoming[keys[-1]]
    need(result == expected, "10.8 dependency security or fork metadata changed: " + name)
    need(fork_entry["mode"] == result_entry["mode"], "10.8 package mode changed: " + name)


def check_v108_reconciliation(source, source_dir, ledger):
    """Check the committed 10.8 ledger against complete, exact mode/blob trees.

    Reconciliation of overlapping source and documentation remains a reviewed
    judgment. This proves identities and path preservation, not runtime behavior.
    """
    merge = source["merge"]
    proof_path = "custom-patches/reconciliation-2026.10.8.json"
    note_path = "custom-patches/NEXT-RELEASE-2026.10.8.md"
    need(type(ledger) is dict and set(ledger) == {
        "schema", "upstream107", "fork107Source", "upstream108", "priorForkDeltaPaths",
        "textualConflicts", "qualificationTransferred", "selfExclusion", "paths"},
        "invalid 10.8 merge ledger fields")
    need(ledger["schema"] == "openclaw-v108-source-reconciliation-v1"
         and ledger["qualificationTransferred"] is False,
         "unsupported 10.8 ledger or qualification")
    need(ledger["upstream107"] == merge["commonCommit"]
         and ledger["fork107Source"] == merge["forkCommit"]
         and ledger["upstream108"] == source["baseCommit"], "10.8 ledger source binding changed")
    need(merge["reconciliation"]["path"] == proof_path
         and ledger["selfExclusion"] == {"path": proof_path, "reason": "result-blob self-reference excluded"},
         "unsupported 10.8 ledger self-exclusion")
    need(type(ledger["textualConflicts"]) is int and ledger["textualConflicts"] == 0,
         "unsupported 10.8 textual conflict claim")
    paths = ledger["paths"]
    need(type(paths) is list and 1 <= len(paths) <= 4096, "invalid 10.8 ledger paths")
    names = []
    for item in paths:
        need(type(item) is dict and set(item) == {
            "path", "upstream107", "fork107", "upstream108", "result", "disposition"},
            "invalid 10.8 ledger path fields")
        name = item["path"]
        need(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_./@+-]+", name)
             and not name.startswith("/") and not any(part in ("", ".", "..") for part in name.split("/")),
             "invalid 10.8 ledger path")
        for key in ("upstream107", "fork107", "upstream108", "result"):
            entry = item[key]
            need(entry is None or (type(entry) is dict and set(entry) == {"mode", "blob"}
                 and entry["mode"] in ("100644", "100755", "120000") and matches(SHA, entry["blob"])),
                 "invalid 10.8 ledger mode/blob: " + name)
        names.append(name)
    fork_changed = set(filter(None, git(source_dir, "diff", "--name-only", "--no-renames", "-z",
                                      merge["commonCommit"], merge["forkCommit"]).split("\0")))
    result_changed = set(filter(None, git(source_dir, "diff", "--name-only", "--no-renames", "-z",
                                        source["baseCommit"], source["commit"]).split("\0")))
    need(len(names) == len(set(names)) and proof_path not in names
         and set(names) == fork_changed | (result_changed - {proof_path})
         and proof_path in result_changed and note_path in names,
         "10.8 ledger coverage differs from prior fork or result delta")
    need(type(ledger["priorForkDeltaPaths"]) is int and ledger["priorForkDeltaPaths"] == len(fork_changed),
         "10.8 prior fork path count changed")
    trees = {}
    for key, commit in (("upstream107", merge["commonCommit"]), ("fork107", merge["forkCommit"]),
                        ("upstream108", source["baseCommit"]), ("result", source["commit"])):
        entries = git(source_dir, "--literal-pathspecs", "ls-tree", "-r", "-z", commit, "--", *names)
        tree = {}
        for entry in filter(None, entries.split("\0")):
            header, name = entry.split("\t", 1)
            mode, kind, blob = header.split()
            need(kind == "blob", "10.8 ledger entry is not a blob: " + name)
            tree[name] = {"mode": mode, "blob": blob}
        trees[key] = tree
    special = {
        "ADDED_SOURCE_ONLY_RUNBOOK": {note_path},
        "ADAPTED_SOURCE_ONLY_RELEASE_BINDING": {"custom-patches/manifest.json"},
        "MERGED_SDK_CONTRACT_DOCUMENTATION": {
            "docs/plugins/sdk-runtime.md", "docs/plugins/sdk-runtime/config-and-utilities.md"},
        "MERGED_TASK_ACCESS_AND_IMMUTABLE_INSPECTION": {"src/plugins/loader-module-runtime.ts"},
        "MERGED_MAINTAINED_TEST_ROUTE_UNION": {
            "test/vitest/vitest.database-worker-core-paths.mjs", "test/vitest/vitest.gateway-server-paths.mjs"},
    }
    for item in paths:
        name, disposition = item["path"], item["disposition"]
        for key, tree in trees.items():
            need(tree.get(name) == item[key], "10.8 ledger mode/blob changed: " + name)
        need(item["result"] is not None, "10.8 ledger cannot retire a fork or security path: " + name)
        need(isinstance(disposition, str), "unsupported 10.8 disposition")
        if disposition == "CARRIED_EXACT":
            need(item["fork107"] is not None and item["fork107"] == item["result"],
                 "10.8 exact fork carry changed: " + name)
        elif disposition == "MERGED_UPSTREAM_METADATA_AND_FORK_SECURITY":
            need(name == "package.json" or re.fullmatch(r"extensions/[A-Za-z0-9._-]+/package\.json", name),
                 "10.8 metadata disposition path changed: " + name)
            need(all(item[key] is not None for key in ("upstream107", "fork107", "upstream108"))
                 and item["upstream107"] != item["upstream108"], "10.8 metadata overlap changed: " + name)
            check_v108_metadata_carry(source_dir, name, item["fork107"], item["upstream108"], item["result"])
        else:
            need(disposition in special and name in special[disposition], "unsupported 10.8 disposition: " + name)
            if disposition == "ADDED_SOURCE_ONLY_RUNBOOK":
                need(all(item[key] is None for key in ("upstream107", "fork107", "upstream108")),
                     "10.8 runbook was not newly added")
            elif disposition != "ADAPTED_SOURCE_ONLY_RELEASE_BINDING":
                need(all(item[key] is not None for key in ("upstream107", "fork107", "upstream108"))
                     and item["upstream107"] != item["upstream108"], "10.8 reviewed overlap changed: " + name)
            else:
                need(item["fork107"] is not None, "10.8 release binding has no fork source")


def check_merge_ancestry(source, source_dir):
    """Missing shallow ancestry must not invent a unique common ancestor."""
    common = source["merge"]["commonCommit"]
    relevant = git(source_dir, "rev-list", "--max-count=4097", source["commit"], "^" + common).splitlines()
    need(len(relevant) <= 4096, "merge ancestry exceeds bounded proof")
    shallow = Path(git(source_dir, "rev-parse", "--path-format=absolute", "--git-path", "shallow"))
    boundaries = set(shallow.read_text().splitlines()) if shallow.exists() else set()
    need(not boundaries.intersection(relevant), "merge ancestry is shallow within required history")


def check_source_graph(source, source_dir):
    chain = [(source["baseCommit"], source["baseTree"])] + [
        (patch["commit"], patch["tree"]) for patch in source["patches"]
    ]
    for commit, tree in chain:
        need(git(source_dir, "rev-parse", f"{commit}^{{tree}}") == tree, "source tree changed")
    if "merge" in source:
        validate_merge_shape(source)
        merge = source["merge"]
        check_merge_ancestry(source, source_dir)
        for name in ("common", "fork"):
            need(git(source_dir, "rev-parse", merge[name + "Commit"] + "^{tree}") == merge[name + "Tree"],
                 "merge " + name + " tree changed")
        integration = merge.get("integration", {"commit": source["commit"], "tree": source["tree"]})
        need(git(source_dir, "rev-parse", integration["commit"] + "^{tree}") == integration["tree"],
             "merge integration tree changed")
        need(git(source_dir, "show", "-s", "--format=%P", integration["commit"]).split() ==
             [merge["forkCommit"], source["baseCommit"]], "merge ordered parents changed")
        if "schema" in merge:
            need(git(source_dir, "rev-parse", merge["securitySource"]["commit"] + "^{tree}") ==
                 merge["securitySource"]["tree"], "merge security source tree changed")
            parent = integration["commit"]
            for item in merge["successors"]:
                need(git(source_dir, "rev-parse", item["commit"] + "^{tree}") == item["tree"]
                     and git(source_dir, "show", "-s", "--format=%P", item["commit"]) == parent,
                     "merge successor parent or tree changed")
                parent = item["commit"]
        need(git(source_dir, "merge-base", "--all", merge["forkCommit"], source["baseCommit"]).splitlines() ==
             [merge["commonCommit"]], "merge common ancestor changed or unavailable")
        check_merge_reconciliation(source, source_dir)
    else:
        for index, (commit, _) in enumerate(chain[1:], 1):
            need(git(source_dir, "show", "-s", "--format=%P", commit) == chain[index - 1][0], "patch is a merge or parent changed")
    return chain


def check_source(manifest, source_dir):
    source = manifest["source"]
    need(git(source_dir, "rev-parse", "HEAD") == source["commit"], "checkout is not the pinned source commit")
    chain = check_source_graph(source, source_dir)
    for lane in ("patchLifecycle", "producerConsumer"):
        for test in manifest["gates"][lane]:
            need(git(source_dir, "cat-file", "-e", f"{source['commit']}:{test}") == "", f"missing pinned test: {test}")
    return chain


def receipt_at(path, manifest, manifest_hash, inventory_hash):
    receipt = read_json(path)
    need(type(receipt) is dict and receipt.get("schema") == "openclaw.fork-release-image.v2", "wrong image receipt schema")
    need(receipt.get("manifestSha256") == manifest_hash, "image receipt is for another manifest")
    need(matches(re.compile(r"[0-9a-f]{64}\Z"), inventory_hash) and receipt.get("inventorySha256") == inventory_hash, "image receipt inventory mismatch")
    need(receipt.get("repository") == manifest["repository"], "image receipt repository mismatch")
    need(receipt.get("sourceSha") == manifest["source"]["commit"], "image receipt source mismatch")
    need(receipt.get("sourceTree") == manifest["source"]["tree"], "image receipt tree mismatch")
    need(receipt.get("architecture") == manifest["image"]["architecture"], "image architecture mismatch")
    for name in ("indexDigest", "imageDigest", "configDigest"):
        need(matches(DIGEST, receipt.get(name)), f"invalid {name}")
    producer = receipt.get("producer", {})
    validate_producer(producer)
    need(receipt.get("artifactName") == image_artifact_name(receipt["sourceSha"], producer), "image artifact name mismatch")
    if manifest.get("review") is not None:
        review = receipt.get("review", {})
        need(type(review) is dict and matches(SHA, review.get("headSha")), "image receipt lacks exact PR head")
        for key in ("prNumber", "baseSha", "changedDiffSha256"):
            need(review.get(key) == manifest["review"][key], f"image PR {key} mismatch")
        if producer.get("kind") == "gcp":
            need(review["headSha"] == receipt["sourceSha"], "GCP image review head differs from source")
    return receipt


def producer_fields(producer):
    if type(producer) is dict and producer.get("kind") == "gcp":
        return "kind toolingSha operationId attempt executionSha256"
    return "workflowSha runId attempt"


def validate_producer(producer):
    need(type(producer) is dict and set(producer) == set(producer_fields(producer).split()),
         "invalid producer fields")
    need(re.fullmatch(r"[1-9][0-9]*", str(producer.get("attempt", ""))), "invalid producer attempt")
    if producer.get("kind") == "gcp":
        need(matches(SHA, producer.get("toolingSha")), "invalid GCP producer tooling SHA")
        need(matches(re.compile(r"[0-9a-f]{32}\Z"), producer.get("operationId")), "invalid GCP operation ID")
        need(matches(re.compile(r"[0-9a-f]{64}\Z"), producer.get("executionSha256")), "invalid GCP execution digest")
    else:
        need(matches(SHA, producer.get("workflowSha")), "invalid producer workflow SHA")
        need(re.fullmatch(r"[1-9][0-9]*", str(producer.get("runId", ""))), "invalid producer run")


def image_artifact_name(source_sha, producer):
    if producer.get("kind") == "gcp":
        return f"fork-release-{source_sha}-gcp-{producer['operationId']}-{producer['attempt']}"
    return f"fork-release-{source_sha}-{producer['runId']}-{producer['attempt']}"


def private_root(path):
    root = Path(path).expanduser().absolute()
    if not root.exists():
        root.mkdir(mode=0o700, parents=True)
    stat = root.lstat()
    need(root.is_dir() and not root.is_symlink() and stat.st_uid == os.getuid() and stat.st_mode & 0o077 == 0, "private state root must be owned and mode 0700")
    return root


@contextmanager
def production_deploy_lock(path):
    """Join the operations repository's existing deployment serialization."""
    need(path is not None and path.is_absolute(), "shared production deploy lock path required")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise Refusal("shared production deploy lock is unavailable") from error
    with os.fdopen(descriptor, "rb") as lock:
        metadata = os.fstat(lock.fileno())
        need(stat.S_ISREG(metadata.st_mode), "shared production deploy lock is not a regular file")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise Refusal("another operations deployment holds the shared lock") from error
        yield


def atomic_json(path, value):
    fd, temporary = tempfile.mkstemp(prefix=".release-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)



def operation_id(state, phase):
    keys = ("manifestSha256", "inventorySha256", "baselineSha256", "backupPolicySha256", "imageDigest")
    return "fr-" + sha256((":".join(state[key] for key in keys) + ":" + phase).encode())[:32]

def load_state(path):
    if not path.exists():
        return None
    stat = path.lstat()
    need(path.is_file() and not path.is_symlink() and stat.st_uid == os.getuid() and stat.st_mode & 0o077 == 0, "unsafe private state file")
    state = read_json(path)
    need(type(state) is dict and state.get("schema") == "openclaw.fork-release-progress.v2", "wrong progress schema")
    need(matches(IDENT, state.get("candidate")) and matches(re.compile(r"[0-9a-f]{64}\Z"), state.get("manifestSha256")), "invalid progress identity")
    need(matches(re.compile(r"[0-9a-f]{64}\Z"), state.get("receiptSha256")) and matches(SHA, state.get("sourceSha")) and matches(DIGEST, state.get("imageDigest")), "invalid progress source or image")
    for key in ("inventorySha256", "baselineSha256", "backupPolicySha256"):
        need(matches(re.compile(r"[0-9a-f]{64}\Z"), state.get(key)), "invalid progress " + key)
    if "backupBindingSha256" in state:
        need(matches(re.compile(r"[0-9a-f]{64}\Z"), state[key]), "invalid backup binding")
    if "prEvidenceSha256" in state:
        need(matches(re.compile(r"[0-9a-f]{64}\Z"), state["prEvidenceSha256"]), "invalid PR evidence identity")
    need(state.get("phase") in (*PHASES, "awaiting_approval", "completed", "rolled_back", "needs_operator"), "invalid progress phase")
    need(state.get("approval") is None or matches(re.compile(r"[0-9a-f]{64}\Z"), state.get("approval")), "invalid approval record")
    steps = state.get("steps")
    need(type(steps) is dict and set(steps).issubset(PHASES), "invalid operation set")
    for phase, step in steps.items():
        expected = operation_id(state, phase)
        need(type(step) is dict and step.get("operationId") == expected, "operation identity changed")
        need(type(step.get("attempts")) is int and 0 <= step["attempts"] <= 2, "invalid operation attempt count")
        need(step.get("state") in ("pending", "issued", "succeeded", "failed"), "invalid operation state")
        if step["state"] == "succeeded":
            need(matches(IDENT, step.get("receiptId")), "missing operation receipt")
        if "rollbackFenceReceiptId" in step:
            need(phase in ("deploy", "health") and step["state"] == "failed" and matches(IDENT, step["rollbackFenceReceiptId"]), "invalid rollback fence")
    if "rollbackRequired" in state:
        need(type(state["rollbackRequired"]) is bool, "invalid rollback requirement")
    return state


def challenge(state):
    steps = state["steps"]
    need(all(steps.get(phase, {}).get("state") == "succeeded" for phase in ("backup", "restore", "rehearsal")), "backup, restore and rehearsal are not complete")
    need(matches(re.compile(r"[0-9a-f]{64}\Z"), state.get("backupBindingSha256")), "fresh backup admission is missing")
    material = [state["manifestSha256"], state["inventorySha256"], state["baselineSha256"],
                state["backupPolicySha256"], state["backupBindingSha256"],
                state["receiptSha256"], state.get("prEvidenceSha256", ""),
                state["imageDigest"], *(steps[phase]["receiptId"] for phase in ("backup", "restore", "rehearsal"))]
    return sha256("\n".join(material).encode())


def adapter_call(adapter, action, phase, operation_id, state, manifest_path, receipt_path, image_dir):
    command = [str(adapter), action, "--phase", phase, "--operation-id", operation_id,
               "--source-sha", state["sourceSha"], "--image-digest", state["imageDigest"],
               "--manifest", str(manifest_path), "--image-receipt", str(receipt_path), "--oci-dir", str(image_dir),
               "--inventory-sha256", state["inventorySha256"],
               "--baseline-sha256", state["baselineSha256"], "--backup-policy-sha256", state["backupPolicySha256"]]
    backup = state["steps"].get("backup", {}).get("receiptId")
    if backup:
        command += ["--backup-receipt", backup]
    restored = state["steps"].get("restore", {}).get("receiptId")
    if restored:
        command += ["--restore-receipt", restored]
    fence = next((state["steps"].get(name, {}).get("rollbackFenceReceiptId") for name in ("health", "deploy")
                  if state["steps"].get(name, {}).get("rollbackFenceReceiptId")), None)
    if fence:
        command += ["--rollback-fence-receipt", fence]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
    except subprocess.TimeoutExpired:
        return {"state": "unknown"}
    if result.returncode == 75:
        return {"state": "retryable"}
    if result.returncode:
        return {"state": "unknown"} if action == "invoke" else {"state": "retryable"}
    try:
        response = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise Refusal("adapter returned invalid JSON") from error
    need(type(response) is dict, "adapter returned invalid response")
    need(response.get("operationId") == operation_id, "adapter operation ID mismatch")
    for key in ("manifestSha256", "inventorySha256", "baselineSha256", "backupPolicySha256", "sourceSha", "imageDigest"):
        need(response.get(key) == state[key], "adapter binding changed: " + key)
    need(response.get("state") in ("not_found", "in_progress", "succeeded", "failed"), "adapter state invalid")
    if response["state"] == "succeeded":
        need(matches(IDENT, response.get("receiptId")), "adapter success lacks opaque receipt ID")
        if phase in ("rehearsal", "deploy", "health"):
            need(response.get("imageDigest") == state["imageDigest"], "adapter image digest changed")
    if response["state"] == "failed" and phase in ("deploy", "health") and response.get("rollbackSafe") is True:
        need(matches(IDENT, response.get("rollbackFenceReceiptId")), "safe rollback lacks one-writer fence receipt")
    return response


def reconcile_step(state, phase, adapter, manifest_path, receipt_path, image_dir, save, admission=None):
    if phase == "rollback":
        need(any(state["steps"].get(name, {}).get("rollbackFenceReceiptId") for name in ("deploy", "health")), "rollback lacks no-write fence proof")
    steps = state["steps"]
    step = steps.get(phase)
    if step is None:
        op_id = operation_id(state, phase)
        step = steps[phase] = {"operationId": op_id, "attempts": 0, "state": "pending"}
        save()
    if step["state"] == "succeeded":
        return "succeeded"
    for _ in range(3):
        response = adapter_call(adapter, "status", phase, step["operationId"], state, manifest_path, receipt_path, image_dir)
        if response["state"] != "retryable":
            break
    else:
        return "pending"
    if response["state"] == "not_found":
        if step["attempts"] >= 2:
            return "pending"
        if phase in ("rehearsal", "deploy"):
            need(callable(admission), "private backup admission interface required")
            admission(state)
            save()
        step["attempts"] += 1
        step["state"] = "issued"
        save()  # Persist the intent before the first possible mutation.
        response = adapter_call(adapter, "invoke", phase, step["operationId"], state, manifest_path, receipt_path, image_dir)
    if response["state"] == "succeeded":
        step["state"] = "succeeded"
        step["receiptId"] = response["receiptId"]
        save()
        return "succeeded"
    if response["state"] == "failed":
        step["state"] = "failed"
        if phase in ("deploy", "health") and response.get("rollbackSafe") is True:
            step["rollbackFenceReceiptId"] = response["rollbackFenceReceiptId"]
        save()
        return "rollback_safe_failure" if step.get("rollbackFenceReceiptId") else "failed"
    return "pending"


def advance(state, adapter, manifest_path, receipt_path, image_dir, save, admission=None):
    while True:
        phase = state["phase"]
        if phase in ("completed", "rolled_back", "blocked", "awaiting_approval", "needs_operator"):
            return
        if phase in ("rehearsal", "deploy"):
            need(callable(admission), "private backup admission interface required")
        result = reconcile_step(state, phase, adapter, manifest_path, receipt_path, image_dir, save, admission)
        if result == "pending":
            return
        if result in ("failed", "rollback_safe_failure"):
            state["rollbackRequired"] = result == "rollback_safe_failure"
            state["phase"] = "rollback" if state["rollbackRequired"] else "needs_operator"
            save()
            continue
        next_phase = {"backup": "restore", "restore": "rehearsal", "rehearsal": "awaiting_approval", "deploy": "health", "health": "cleanup", "rollback": "cleanup"}
        if phase == "cleanup":
            state["phase"] = "rolled_back" if state.get("rollbackRequired") else "completed"
        else:
            state["phase"] = next_phase[phase]
        save()



def private_inputs(baseline_path, policy_path):
    need(baseline_path is not None and policy_path is not None, "private baseline and backup policy required")
    baseline, policy = read_json(baseline_path), read_json(policy_path)
    import preflight
    checks = preflight.Checks()
    checks.fields(baseline, "sourceSha imageDigest mutableInventorySha256", "baseline.fields")
    if type(baseline) is dict:
        checks.need(matches(SHA, baseline.get("sourceSha")), "baseline.source")
        checks.need(matches(DIGEST, baseline.get("imageDigest")), "baseline.image")
        checks.need(matches(preflight.HEX256, baseline.get("mutableInventorySha256")), "baseline.mutable_inventory")
    if checks.fields(policy, "schema maxAgeSeconds retainSeconds", "backup.policy.fields"):
        checks.need(policy["schema"] == "openclaw.fork-backup-policy.v1", "backup.policy.schema")
        for key in ("maxAgeSeconds", "retainSeconds"):
            checks.need(type(policy[key]) is int and policy[key] > 0, "backup.policy." + key)
    need(not checks.errors, "preflight: " + ", ".join(sorted(set(checks.errors))))
    return baseline, policy, sha256(Path(baseline_path).read_bytes()), sha256(Path(policy_path).read_bytes())


def backup_admission(adapter, state, manifest_path, receipt_path, image_dir, baseline, policy, now=None):
    """The private adapter reobserves archive facts and live baseline; no mutation."""
    import preflight
    command = [str(adapter), "admit", "--phase", state["phase"],
               "--source-sha", state["sourceSha"], "--image-digest", state["imageDigest"],
               "--manifest", str(manifest_path), "--image-receipt", str(receipt_path),
               "--oci-dir", str(image_dir)]
    for key, flag in (("inventorySha256", "inventory-sha256"), ("baselineSha256", "baseline-sha256"),
                      ("backupPolicySha256", "backup-policy-sha256")):
        command += ["--" + flag, state[key]]
    for phase in ("backup", "restore"):
        value = state["steps"].get(phase, {}).get("receiptId")
        need(matches(IDENT, value), "backup and restore receipts required for admission")
        command += ["--" + phase + "-receipt", value]
    try:
        response = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    except subprocess.TimeoutExpired as error:
        raise Refusal("private admission timed out") from error
    need(response.returncode == 0, "private admission unavailable")
    try:
        value = json.loads(response.stdout)
    except ValueError as error:
        raise Refusal("private admission JSON invalid") from error
    now = now or preflight.datetime.now(preflight.timezone.utc)
    checks = preflight.Checks()
    if checks.fields(value, "schema manifestSha256 inventorySha256 baselineSha256 backupPolicySha256 sourceSha imageDigest checkedAt evidence", "admission.fields"):
        checks.need(value["schema"] == "openclaw.fork-private-admission.v1", "admission.schema")
        for key in ("manifestSha256", "inventorySha256", "baselineSha256", "backupPolicySha256", "sourceSha", "imageDigest"):
            checks.need(value[key] == state[key], "admission." + key)
        observed = checks.timestamp(value["checkedAt"], "admission.checked_at")
        if observed:
            checks.need(0 <= (now - observed).total_seconds() <= 60, "admission.stale")
        preflight.backup_checks(checks, value["evidence"], baseline, state["imageDigest"],
                                now, policy["maxAgeSeconds"], policy["retainSeconds"])
        if type(value["evidence"]) is dict:
            for phase, field in (("backup", "archive"), ("restore", "restore")):
                item = value["evidence"].get(field)
                checks.need(type(item) is dict and item.get("receiptId") == state["steps"][phase]["receiptId"],
                            "admission." + phase + ".receipt")
    need(not checks.errors, "preflight: " + ", ".join(sorted(set(checks.errors))))
    evidence = value["evidence"]
    # verifiedAt and checkedAt may advance; immutable backup/restore identity must not.
    bound = {**evidence, "archive": {key: item for key, item in evidence["archive"].items() if key != "verifiedAt"}}
    binding = sha256(json.dumps(bound, sort_keys=True, separators=(",", ":")).encode())
    need(state.get("backupBindingSha256", binding) == binding, "backup identity changed after rehearsal")
    state["backupBindingSha256"] = binding

def human_status(state):
    if state is None:
        return "Release has not started."
    lines = [f"Candidate: {state['candidate']}", f"Source: {state['sourceSha']}",
             f"Image: {state['imageDigest']}", f"Phase: {state['phase']}"]
    for phase in PHASES:
        step = state["steps"].get(phase)
        if step:
            lines.append(f"{phase}: {step['state']} (operation {step['operationId']}, attempts {step['attempts']})")
    if state["phase"] == "awaiting_approval":
        lines.append(f"Production approval challenge: {challenge(state)}")
    return "\n".join(lines)


def validation_node_version(inventory):
    """Keep retained workflow runtime; select the supported future stable lanes."""
    upstream = inventory.get("upstream")
    return "24.22.1" if upstream and upstream["tag"] in ("v2026.10.6", "v2026.10.7", "v2026.10.8") else "24.21.0"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("identity", "source-check", "gates", "status", "run", "approve"))
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--source-dir", type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--backup-policy", type=Path)
    parser.add_argument("--private-root", type=Path)
    parser.add_argument("--image-receipt", type=Path)
    parser.add_argument("--pr-evidence", type=Path)
    parser.add_argument("--oci-dir", type=Path)
    parser.add_argument("--adapter", type=Path)
    parser.add_argument("--shared-deploy-lock", type=Path)
    parser.add_argument("--challenge")
    args = parser.parse_args()
    manifest, manifest_hash = manifest_at(args.manifest)
    import preflight
    inventory, inventory_hash = preflight.inventory_at(args.inventory, manifest, manifest_hash)
    if args.command == "identity":
        print(f"source_sha={manifest['source']['commit']}")
        print(f"node_version={validation_node_version(inventory)}")
        print(f"extensions={manifest['image']['extensions']}")
        print(f"manifest_sha256={manifest_hash}")
        print(f"inventory_sha256={inventory_hash}")
        print("history_commits=" + " ".join(preflight.history_commits(inventory, manifest)))
        print(f"upstream_tag={inventory['upstream']['tag'] if inventory['upstream'] else ''}")
        print(f"review_base_sha={manifest.get('review', {}).get('baseSha', '')}")
        print(f"review_pr_number={manifest.get('review', {}).get('prNumber', '')}")
        return
    if args.command == "source-check":
        need(args.source_dir is not None, "source checkout required")
        preflight.inventory_at(args.inventory, manifest, manifest_hash, args.source_dir)
        check_source(manifest, args.source_dir)
        print(f"Exact source and {len(manifest['source']['patches'])} declared integration/patch entries verified.")
        return
    if args.command == "gates":
        for lane in ("patchLifecycle", "producerConsumer"):
            print(*manifest["gates"][lane], sep="\n")
        return
    need(args.private_root is not None, "private state root required")
    if args.command == "status":
        root = private_root(args.private_root)
        state_path = root / f"{manifest['candidate']}.json"
        print(human_status(load_state(state_path)))
        return
    need(args.image_receipt is not None, "exact image receipt required")
    need(args.source_dir is not None, "exact source checkout required before private operations")
    preflight.inventory_at(args.inventory, manifest, manifest_hash, args.source_dir)
    receipt = receipt_at(args.image_receipt, manifest, manifest_hash, inventory_hash)
    baseline, policy, baseline_hash, policy_hash = private_inputs(args.baseline, args.backup_policy)
    receipt_hash = sha256(args.image_receipt.read_bytes())
    pr_evidence_hash = None
    if manifest.get("review") is not None:
        need(args.pr_evidence is not None, "exact PR check evidence required")
        import pr as pr_checks

        evidence = read_json(args.pr_evidence)
        need(type(evidence) is dict, "invalid PR evidence object")
        need(evidence.get("schema") == "openclaw.fork-task-pr-evidence.v1" and evidence.get("kind") == "release", "wrong PR check evidence")
        need(evidence.get("inventorySha256") == inventory_hash and evidence.get("manifestSha256") == manifest_hash and evidence.get("sourceSha") == manifest["source"]["commit"] and evidence.get("sourceTree") == manifest["source"]["tree"], "PR check source differs from release")
        review = manifest["review"]
        need(evidence.get("prNumber") == review["prNumber"] and evidence.get("baseSha") == review["baseSha"] and evidence.get("changedDiffSha256") == review["changedDiffSha256"], "PR check review binding differs")
        need(evidence.get("headSha") == receipt["review"]["headSha"], "PR check head differs from tested image")
        assessed = pr_checks.assess_live(evidence)
        need(assessed["reviewState"] == "approved_exact_head", "current PR approval is missing")
        pr_evidence_hash = sha256(args.pr_evidence.read_bytes())
    need(manifest["productionEligible"], "seed manifest is not production eligible")
    if args.command in ("run", "approve"):
        need(args.adapter is not None and args.oci_dir is not None, "adapter and OCI artifact required")
        need(args.adapter.is_absolute() and args.adapter.is_file() and os.access(args.adapter, os.X_OK), "invalid adapter executable")
        check = subprocess.run(["node", str(Path(__file__).with_name("image.mjs")), "verify", str(args.manifest), str(args.inventory), str(args.image_receipt), str(args.oci_dir)], check=False)
        need(check.returncode == 0, "OCI artifact does not match image receipt")
    root = private_root(args.private_root)
    state_path = root / f"{manifest['candidate']}.json"
    lock_path = root / "production.lock"
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "r+", encoding="utf-8") as lock:
        os.fchmod(lock.fileno(), 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise Refusal("another production operation holds the lock") from error
        state = load_state(state_path)
        if state is None:
            need(args.command == "run", "no prepared release exists")
            state = {"schema": "openclaw.fork-release-progress.v2", "candidate": manifest["candidate"],
                     "manifestSha256": manifest_hash, "inventorySha256": inventory_hash,
                     "baselineSha256": baseline_hash, "backupPolicySha256": policy_hash,
                     "sourceSha": manifest["source"]["commit"],
                     "receiptSha256": receipt_hash, "imageDigest": receipt["indexDigest"],
                     **({"prEvidenceSha256": pr_evidence_hash} if pr_evidence_hash else {}),
                     "phase": "backup", "steps": {}, "approval": None}
            atomic_json(state_path, state)
        need(state["manifestSha256"] == manifest_hash and state["receiptSha256"] == receipt_hash and state["sourceSha"] == receipt["sourceSha"] and state["imageDigest"] == receipt["indexDigest"], "progress identity changed")
        need(state.get("prEvidenceSha256") == pr_evidence_hash, "PR check evidence changed")
        need(state["inventorySha256"] == inventory_hash and state["baselineSha256"] == baseline_hash and state["backupPolicySha256"] == policy_hash, "private admission inputs changed")
        def admission(current):
            backup_admission(args.adapter, current, args.manifest, args.image_receipt, args.oci_dir, baseline, policy)
        if args.command == "approve":
            admission(state)
            need(state["phase"] == "awaiting_approval" and args.challenge == challenge(state), "approval challenge differs from exact rehearsed release")
            state["approval"] = args.challenge
            state["phase"] = "deploy"
            atomic_json(state_path, state)
        else:
            def save():
                atomic_json(state_path, state)

            if state["phase"] in ("deploy", "health", "rollback", "cleanup", "completed", "rolled_back"):
                need(state["approval"] == challenge(state), "production approval no longer matches rehearsal")
            if state["phase"] in ("deploy", "health", "rollback", "cleanup"):
                with production_deploy_lock(args.shared_deploy_lock):
                    advance(state, args.adapter, args.manifest, args.image_receipt, args.oci_dir, save, admission)
            else:
                advance(state, args.adapter, args.manifest, args.image_receipt, args.oci_dir, save, admission)
        print(human_status(state))


if __name__ == "__main__":
    # Keep Refusal identity consistent when preflight imports this CLI module.
    sys.modules["release"] = sys.modules[__name__]
    try:
        main()
    except (Refusal, OSError, subprocess.CalledProcessError, ValueError, KeyError) as error:
        print(f"Fork release refused: {error}", file=sys.stderr)
        sys.exit(1)

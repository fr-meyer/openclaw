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
    need(type(source) is dict and set(source) == {"baseCommit", "baseTree", "patches", "commit", "tree"}, "invalid source fields")
    for name in ("baseCommit", "baseTree", "commit", "tree"):
        need(matches(SHA, source.get(name)), f"invalid source {name}")
    patches = source.get("patches")
    need(type(patches) is list and 1 <= len(patches) <= 64, "invalid patch chain length")
    for patch in patches:
        need(type(patch) is dict and set(patch) == {"commit", "tree"}, "invalid patch entry")
        need(matches(SHA, patch["commit"]) and matches(SHA, patch["tree"]), "invalid patch identity")
    need(patches[-1] == {"commit": source["commit"], "tree": source["tree"]}, "final patch differs from source")
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
    result = subprocess.run(["git", "-C", str(source_dir), *args], capture_output=True, text=True, check=True)
    return result.stdout.strip()


def check_source(manifest, source_dir):
    source = manifest["source"]
    need(git(source_dir, "rev-parse", "HEAD") == source["commit"], "checkout is not the pinned source commit")
    chain = [(source["baseCommit"], source["baseTree"])] + [
        (patch["commit"], patch["tree"]) for patch in source["patches"]
    ]
    for index, (commit, tree) in enumerate(chain):
        need(git(source_dir, "rev-parse", f"{commit}^{{tree}}") == tree, "source tree changed")
        if index:
            need(git(source_dir, "rev-parse", f"{commit}^1") == chain[index - 1][0], "patch parent changed")
            need(git(source_dir, "show", "-s", "--format=%P", commit) == chain[index - 1][0], "patch is a merge")
    for lane in ("patchLifecycle", "producerConsumer"):
        for test in manifest["gates"][lane]:
            need(git(source_dir, "cat-file", "-e", f"{source['commit']}:{test}") == "", f"missing pinned test: {test}")
    return chain


def receipt_at(path, manifest, manifest_hash):
    receipt = read_json(path)
    need(type(receipt) is dict and receipt.get("schema") == "openclaw.fork-release-image.v1", "wrong image receipt schema")
    need(receipt.get("manifestSha256") == manifest_hash, "image receipt is for another manifest")
    need(receipt.get("repository") == manifest["repository"], "image receipt repository mismatch")
    need(receipt.get("sourceSha") == manifest["source"]["commit"], "image receipt source mismatch")
    need(receipt.get("sourceTree") == manifest["source"]["tree"], "image receipt tree mismatch")
    need(receipt.get("architecture") == manifest["image"]["architecture"], "image architecture mismatch")
    for name in ("indexDigest", "imageDigest", "configDigest"):
        need(matches(DIGEST, receipt.get(name)), f"invalid {name}")
    producer = receipt.get("producer", {})
    need(type(producer) is dict and matches(SHA, producer.get("workflowSha")), "invalid producer workflow SHA")
    need(re.fullmatch(r"[1-9][0-9]*", str(producer.get("runId", ""))), "invalid producer run")
    need(re.fullmatch(r"[1-9][0-9]*", str(producer.get("attempt", ""))), "invalid producer attempt")
    need(receipt.get("artifactName") == f"fork-release-{receipt['sourceSha']}-{producer['runId']}-{producer['attempt']}", "image artifact name mismatch")
    if manifest.get("review") is not None:
        review = receipt.get("review", {})
        need(type(review) is dict and matches(SHA, review.get("headSha")), "image receipt lacks exact PR head")
        for key in ("prNumber", "baseSha", "changedDiffSha256"):
            need(review.get(key) == manifest["review"][key], f"image PR {key} mismatch")
    return receipt


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


def load_state(path):
    if not path.exists():
        return None
    stat = path.lstat()
    need(path.is_file() and not path.is_symlink() and stat.st_uid == os.getuid() and stat.st_mode & 0o077 == 0, "unsafe private state file")
    state = read_json(path)
    need(type(state) is dict and state.get("schema") == "openclaw.fork-release-progress.v1", "wrong progress schema")
    need(matches(IDENT, state.get("candidate")) and matches(re.compile(r"[0-9a-f]{64}\Z"), state.get("manifestSha256")), "invalid progress identity")
    need(matches(re.compile(r"[0-9a-f]{64}\Z"), state.get("receiptSha256")) and matches(SHA, state.get("sourceSha")) and matches(DIGEST, state.get("imageDigest")), "invalid progress source or image")
    if "prEvidenceSha256" in state:
        need(matches(re.compile(r"[0-9a-f]{64}\Z"), state["prEvidenceSha256"]), "invalid PR evidence identity")
    need(state.get("phase") in (*PHASES, "awaiting_approval", "completed", "rolled_back", "needs_operator"), "invalid progress phase")
    need(state.get("approval") is None or matches(re.compile(r"[0-9a-f]{64}\Z"), state.get("approval")), "invalid approval record")
    steps = state.get("steps")
    need(type(steps) is dict and set(steps).issubset(PHASES), "invalid operation set")
    for phase, step in steps.items():
        expected = "fr-" + sha256(f"{state['manifestSha256']}:{state['imageDigest']}:{phase}".encode())[:32]
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
    material = [state["manifestSha256"], state["receiptSha256"], state.get("prEvidenceSha256", ""),
                state["imageDigest"], *(steps[phase]["receiptId"] for phase in ("backup", "restore", "rehearsal"))]
    return sha256("\n".join(material).encode())


def adapter_call(adapter, action, phase, operation_id, state, manifest_path, receipt_path, image_dir):
    command = [str(adapter), action, "--phase", phase, "--operation-id", operation_id,
               "--source-sha", state["sourceSha"], "--image-digest", state["imageDigest"],
               "--manifest", str(manifest_path), "--image-receipt", str(receipt_path), "--oci-dir", str(image_dir)]
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
    need(response.get("state") in ("not_found", "in_progress", "succeeded", "failed"), "adapter state invalid")
    if response["state"] == "succeeded":
        need(matches(IDENT, response.get("receiptId")), "adapter success lacks opaque receipt ID")
        if phase in ("rehearsal", "deploy", "health"):
            need(response.get("imageDigest") == state["imageDigest"], "adapter image digest changed")
    if response["state"] == "failed" and phase in ("deploy", "health") and response.get("rollbackSafe") is True:
        need(matches(IDENT, response.get("rollbackFenceReceiptId")), "safe rollback lacks one-writer fence receipt")
    return response


def reconcile_step(state, phase, adapter, manifest_path, receipt_path, image_dir, save):
    if phase == "rollback":
        need(any(state["steps"].get(name, {}).get("rollbackFenceReceiptId") for name in ("deploy", "health")), "rollback lacks no-write fence proof")
    steps = state["steps"]
    step = steps.get(phase)
    if step is None:
        operation_id = "fr-" + sha256(f"{state['manifestSha256']}:{state['imageDigest']}:{phase}".encode())[:32]
        step = steps[phase] = {"operationId": operation_id, "attempts": 0, "state": "pending"}
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


def advance(state, adapter, manifest_path, receipt_path, image_dir, save):
    while True:
        phase = state["phase"]
        if phase in ("completed", "rolled_back", "blocked", "awaiting_approval", "needs_operator"):
            return
        result = reconcile_step(state, phase, adapter, manifest_path, receipt_path, image_dir, save)
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("identity", "source-check", "gates", "status", "run", "approve"))
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--source-dir", type=Path)
    parser.add_argument("--private-root", type=Path)
    parser.add_argument("--image-receipt", type=Path)
    parser.add_argument("--pr-evidence", type=Path)
    parser.add_argument("--oci-dir", type=Path)
    parser.add_argument("--adapter", type=Path)
    parser.add_argument("--shared-deploy-lock", type=Path)
    parser.add_argument("--challenge")
    args = parser.parse_args()
    manifest, manifest_hash = manifest_at(args.manifest)
    if args.command == "identity":
        print(f"source_sha={manifest['source']['commit']}")
        print(f"extensions={manifest['image']['extensions']}")
        print(f"manifest_sha256={manifest_hash}")
        print(f"review_base_sha={manifest.get('review', {}).get('baseSha', '')}")
        return
    if args.command == "source-check":
        need(args.source_dir is not None, "source checkout required")
        check_source(manifest, args.source_dir)
        print(f"Exact source and {len(manifest['source']['patches'])} ordered patches verified.")
        return
    if args.command == "gates":
        for lane in ("patchLifecycle", "producerConsumer"):
            print(*manifest["gates"][lane], sep="\n")
        return
    need(args.private_root is not None, "private state root required")
    root = private_root(args.private_root)
    state_path = root / f"{manifest['candidate']}.json"
    if args.command == "status":
        print(human_status(load_state(state_path)))
        return
    need(args.image_receipt is not None, "exact image receipt required")
    receipt = receipt_at(args.image_receipt, manifest, manifest_hash)
    receipt_hash = sha256(args.image_receipt.read_bytes())
    pr_evidence_hash = None
    if manifest.get("review") is not None:
        need(args.pr_evidence is not None, "exact PR check evidence required")
        import pr as pr_checks

        evidence = read_json(args.pr_evidence)
        need(evidence.get("schema") == "openclaw.fork-task-pr-evidence.v1" and evidence.get("kind") == "release", "wrong PR check evidence")
        need(evidence.get("manifestSha256") == manifest_hash and evidence.get("sourceSha") == manifest["source"]["commit"] and evidence.get("sourceTree") == manifest["source"]["tree"], "PR check source differs from release")
        review = manifest["review"]
        need(evidence.get("prNumber") == review["prNumber"] and evidence.get("baseSha") == review["baseSha"] and evidence.get("changedDiffSha256") == review["changedDiffSha256"], "PR check review binding differs")
        need(evidence.get("headSha") == receipt["review"]["headSha"], "PR check head differs from tested image")
        assessed = pr_checks.assess_live(evidence)
        need(assessed["reviewState"] == "approved_exact_head", "current PR approval is missing")
        pr_evidence_hash = sha256(args.pr_evidence.read_bytes())
    need(manifest["productionEligible"], "seed manifest is not production eligible")
    if args.command == "run":
        need(args.adapter is not None and args.oci_dir is not None, "adapter and OCI artifact required")
        need(args.adapter.is_absolute() and args.adapter.is_file() and os.access(args.adapter, os.X_OK), "invalid adapter executable")
        check = subprocess.run(["node", str(Path(__file__).with_name("image.mjs")), "verify", str(args.manifest), str(args.image_receipt), str(args.oci_dir)], check=False)
        need(check.returncode == 0, "OCI artifact does not match image receipt")
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
            state = {"schema": "openclaw.fork-release-progress.v1", "candidate": manifest["candidate"],
                     "manifestSha256": manifest_hash, "sourceSha": manifest["source"]["commit"],
                     "receiptSha256": receipt_hash, "imageDigest": receipt["indexDigest"],
                     **({"prEvidenceSha256": pr_evidence_hash} if pr_evidence_hash else {}),
                     "phase": "backup", "steps": {}, "approval": None}
            atomic_json(state_path, state)
        need(state["manifestSha256"] == manifest_hash and state["receiptSha256"] == receipt_hash and state["sourceSha"] == receipt["sourceSha"] and state["imageDigest"] == receipt["indexDigest"], "progress identity changed")
        need(state.get("prEvidenceSha256") == pr_evidence_hash, "PR check evidence changed")
        if args.command == "approve":
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
                    advance(state, args.adapter, args.manifest, args.image_receipt, args.oci_dir, save)
            else:
                advance(state, args.adapter, args.manifest, args.image_receipt, args.oci_dir, save)
        print(human_status(state))


if __name__ == "__main__":
    try:
        main()
    except (Refusal, OSError, subprocess.CalledProcessError, ValueError, KeyError) as error:
        print(f"Fork release refused: {error}", file=sys.stderr)
        sys.exit(1)

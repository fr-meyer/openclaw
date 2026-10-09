import copy
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import pr


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


def fixture(root):
    git(root, "init", "-q")
    git(root, "config", "user.email", "release-test@example.invalid")
    git(root, "config", "user.name", "Release Test")
    (root / "src").mkdir()
    (root / "src/a.test.ts").write_text("test('a', () => {});\n")
    (root / "src/b.test.ts").write_text("test('b', () => {});\n")
    (root / "product.txt").write_text("before\n")
    git(root, "add", ".")
    git(root, "commit", "-qm", "base")
    base = git(root, "rev-parse", "HEAD")
    base_tree = git(root, "rev-parse", "HEAD^{tree}")
    (root / "product.txt").write_text("after\n")
    git(root, "add", "product.txt")
    git(root, "commit", "-qm", "product")
    source = git(root, "rev-parse", "HEAD")
    source_tree = git(root, "rev-parse", "HEAD^{tree}")
    changed_digest = pr.sha256(subprocess.run(
        ["git", "-C", str(root), "diff", "--binary", "--full-index", "--no-ext-diff", base, source],
        check=True, capture_output=True).stdout)
    manifest = {
        "schema": "openclaw.fork-release.v1", "repository": "fr-meyer/openclaw",
        "candidate": "test-release", "productionEligible": True,
        "source": {"baseCommit": base, "baseTree": base_tree,
                   "patches": [{"commit": source, "tree": source_tree}],
                   "commit": source, "tree": source_tree},
        "gates": {"patchLifecycle": ["src/a.test.ts"],
                  "producerConsumer": ["src/b.test.ts"]},
        "image": {"architecture": "amd64", "extensions": "codex"},
        "review": {"prNumber": 7, "baseSha": base,
                   "changedDiffSha256": changed_digest},
    }
    manifest_path = root / "scripts/fork-release/manifest.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(json.dumps(manifest) + "\n")
    git(root, "add", "scripts/fork-release/manifest.json")
    git(root, "commit", "-qm", "manifest seal")
    head = git(root, "rev-parse", "HEAD")
    body = pr.template("release", "fr-meyer", "main", "Test release candidate", [])
    event = {
        "action": "synchronize", "repository": {"full_name": "fr-meyer/openclaw"},
        "pull_request": {"number": 7, "draft": True, "body": body,
                         "user": {"login": "fr-meyer"},
                         "head": {"sha": head, "ref": "candidate/test-release",
                                  "repo": {"full_name": "fr-meyer/openclaw"}},
                         "base": {"sha": base, "ref": "main",
                                  "repo": {"full_name": "fr-meyer/openclaw"}}},
    }
    run = {"runId": 91, "attempt": 1, "checkRunId": 101,
           "workflowSha": "d" * 40}
    return manifest_path, event, run


class PrTests(unittest.TestCase):
    def test_offline_seal_has_ordered_ancestry_after_bounded_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "origin"
            root.mkdir()
            manifest_path, event, _ = fixture(root)
            checkout = Path(directory) / "tooling"
            workflow = (Path(__file__).resolve().parents[2] /
                        ".github/workflows/fork-release-pipeline.yml").read_text()
            tooling_step = workflow.split("- name: Checkout trusted pipeline tooling", 1)[1].split(
                "- name:", 1)[0]
            depth = re.search(r"fetch-depth:\s*(\d+)", tooling_step)
            self.assertIsNotNone(depth)
            subprocess.run(["git", "clone", "--quiet", f"--depth={depth.group(1)}", root.as_uri(),
                            str(checkout)], check=True, capture_output=True)
            git(checkout, "fetch", "--no-tags", "--depth=1", "origin",
                event["pull_request"]["base"]["sha"])
            checked = pr.offline_release_seal(
                checkout / "scripts/fork-release/manifest.json", checkout)
            self.assertEqual(checked["sourceSha"],
                             json.loads(manifest_path.read_text())["source"]["commit"])

    def test_opening_preflight_requires_guard_on_exact_base_and_security_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            git(root, "init", "-q")
            git(root, "config", "user.email", "release-test@example.invalid")
            git(root, "config", "user.name", "Release Test")
            guard = (Path(__file__).resolve().parents[2] / ".github/workflows/clawsweeper-dispatch.yml").read_text()
            (workflows / "clawsweeper-dispatch.yml").write_text(guard)
            (workflows / "security-review.yml").write_text(
                "on:\n  pull_request_target:\n    types: [opened]\npermissions:\n  statuses: write\n"
                "jobs:\n  review:\n    permissions:\n      pull-requests: write\n")
            git(root, "add", ".")
            git(root, "commit", "-qm", "guarded base")
            base = git(root, "rev-parse", "HEAD")
            self.assertEqual(pr.opening_preflight(root, base)["forkDraftExternalDispatch"],
                             "blocked_by_base_guard")
            with self.assertRaisesRegex(pr.Refusal, "differs from declared PR base"):
                pr.opening_preflight(root, "0" * 40)
            (workflows / "clawsweeper-dispatch.yml").write_text(
                guard.replace("github.event.pull_request.draft == false", "true"))
            git(root, "add", ".")
            git(root, "commit", "-qm", "unguarded base")
            with self.assertRaisesRegex(pr.Refusal, "can dispatch a fork draft"):
                pr.opening_preflight(root, git(root, "rev-parse", "HEAD"))
            (workflows / "clawsweeper-dispatch.yml").write_text(guard)
            (workflows / "security-review.yml").write_text("on:\n  pull_request_target:\n")
            git(root, "add", ".")
            git(root, "commit", "-qm", "missing security gate")
            with self.assertRaisesRegex(pr.Refusal, "security review gate is missing"):
                pr.opening_preflight(root, git(root, "rev-parse", "HEAD"))

    def test_fork_draft_dispatch_guard_preserves_ready_and_upstream_events(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/clawsweeper-dispatch.yml").read_text()
        self.assertIn("pull_request_target:", workflow)
        self.assertIn("ready_for_review", workflow)
        self.assertRegex(workflow, re.compile(
            r"github\.repository != 'fr-meyer/openclaw'\s*\|\|\s*"
            r"github\.event_name != 'pull_request_target'\s*\|\|\s*"
            r"github\.event\.pull_request\.draft == false"
        ))

    def test_draft_release_pr_binds_exact_head_base_and_diff(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, event, run = fixture(root)
            evidence = pr.release_seal(pr.intake(event, run), manifest_path, root)
            self.assertTrue(evidence["draft"])
            self.assertEqual(evidence["headSha"], git(root, "rev-parse", "HEAD"))
            self.assertEqual(evidence["sourceSha"], git(root, "rev-parse", "HEAD^"))
            self.assertEqual(pr.offline_release_seal(manifest_path, root)["changedDiffSha256"],
                             evidence["changedDiffSha256"])
            self.assertEqual(pr.validate_binding(manifest_path, root)["sourceSha"],
                             evidence["sourceSha"])

    def test_generated_binding_rejects_stale_hash_and_cross_candidate_rebinding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, event, _ = fixture(root)
            base = event["pull_request"]["base"]["sha"]
            source = git(root, "rev-parse", "HEAD^")
            proposal_source = root / "binding-source.json"
            proposal_source.write_text(manifest_path.read_text())
            branch = git(root, "branch", "--show-current")
            git(root, "checkout", "-q", source)
            generated = pr.generate_binding(proposal_source, root, "test-release", 7, base)
            self.assertEqual(generated["source"]["commit"], source)
            self.assertEqual(generated["review"]["changedDiffSha256"],
                             json.loads(proposal_source.read_text())["review"]["changedDiffSha256"])
            with self.assertRaisesRegex(pr.Refusal, "candidate identity"):
                pr.generate_binding(proposal_source, root, "another-candidate", 7, base)
            with self.assertRaisesRegex(pr.Refusal, "cannot be silently changed"):
                pr.generate_binding(proposal_source, root, "test-release", 8, base)
            git(root, "checkout", "-q", branch)
            changed = json.loads(manifest_path.read_text())
            changed["review"]["changedDiffSha256"] = "0" * 64
            manifest_path.write_text(json.dumps(changed) + "\n")
            with self.assertRaisesRegex(pr.Refusal, "changed diff binding is stale"):
                pr.validate_binding(manifest_path, root)
            changed["review"]["changedDiffSha256"] = generated["review"]["changedDiffSha256"]
            changed["source"]["baseTree"] = "0" * 40
            manifest_path.write_text(json.dumps(changed) + "\n")
            with self.assertRaisesRegex(pr.Refusal, "source binding is stale"):
                pr.validate_binding(manifest_path, root)

    def test_reseal_of_same_product_diff_can_reuse_diff_review(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, event, run = fixture(root)
            before = pr.release_seal(pr.intake(event, run), manifest_path, root)
            manifest = json.loads(manifest_path.read_text())
            manifest["candidate"] = "test-release-resealed"
            manifest_path.write_text(json.dumps(manifest) + "\n")
            git(root, "add", "scripts/fork-release/manifest.json")
            git(root, "commit", "--amend", "-qm", "manifest seal")
            event["pull_request"]["head"]["sha"] = git(root, "rev-parse", "HEAD")
            after = pr.release_seal(pr.intake(event, run), manifest_path, root)
            self.assertNotEqual(before["headSha"], after["headSha"])
            self.assertTrue(pr.reusable_changed_diff(before, after))
            event["pull_request"]["base"]["sha"] = "f" * 40
            with self.assertRaisesRegex(pr.Refusal, "manifest PR/base"):
                pr.release_seal(pr.intake(event, run), manifest_path, root)

    def test_exact_review_and_check_expire_when_head_moves(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, event, run_context = fixture(root)
            evidence = pr.release_seal(pr.intake(event, run_context), manifest_path, root)
            current = {
                "number": 7, "state": "open", "body": event["pull_request"]["body"],
                "user": {"login": "fr-meyer"},
                "head": {"sha": evidence["headSha"], "ref": "candidate/test-release",
                         "repo": {"full_name": "fr-meyer/openclaw"}},
                "base": {"sha": evidence["baseSha"], "ref": "main",
                         "repo": {"full_name": "fr-meyer/openclaw"}},
            }
            reviews = [{"id": 1, "submitted_at": "2026-10-09T00:00:00Z",
                        "user": {"login": "reviewer"}, "state": "APPROVED",
                        "commit_id": evidence["headSha"]}]
            run = {"id": 91, "run_attempt": 1, "event": "pull_request",
                   "conclusion": "success", "head_branch": "candidate/test-release",
                   "repository": {"full_name": "fr-meyer/openclaw"},
                   "path": pr.WORKFLOW}
            jobs = [{"check_run_url": "https://api.github.com/repos/fr-meyer/openclaw/check-runs/101",
                     "conclusion": "success"}]
            self.assertEqual(pr.assess_current(evidence, current, reviews, run, jobs)["reviewState"],
                             "approved_exact_head")
            prefix = "repos/fr-meyer/openclaw"
            snapshots = {
                f"{prefix}/pulls/7": current,
                f"{prefix}/actions/runs/91": run,
                f"{prefix}/pulls/7/reviews?per_page=100&page=1": reviews,
                f"{prefix}/actions/runs/91/attempts/1/jobs?per_page=100&page=1": {"jobs": jobs},
            }
            self.assertFalse(pr.assess_live(evidence, snapshots.__getitem__)["mergeAuthorized"])
            changed_body = copy.deepcopy(current)
            changed_body["body"] = pr.template("release", "fr-meyer", "main",
                                               "Test release candidate",
                                               ["12:" + "a" * 40])
            with self.assertRaisesRegex(pr.Refusal, "PR intent changed"):
                pr.assess_current(evidence, changed_body, reviews, run, jobs)
            snapshots[f"{prefix}/pulls/7"] = changed_body
            with self.assertRaisesRegex(pr.Refusal, "PR intent changed"):
                pr.assess_live(evidence, snapshots.__getitem__)
            snapshots[f"{prefix}/pulls/7"] = current
            dependent = copy.deepcopy(evidence)
            dependent["dependsOn"] = [{"number": 12, "headSha": "a" * 40}]
            dependent_current = copy.deepcopy(current)
            dependent_current["body"] = changed_body["body"]
            snapshots[f"{prefix}/pulls/7"] = dependent_current
            snapshots[f"{prefix}/pulls/12"] = {
                "number": 12, "head": {"sha": "a" * 40},
                "base": {"ref": "main", "repo": {"full_name": "fr-meyer/openclaw"}},
                "state": "open", "merged_at": None,
            }
            with self.assertRaisesRegex(pr.Refusal, "dependency is not merged"):
                pr.assess_live(dependent, snapshots.__getitem__)
            snapshots[f"{prefix}/pulls/7"] = current
            moved = copy.deepcopy(current)
            moved["head"]["sha"] = "e" * 40
            with self.assertRaisesRegex(pr.Refusal, "head/base advanced"):
                pr.assess_current(evidence, moved, reviews, run, jobs)
            moved = copy.deepcopy(current)
            moved["base"]["sha"] = "e" * 40
            with self.assertRaisesRegex(pr.Refusal, "head/base advanced"):
                pr.assess_current(evidence, moved, reviews, run, jobs)
            failed_jobs = copy.deepcopy(jobs)
            failed_jobs[0]["conclusion"] = "failure"
            with self.assertRaisesRegex(pr.Refusal, "exact PR check"):
                pr.assess_current(evidence, current, reviews, run, failed_jobs)
            reviews.append({"id": 2, "submitted_at": "2026-10-09T00:01:00Z",
                            "user": {"login": "reviewer"}, "state": "CHANGES_REQUESTED",
                            "commit_id": evidence["headSha"]})
            with self.assertRaisesRegex(pr.Refusal, "change request"):
                pr.assess_current(evidence, current, reviews, run, jobs)

    def test_task_intent_requires_owner_and_declared_dependency(self):
        body = pr.template("task", "fr-meyer", "main", "Isolated work", ["12:" + "a" * 40])
        event = {"action": "opened", "repository": {"full_name": "fr-meyer/openclaw"},
                 "pull_request": {"number": 13, "draft": True, "body": body,
                                  "user": {"login": "fr-meyer"},
                                  "head": {"sha": "b" * 40, "ref": "task/isolate-work",
                                           "repo": {"full_name": "fr-meyer/openclaw"}},
                                  "base": {"sha": "c" * 40, "ref": "main",
                                           "repo": {"full_name": "fr-meyer/openclaw"}}}}
        evidence = pr.intake(event, {"runId": 1, "attempt": 1, "checkRunId": 2,
                                     "workflowSha": "d" * 40})
        self.assertTrue(evidence["draft"])
        self.assertEqual(evidence["dependsOn"][0]["number"], 12)
        event["pull_request"]["head"]["repo"]["full_name"] = "other/fork"
        with self.assertRaisesRegex(pr.Refusal, "external PR head"):
            pr.intake(event, evidence["run"])
        event["pull_request"]["head"]["repo"]["full_name"] = "fr-meyer/openclaw"
        event["pull_request"]["base"]["ref"] = "other"
        with self.assertRaisesRegex(pr.Refusal, "target differs"):
            pr.intake(event, evidence["run"])
        event["pull_request"]["base"]["ref"] = "main"
        event["pull_request"]["user"]["login"] = "unknown"
        with self.assertRaisesRegex(pr.Refusal, "declared owner"):
            pr.intake(event, evidence["run"])
        event["pull_request"]["body"] = body.replace('"owner": "fr-meyer"', '"owner": "<script>"')
        with self.assertRaisesRegex(pr.Refusal, "PR body needs one"):
            pr.intake(event, evidence["run"])
        event["pull_request"]["user"]["login"] = "fr-meyer"
        event["pull_request"]["body"] = body.replace('"headSha": "' + "a" * 40 + '"', '"headSha": "bad"')
        with self.assertRaisesRegex(pr.Refusal, "invalid dependency identity"):
            pr.intake(event, evidence["run"])
        event["pull_request"]["body"] = body
        event["pull_request"]["number"] = 12
        with self.assertRaisesRegex(pr.Refusal, "depends on itself"):
            pr.intake(event, evidence["run"])

    def test_transitive_dependency_cycle_is_refused(self):
        evidence = {"schema": "openclaw.fork-task-pr-evidence.v1", "repository": "fr-meyer/openclaw",
                    "prNumber": 1, "kind": "task", "owner": "fr-meyer", "target": "main",
                    "scope": "one",
                    "headRef": "task/a", "headSha": "a" * 40, "baseSha": "b" * 40,
                    "dependsOn": [{"number": 2, "headSha": "c" * 40}],
                    "run": {"runId": 9, "attempt": 1, "checkRunId": 10}}
        prefix = "repos/fr-meyer/openclaw"
        def current(number, head, body, state="closed", merged="2026-10-09T00:00:00Z"):
            return {"number": number, "state": state, "merged_at": merged, "body": body,
                    "user": {"login": "fr-meyer"},
                    "head": {"sha": head, "ref": "task/a", "repo": {"full_name": "fr-meyer/openclaw"}},
                    "base": {"sha": "b" * 40, "ref": "main", "repo": {"full_name": "fr-meyer/openclaw"}}}
        snapshots = {
            f"{prefix}/pulls/1": current(1, "a" * 40,
                                           pr.template("task", "fr-meyer", "main", "one",
                                                       ["2:" + "c" * 40]), "open", None),
            f"{prefix}/pulls/2": current(2, "c" * 40, pr.template("task", "fr-meyer", "main", "two", ["3:" + "d" * 40])),
            f"{prefix}/pulls/3": current(3, "d" * 40, pr.template("task", "fr-meyer", "main", "three", ["1:" + "a" * 40])),
            f"{prefix}/actions/runs/9": {"id": 9, "run_attempt": 1, "event": "pull_request",
                                              "conclusion": "success", "head_branch": "task/a",
                                              "repository": {"full_name": "fr-meyer/openclaw"}, "path": pr.WORKFLOW},
            f"{prefix}/pulls/1/reviews?per_page=100&page=1": [
                {"id": 1, "user": {"login": "reviewer"}, "state": "APPROVED", "commit_id": "a" * 40}],
            f"{prefix}/actions/runs/9/attempts/1/jobs?per_page=100&page=1": {"jobs": [
                {"check_run_url": f"https://api.github.com/{prefix}/check-runs/10", "conclusion": "success"}]},
        }
        with self.assertRaisesRegex(pr.Refusal, "dependency cycle"):
            pr.assess_live(evidence, snapshots.__getitem__)


if __name__ == "__main__":
    unittest.main()

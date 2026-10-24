import copy
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import release
import preflight

import pr


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


def fixture(root, historical=False):
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
    origin = base
    if historical:
        (root / "product.txt").write_text("prior downstream behavior\n")
        git(root, "add", "product.txt")
        git(root, "commit", "-qm", "prior downstream patch")
        origin = git(root, "rev-parse", "HEAD")
        git(root, "checkout", "-q", "-b", "admitted", base)
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
    inventory = {
        "schema": "openclaw.fork-patch-inventory.v1", "repository": manifest["repository"],
        "candidate": manifest["candidate"], "manifestSha256": pr.sha256(manifest_path.read_bytes()),
        "upstream": {"tag": "v2026.10.1", "tagObject": "1" * 40, "commit": base,
                     "verificationSha256": "a" * 64},
        "patches": [{"id": "fixture-product", "originCommit": origin if historical else source, "disposition": "adapt" if historical else "carry",
                     "appliedCommit": source, "rationale": "Keep the fixture change", "evidenceSha256": None,
                     "regressionTests": ["src/a.test.ts"], "dependsOn": [], "regressionOwner": "fixture",
                     "paths": [{"path": "product.txt", "boundary": "container", "sourceCommit": origin if historical else source,
                                "sourceTree": git(root, "rev-parse", origin + "^{tree}") if historical else source_tree,
                                "sourceBlob": git(root, "rev-parse", (origin if historical else source) + ":product.txt"),
                                "upstreamBlob": git(root, "rev-parse", base + ":product.txt"),
                                "candidateBlob": git(root, "rev-parse", source + ":product.txt")}]}]}
    manifest_path.with_name("patch-inventory.json").write_text(json.dumps(inventory) + "\n")
    git(root, "add", "scripts/fork-release/manifest.json", "scripts/fork-release/patch-inventory.json")
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
    def setUp(self):
        original = release.git
        def observed_tag(checkout, *args):
            # Tag creation is forbidden in this task. Only the tag observation is
            # synthetic; source ancestry, blobs, diff and seal commits use real Git.
            if args[:2] == ("cat-file", "tag") and args[2] == "1" * 40:
                manifest = json.loads((Path(checkout) / "scripts/fork-release/manifest.json").read_text())
                return "object " + manifest["source"]["baseCommit"] + "\ntype commit\ntag v2026.10.1\n\nfixture"
            return original(checkout, *args)
        self.tag_patch = patch.object(release, "git", side_effect=observed_tag)
        self.tag_patch.start()
        self.addCleanup(self.tag_patch.stop)

    def test_offline_seal_has_ordered_ancestry_after_bounded_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "origin"
            root.mkdir()
            manifest_path, event, _ = fixture(root)
            checkout = Path(directory) / "metadata"
            workflow = (Path(__file__).resolve().parents[2] /
                        ".github/workflows/fork-release-pipeline.yml").read_text()
            metadata_step = workflow.split("- name: Checkout exact candidate metadata", 1)[1].split(
                "- name:", 1)[0]
            depth = re.search(r"fetch-depth:\s*(\d+)", metadata_step)
            self.assertIsNotNone(depth)
            manual = workflow.split("  qualify-and-prepare:", 1)[1]
            self.assertIn("candidate_head_sha:", workflow)
            self.assertIn("github.ref == 'refs/heads/main'", manual)
            self.assertIn("--manifest metadata/scripts/fork-release/manifest.json", manual)
            self.assertIn("metadata/scripts/fork-release/patch-inventory.json source", manual)
            self.assertNotIn("tooling/scripts/fork-release/manifest.json", manual)
            subprocess.run(["git", "clone", "--quiet", f"--depth={depth.group(1)}", root.as_uri(),
                            str(checkout)], check=True, capture_output=True)
            git(checkout, "fetch", "--no-tags", "--depth=1", "origin",
                event["pull_request"]["base"]["sha"])
            checked = pr.offline_release_seal(
                checkout / "scripts/fork-release/manifest.json", checkout)
            self.assertEqual(checked["sourceSha"],
                             json.loads(manifest_path.read_text())["source"]["commit"])


    def test_divergent_historical_patch_requires_explicit_pinned_object_acquisition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "origin"
            root.mkdir()
            manifest_path, _, _ = fixture(root, historical=True)
            checkout = Path(directory) / "candidate"
            subprocess.run(["git", "clone", "--quiet", "--single-branch", "--depth=3",
                            root.as_uri(), str(checkout)], check=True, capture_output=True)
            manifest, manifest_hash = release.manifest_at(manifest_path)
            inventory_path = manifest_path.with_name("patch-inventory.json")
            inventory = json.loads(inventory_path.read_text())
            origin = inventory["patches"][0]["originCommit"]
            self.assertEqual(preflight.history_commits(inventory), [origin])
            with self.assertRaisesRegex(release.Refusal, "source_object"):
                preflight.inventory_at(inventory_path, manifest, manifest_hash, checkout, check_head=False)
            # Local file transport models the workflow's fixed-fork SHA fetch; no network/tag creation.
            git(checkout, "fetch", "--no-tags", "--depth=1", "origin", origin)
            admitted, _ = preflight.inventory_at(inventory_path, manifest, manifest_hash, checkout, check_head=False)
            self.assertEqual(admitted["patches"][0]["disposition"], "adapt")

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


    def test_seal_refuses_dirty_inventory_untracked_metadata_and_extra_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, event, run = fixture(root)
            inventory_path = manifest_path.with_name("patch-inventory.json")
            inventory = json.loads(inventory_path.read_text())
            inventory["patches"][0]["rationale"] = "Dirty decision"
            inventory_path.write_text(json.dumps(inventory) + "\n")
            with self.assertRaisesRegex(pr.Refusal, "committed PR head"):
                pr.release_seal(pr.intake(event, run), manifest_path, root)
            git(root, "add", str(inventory_path))
            (root / "extra.txt").write_text("Unreviewed tooling\n")
            git(root, "add", "extra.txt")
            git(root, "commit", "--amend", "-qm", "extra seal content")
            event["pull_request"]["head"]["sha"] = git(root, "rev-parse", "HEAD")
            with self.assertRaisesRegex(pr.Refusal, "exactly manifest and inventory"):
                pr.release_seal(pr.intake(event, run), manifest_path, root)


    def test_inventory_origin_must_be_a_retained_commit_not_a_blob(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, _, _ = fixture(root)
            path = manifest_path.with_name("patch-inventory.json")
            inventory = json.loads(path.read_text())
            inventory["patches"][0]["originCommit"] = inventory["patches"][0]["paths"][0]["sourceBlob"]
            path.write_text(json.dumps(inventory) + "\n")
            manifest, manifest_hash = release.manifest_at(manifest_path)
            with self.assertRaisesRegex(release.Refusal, "inventory.origin.0.commit"):
                preflight.inventory_at(path, manifest, manifest_hash, root, check_head=False)

    def test_seal_refuses_inventory_queue_and_blob_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, event, run = fixture(root)
            path = manifest_path.with_name("patch-inventory.json")
            inventory = json.loads(path.read_text())
            inventory["patches"][0]["appliedCommit"] = "f" * 40
            inventory["patches"][0]["paths"][0]["candidateBlob"] = "f" * 40
            path.write_text(json.dumps(inventory) + "\n")
            with self.assertRaises(pr.Refusal) as error:
                pr.release_seal(pr.intake(event, run), manifest_path, root)
            self.assertIn("inventory.ordered_queue", str(error.exception))
            self.assertIn("inventory.path.0.candidateBlob", str(error.exception))

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

    def test_metadata_reseal_reuses_product_diff_but_rechecks_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, event, run = fixture(root)
            before = pr.release_seal(pr.intake(event, run), manifest_path, root)
            manifest = json.loads(manifest_path.read_text())
            manifest["candidate"] = "test-release-resealed"
            manifest_path.write_text(json.dumps(manifest) + "\n")
            inventory_path = manifest_path.with_name("patch-inventory.json")
            inventory = json.loads(inventory_path.read_text())
            inventory["candidate"] = manifest["candidate"]
            inventory["manifestSha256"] = pr.sha256(manifest_path.read_bytes())
            inventory_path.write_text(json.dumps(inventory) + "\n")
            git(root, "add", "scripts/fork-release/manifest.json", "scripts/fork-release/patch-inventory.json")
            git(root, "commit", "--amend", "-qm", "manifest seal")
            event["pull_request"]["head"]["sha"] = git(root, "rev-parse", "HEAD")
            after = pr.release_seal(pr.intake(event, run), manifest_path, root)
            self.assertNotEqual(before["headSha"], after["headSha"])
            self.assertTrue(pr.reusable_changed_diff(before, after))
            self.assertNotEqual(before["inventorySha256"], after["inventorySha256"])
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
                   "head_sha": evidence["headSha"],
                   "pull_requests": [{"number": 7, "head": {"sha": evidence["headSha"]},
                                      "base": {"sha": evidence["baseSha"]}}],
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

    def test_run_is_bound_to_current_pr_and_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, event, run_context = fixture(root)
            evidence = pr.release_seal(pr.intake(event, run_context), manifest_path, root)
            current = {**copy.deepcopy(event["pull_request"]), "state": "open",
                       "merge_commit_sha": "f" * 40}
            reviews = [{"id": 1, "user": {"login": "reviewer"}, "state": "APPROVED",
                        "commit_id": evidence["headSha"]}]
            run = {"id": 91, "run_attempt": 1, "event": "pull_request",
                   "conclusion": "success", "head_branch": evidence["headRef"],
                   "head_sha": evidence["headSha"],
                   "pull_requests": [{"number": 7, "head": {"sha": evidence["headSha"]},
                                      "base": {"sha": evidence["baseSha"]}}],
                   "repository": {"full_name": evidence["repository"]}, "path": pr.WORKFLOW}
            jobs = [{"check_run_url": "https://api.github.com/repos/fr-meyer/openclaw/check-runs/101",
                     "conclusion": "success"}]
            for commit in (evidence["headSha"], current["merge_commit_sha"]):
                with self.subTest(accepted_commit=commit):
                    checked = {**run, "head_sha": commit}
                    self.assertEqual(pr.assess_current(evidence, current, reviews, checked, jobs)["headSha"],
                                     evidence["headSha"])

            invalid = {}
            invalid["stale_commit_same_branch"] = {**run, "head_sha": "e" * 40}
            invalid["missing_commit"] = {key: value for key, value in run.items() if key != "head_sha"}
            invalid["missing_pr_association"] = {key: value for key, value in run.items()
                                                 if key != "pull_requests"}
            invalid["empty_pr_association"] = {**run, "pull_requests": []}
            invalid["wrong_pr"] = copy.deepcopy(run)
            invalid["wrong_pr"]["pull_requests"][0]["number"] = 8
            invalid["stale_pr_head"] = copy.deepcopy(run)
            invalid["stale_pr_head"]["pull_requests"][0]["head"]["sha"] = "e" * 40
            invalid["stale_pr_base"] = copy.deepcopy(run)
            invalid["stale_pr_base"]["pull_requests"][0]["base"]["sha"] = "e" * 40
            invalid["duplicate_pr_association"] = {**run, "pull_requests": run["pull_requests"] * 2}
            invalid["malformed_pr_head"] = copy.deepcopy(run)
            invalid["malformed_pr_head"]["pull_requests"][0]["head"] = None
            for reason, changed in invalid.items():
                with self.subTest(rejected=reason), self.assertRaisesRegex(pr.Refusal, "check run"):
                    pr.assess_current(evidence, current, reviews, changed, jobs)

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
                                              "head_sha": "a" * 40,
                                              "pull_requests": [{"number": 1, "head": {"sha": "a" * 40},
                                                                 "base": {"sha": "b" * 40}}],
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

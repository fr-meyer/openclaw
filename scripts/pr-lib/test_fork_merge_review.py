"""Exercise the actual shell admission seam without a reviewer or network."""
import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class MergeReviewTests(unittest.TestCase):
    def run_gate(self, repository="fr-meyer/openclaw", host="github.com", *,
                 initial=False, reviewer_status=0, stable_status=0):
        script = r'''
set -e
script_parent_dir="$PWD/scripts"
source scripts/pr-lib/merge.sh
MERGE_REPO_NAME="$1" MERGE_REPO_HOST="$2"
pr_gh_plain() { echo unexpected-network >&2; return 99; }
require_clawsweeper_review() { echo initial-clawsweeper; }
fetch_clawsweeper_review_comments() { echo fetch-clawsweeper; }
validate_clawsweeper_review_comments() {
  echo validate-clawsweeper
  CLAWSWEEPER_REVIEW_EVIDENCE='{"commentId":123}'
}
# Stable status is captured independently of the function's positional args.
stable_code="$5"
merge_outcome_stable() { echo stable; return "$stable_code"; }
reviewer_code="$4"
python3() {
  printf '%s\n' "$*" >&2
  printf '{"reviewedHead":"%s"}\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  return "$reviewer_code"
}
if [ "$3" = initial ]; then
  require_initial_external_review 42 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "$1" "$2"
else
  require_final_external_review 42 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  printf '%s\n%s\n' "$MERGE_EXTERNAL_REVIEW_KIND" "$MERGE_EXTERNAL_REVIEW_EVIDENCE"
fi
'''
        return subprocess.run(
            ["/bin/bash", "-c", script, "fixture", repository, host,
             "initial" if initial else "final", str(reviewer_status), str(stable_status)],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )

    def test_exact_fork_runs_review_then_revalidates_authority(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines()[0:2], ["stable", "codexReview"])
        self.assertIn("fork-codex-review.py", result.stderr)
        self.assertTrue(result.stderr.startswith("-I "))
        self.assertIn("--base-sha " + "b" * 40, result.stderr)
        self.assertIn("--head-sha " + "a" * 40, result.stderr)
        self.assertNotIn("clawsweeper", result.stdout)

    def test_initial_fork_stage_defers_without_claiming_completion(self):
        result = self.run_gate(initial=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("pending", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_upstream_and_wrong_host_keep_original_gate(self):
        for repository, host in [("openclaw/openclaw", "github.com"),
                                 ("fr-meyer/openclaw", "example.com")]:
            with self.subTest(repository=repository, host=host):
                result = self.run_gate(repository, host)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines()[:4],
                                 ["fetch-clawsweeper", "stable", "validate-clawsweeper", "clawsweeperReview"])
                self.assertEqual(result.stderr, "")
                self.assertEqual(self.run_gate(repository, host, initial=True).stdout,
                                 "initial-clawsweeper\n")

    def test_failed_review_or_changed_authority_refuses(self):
        for reviewer, stable in [(1, 0), (2, 0), (0, 1)]:
            with self.subTest(reviewer=reviewer, stable=stable):
                result = self.run_gate(reviewer_status=reviewer, stable_status=stable)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("codexReview", result.stdout)


if __name__ == "__main__":
    unittest.main()

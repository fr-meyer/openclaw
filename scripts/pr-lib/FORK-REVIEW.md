# Fork Codex review gate

## Scope and adoption status

This policy applies only to pull requests targeting `github.com/fr-meyer/openclaw`,
including contributor-fork heads. Adoption follows the procedure below; its exact
remote outcome belongs in the operation's retained evidence.
Upstream OpenClaw's ClawSweeper gate remains unchanged for other repositories.
The separate release-candidate gate in `scripts/fork-release/pr.py` still requires
its existing GitHub approval; this policy does not replace that approval.

## Normal admission after adoption

The trusted, anchored PR wrapper invokes `fork-codex-review.py` at final admission.
That helper launches a fresh independent Codex review through the existing
`.agents/skills/autoreview/scripts/autoreview` entry point. It records the exact
repository, PR, base, head and tree, both full and reviewed diff hashes, and the
helper, CLI, report, status and log hashes. The gate requires a fresh, completed,
clean review of the exact candidate; missing, stale, changed or incomplete
evidence fails admission. Importing a cached report is not a supported substitute.

The prepared independent review, CI gates and remote identity checks remain in
force. Candidate drift invalidates the binding and requires fresh qualification.
The fork accepts only immediate squash admission. Auto-merge, merge queues, admin
and alternate merge methods are refused before review because a local review
cannot bind a later deferred candidate. Existing expected-head dispatch and final
authority rechecks remain; this policy adds no atomic expected-base guarantee.
The local receipt is operator-attested evidence, not cryptographic proof from the
review provider. It does not create or impersonate a GitHub review or approval.

## Disclosure boundary

Permission to use the Codex review service must already cover the exact PR's
source, tests and documentation. This gate grants no new disclosure authority.
Credentials and database contents must not be included. Review is bounded to the
exact PR scope; it does not authorize an automatic repository-wide upload.
A denied or uncertain submission must be reconciled under the existing approval
rules, without changing routes to bypass the denial.

## One-time policy bootstrap

The user approved this policy adaptation and tooling adoption onto the fork's
`main`. The old anchored wrapper cannot execute its own replacement. First
independently review and test a policy-only bootstrap of the exact change,
record its base/head and review evidence, and adopt only that reviewed policy
revision under that recorded owner authority. Verify the actual
remote outcome before treating the canonical policy as installed.

This bootstrap does not authorize landing unrelated release work,
spoofing an anchor, or invoking an unlanded development wrapper as trusted policy.
After verified adoption, normal operations must use the canonical anchored wrapper.

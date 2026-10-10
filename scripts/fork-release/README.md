# Fork release pipeline (staged)

This lane belongs only to `fr-meyer/openclaw`. It is independent of the active
9.8 deployment and does not modify its candidate, release workflows, or server.
The checked-in manifest pins a **source-only seed** at fork main `8b1f5c8`; it
has `productionEligible: false`. A future candidate needs its own reviewed,
complete ordered patch chain, focused test selection, and explicit decision to
set that field to `true`. Never change this seed merely to match a moving branch.

## Parallel work through draft PRs

Use one task-specific branch and one draft PR per independent change. Name task
branches `task/<short-name>` and release candidate branches
`candidate/<version-or-name>`; start each in its own worktree from a reviewed
fork commit. Do not switch or overwrite another task's checkout. The PR body
declares one owner, exact target, scope and dependencies pinned as PR number +
head SHA. Generate its body with the source-only helper:

```sh
git -C "$FORK_REPO" worktree add -b "task/$SLUG" "$NEW_WORKTREE" "$EXACT_BASE_SHA"
python3 scripts/fork-release/pr.py template --kind task \
  --owner fr-meyer --target main --scope 'Describe this one task' \
  --dependency 123:0123456789abcdef0123456789abcdef01234567 \
  --output /tmp/task-pr-body.md
```

The helper does not create a branch or PR. After the exact PR-opening effects
are reviewed, the branch owner can open a **draft** PR with that body. Keep
dependent PRs separate and identify their pinned heads; a changed or unmerged
dependency remains blocked at current-state assessment. The owner is the PR
author or an assignee. A task PR can target an integration branch, but its
declared target must match the actual base. No workflow here merges a PR.

The fork's new `pull_request` intake runs on opened, reopened, synchronized,
ready-for-review and converted-to-draft events, owner assignment changes, and
body/base edits. It
does **not** skip drafts. It accepts only same-repository `task/` or
`candidate/` heads, uses a trusted exact-base sparse checkout, has read-only
contents permission, and uploads a small head/base/owner/dependency/check
record. Other PR heads skip its jobs. Different PR numbers have separate
concurrency groups; a new event for the same PR cancels stale work. This is
a coordination check, not a replacement for repository branch policies.

The fork's existing `ci.yml` skips drafts; its upstream-only scheduled jobs
do not provide fork coverage. Opening a PR still runs `workflow-sanity.yml`
and small iOS/macOS/shared scope jobs; their Xcode scans skip drafts. For this
tooling diff, testbox, CodeQL and Opengrep jobs match paths but skip drafts.
The inherited `pull_request_target` opening triggers include
`security-review.yml`, which preserves the status/review gate, and
`labeler.yml`, which may update GitHub labels. `auto-response.yml` and
`real-behavior-proof.yml` normally skip an owner/member author but can run for
another association. Their current permissions and behavior are unchanged.
The narrow `clawsweeper-dispatch.yml` guard skips only **draft PRs in
`fr-meyer/openclaw`**; upstream is unchanged, and a ready-for-review fork PR
still reaches ClawSweeper if its existing app key is configured. No token,
secret, environment, repository setting or security review gate is changed.

**Bootstrap matters:** `pull_request_target` executes the base branch's
workflow. A first PR containing this guard cannot suppress the fork's old
ClawSweeper dispatch on its own opening. Before any PR, review the exact base
workflow and choose an activation route: separately review and explicitly
authorize a guard-only change to fork `main`, accept the existing external
dispatches for a guard bootstrap PR and its later `main` push, or publish only
a non-triggering branch and defer the PR. A ready transition or PR edits can
cause further dispatches. Do not assume that draft status alone prevents the
old dispatch.
The guard-only `main` push itself matches the inherited ClawSweeper **push**
trigger and other `main` CI triggers, so it also requires a separate review of
those effects; the draft-only guard does not suppress them.
Before opening any later fork draft, run the read-only exact-base check from
the tooling branch against a checkout pinned to the intended PR base:

```sh
python3 scripts/fork-release/pr.py opening-preflight \
  --checkout "$EXACT_BASE_CHECKOUT" --base-sha "$EXACT_BASE_SHA"
```

It refuses the old dispatch rule or a missing security review gate. It checks
those two known admission rules, not every inherited workflow or external
repository setting; review the opening inventory and current base separately.
For a tooling draft after the guard is live on fork `main`, the expected
opening work is workflow-sanity, three lightweight scope jobs, security
review, and labeler; the other code/test jobs skip until ready. Opening or
making a PR ready remains a separately reviewed step because each transition
has different runner, metadata and external-review effects.

### One visible release candidate PR

Open a single draft `candidate/` PR against fork `main` from the product source
commit, then add one **manifest-only seal commit** to that same PR after its
number is known. The seal commit's sole changed path is
`scripts/fork-release/manifest.json`; its parent is the exact product source
commit. The manifest's `review` object pins the PR number, exact base SHA and
SHA-256 of `git diff --binary --full-index --no-ext-diff BASE SOURCE`. The PR
workflow verifies those facts, the ordered patch chain, and one focused
lifecycle/producer-consumer test invocation. It runs while the PR is draft and
does **not** build an image or access production. The resulting small evidence
artifact names the head, base, source, diff, workflow, run, attempt and check.

Generate the candidate binding from the product source checkout, rather than
typing commit, tree or diff hashes. `bind` emits a separate proposed manifest;
review and copy that file into the candidate branch, then make the manifest-only
seal commit. It refuses a different candidate ID, PR number or PR base on an
already bound manifest. The seal gate recomputes the binding from Git objects
and fails if any patch tree or changed-diff hash is stale.

```sh
python3 scripts/fork-release/pr.py bind \
  --manifest scripts/fork-release/manifest.json --checkout "$SOURCE_CHECKOUT" \
  --candidate "$CANDIDATE" --pr-number "$PR_NUMBER" --base-sha "$PR_BASE_SHA" \
  --output /tmp/proposed-release-manifest.json
python3 scripts/fork-release/pr.py binding-check \
  --manifest "$SEALED_CHECKOUT/scripts/fork-release/manifest.json" \
  --checkout "$SEALED_CHECKOUT"
```

Refreshing hashes within the same candidate, PR, base and reviewed scope is
mechanical; changed product behavior or deployment scope still needs review.

`pr.py compare --previous OLD.json --evidence NEW.json` reports whether an
earlier review covered the same product diff under the same PR/base and source
tree. A manifest-only reseal can reuse that changed-diff review work. A fresh
check and current-head approval are still required. `pr.py assess-live
--evidence RELEASE_PR_EVIDENCE.json` reads the public GitHub API without new
credentials and checks current PR, review, run, job and dependency records;
it rejects moved heads/bases, stale review, failed check and unresolved
dependencies. The offline `assess` command accepts independently fetched JSON
snapshots for diagnostics and tests. API unavailability blocks release
progress. Assessment output explicitly has `mergeAuthorized: false`: main or
master merge always needs the user's explicit decision, and another target
must still satisfy all of its existing gates and policies. This helper never
posts, approves, merges or changes GitHub settings.

A reviewed push to `release-pipeline/contracts/**` runs the exact-source,
offline regression, and focused lifecycle and producer/consumer gates on one
hosted Ubuntu job. It skips OCI tooling, image creation, and artifact upload.
Its green check is contract evidence only, never an image or deployment receipt.

After the exact candidate PR and checks are reviewed, the hosted OCI build is
started only by a separate `workflow_dispatch` (or a reviewed push to another
`release-pipeline/**` branch). The normal PR-opening path cannot build it.
GitHub requires the dispatch workflow file on the default branch, so manual
dispatch begins only after the tooling has been reviewed and landed there.
The reviewed push route can validate a branch before that merge.

## Source and hosted proof

`manifest.json` is the single candidate source identity: base commit/tree,
ordered custom commits/trees, final commit/tree, focused lifecycle and
producer/consumer tests, and image architecture/extensions. `release.py
source-check` verifies the entire parent chain and every named test in an exact
checkout. The workflow runs those tests in one hosted Linux process, then uses
the same checkout to build one OCI image. It uses the official Docker release
preparation's OCI closure, attestation and smoke helpers; the smoke copy is
checked against the prepared config digest. The OCI payload and `receipt.json`
are uploaded together under a run/attempt-specific artifact name. No registry
push or production action occurs in CI. CI gets `contents: read` only.

The earlier `mergeguez-d2ec-qualification.yml` proved a fixed old baseline with
sealed patches and first-attempt branch/actor conditions. This lane retains
exact-source and offline contract gates, while allowing a reviewed manifest to
select each future candidate. It does not copy that task's private companion
inputs or its hosted build supervisor.

## v2026.9.9 source-only preparation

`manifests/v2026.9.9.json` pins the 9.9 upstream base and three ordered
source patches. The final patch is `c3f9123d4bea1e6cc8b21c8742fc71e0385f7ca6`.
It remains `productionEligible: false`. The original seed manifest and its route are
unchanged. The v2 manifest adds an explicit Node test lane and the parity image
build decision; `release.py gates --runner node` emits only Node's
`*.test.mjs` paths, while its default emits the Vitest paths.

A reviewed push to `release-pipeline/source/v2026.9.9` runs the exact-source
checkout, offline contracts, the inert publisher source plan, changed-owner
planner, type checks, build, focused Vitest tests, and Node tests on a standard
hosted Linux runner. The upstream `v2026.9.9` tag is fetched from the public
upstream repository for the source plan; its peeled commit is checked against
the source manifest. Both focused test lanes report their exit status; either
failure keeps the source job red and the image job skipped. This route produces
no OCI image or artifact.

A separate reviewed push to `release-pipeline/image/v2026.9.9` first reruns
the same source job, then allows one `linux/amd64` Buildx preparation with
`OPENCLAW_EXTENSIONS=workboard` and `OPENCLAW_PARITY_IMAGE=1`. It seals and
smokes the same source digest, verifies the packaged inert publisher against
its source commit, and refuses an OCI payload over 4 GiB before a three-day
artifact upload. Neither route uses secrets, registry pushes, deployment, or
production authority. A branch push is an explicit CI dispatch with hosted
runner and artifact storage effects; review its exact diff, current allowance,
and artifact size before using the image route.

## Private deployment interface

`release.py run` is an operator-side coordinator. It requires a reviewed
production-eligible manifest, the exact Actions image receipt and OCI payload,
and a separately supplied executable adapter. It verifies OCI bytes, image
labels and attestations before any operation. Its state is in a private mode
`0700` directory; records and the production lock are mode `0600`. Use **one
shared private root for all candidate releases**, for example
`~/.local/state/openclaw-fork-release`. Do not put it in the public repository
or upload it as a workflow artifact.

The adapter has one small command interface:

```
ADAPTER status|invoke --phase PHASE --operation-id ID \
  --source-sha SHA --image-digest sha256:... \
  --manifest FILE --image-receipt FILE --oci-dir DIR \
  [--backup-receipt OPAQUE_ID] [--restore-receipt OPAQUE_ID] \
  [--rollback-fence-receipt OPAQUE_ID]
```

Each call returns one JSON object with the same `operationId` and `state` of
`not_found`, `in_progress`, `succeeded`, or `failed`. Success includes an opaque
`receiptId`; `rehearsal`, `deploy`, and `health` success also includes the exact
`imageDigest`. The adapter must durably deduplicate `invoke` by operation ID,
and `status` must reconcile a possibly accepted operation before any retry.
`backup` captures all mutable production data privately. `restore` copies
that backup to a disposable isolated target; `rehearsal` tests the exact image
against that restored copy. `deploy` uses the same digest, `health` verifies
it, `rollback` restores the captured data only after a failure with a verified
no-write, one-writer fence, and `cleanup` removes only transient staging.
Cleanup must retain the backup and audit receipts. The adapter must fail closed
if isolation, restore compatibility, image identity, or health proof is absent.
On a failed deploy or health operation, automatic rollback requires
`rollbackSafe: true` and an opaque `rollbackFenceReceiptId` from the adapter.
That receipt must prove the candidate writer is stopped and no candidate writes
or external effects were acknowledged. Otherwise the coordinator stops at
`needs_operator` and leaves all data for incident reconciliation. A status
label or a failed process exit alone is never rollback proof.

`ops_gate.py` is the source-only bridge to the existing private
`openclaw-runtime-tools-gate`. Its `image` mode passes the OCI receipt's
**config digest** as the approved Docker image ID and checks the gate's
reported source revision against the manifest. Its `post` mode checks the
running image ID, health, readiness, restart/OOM state and read-only broker
preflight. Both emit a compact receipt hash; keep the full gate output in
private operation records. The OCI index digest remains the release identity
in `release.py`; the config digest is the Docker daemon image ID. An adapter
must call `image` before changing the Compose selector and `post` after
recreation. No coordinator phase invokes this bridge automatically yet.

The fork's `openclaw backup create --verify --json` and `backup restore
ARCHIVE --target FRESH_DIR --json` are useful private capture and disposable
restore primitives. The archive is not an atomic snapshot across config and
databases; later writes remain live. Restore never activates into the live
state tree, and its sanitized SQLite snapshots are not an exactly-once
delivery continuation point. A private adapter can use these commands only
after it proves the current release's complete mutable path inventory,
quiescence or a compatible write fence, and a safe activation sequence.
Until then it must refuse to report backup, rollback, or live restore as
successful. The current 9.8 procedure and private data remain outside this
source branch.

The coordinator records intent before invocation, polls operation status on
resume, retries transient status reads at most three times, and issues at most
two calls per phase with the **same** operation ID. An unresolved phase stays
pending and needs inspection; no new ID is invented. A single private-root
lock serializes releases. Progress is human readable via `status`.

Before `deploy`, `health`, `rollback`, or `cleanup`, the coordinator also
acquires the existing operations deployment lock. Supply its absolute path
with `--shared-deploy-lock`; on the current GCP host this is
`/home/frmeyer/openclaw-operations/.production-deploy.lock`. A missing,
symlinked, or busy file refuses the operation. The lock is released after a
single `run`, including when an operation is still pending. The adapter must
therefore recheck the live baseline and selector under this lock on every
invoke and reconciliation; a backup or rehearsal receipt alone is not proof
that production stayed unchanged between calls. Any other deployment path
that ignores the shared lock needs a separate admission decision.

Operator command shape after all separate publication and adapter reviews:

```sh
python3 scripts/fork-release/release.py run --manifest MANIFEST \
  --image-receipt RECEIPT --pr-evidence RELEASE_PR_EVIDENCE.json \
  --oci-dir OCI_DIR --private-root PRIVATE_ROOT \
  --adapter /absolute/path/to/reviewed-adapter \
  --shared-deploy-lock /home/frmeyer/openclaw-operations/.production-deploy.lock
python3 scripts/fork-release/release.py status --manifest MANIFEST \
  --private-root PRIVATE_ROOT
python3 scripts/fork-release/release.py approve --manifest MANIFEST \
  --image-receipt RECEIPT --pr-evidence RELEASE_PR_EVIDENCE.json \
  --private-root PRIVATE_ROOT \
  --challenge PRINTED_CHALLENGE
```

After backup, restore and rehearsal, `run` stops and prints a challenge over the exact
manifest, image digest, backup, restore and rehearsal receipts. The operator reviews
those records, the current exact-head/base PR review and check evidence,
the source/test run, the Actions producer run and artifact
identity, then invokes `approve --challenge CHALLENGE`. That is the one scoped
checkpoint authorizing deploy and its fenced, preplanned rollback. This repository
contains no adapter, production credentials, backup access, IAM change, or
deployment dispatch. The seed manifest cannot enter this path.
For a production-eligible manifest, `run` and `approve` also recheck that
evidence through the public GitHub API before advancing. They retain its hash
in private progress and include it in the approval challenge.

## Review and activation sequence

1. Review this source diff and the workflow's draft PR trigger, read-only
   permissions, sparse base checkout, candidate dependency install, manual
   Docker build, OCI upload and 14-day retention. Run offline tests.
2. After exact PR-opening effects are accepted, publish the tooling branch and
   land it only with the user's main-merge decision. Open task-specific draft
   PRs without touching the active 9.8 branch. For a future release, seal one
   candidate PR and verify its exact head/base, changed diff and targeted gates.
3. Only under a separate reviewed build decision, dispatch the OCI workflow.
   Verify run/attempt, workflow SHA, source SHA/tree, PR binding, OCI receipt
   and artifact digest before any private transfer.
4. Implement and review an adapter against existing backup, rehearsal, deploy,
   restore and rollback procedures. Prove it on disposable data. A production
   candidate must set `productionEligible: true` in a separately reviewed
   manifest. Obtain the printed checkpoint approval before production mutation.

There is no assumption that the image can be rebuilt byte for byte later.
BuildKit, dependency downloads and timestamps can vary; the OCI digest from
the one hosted build is the only deployable image identity.

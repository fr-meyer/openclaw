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
`candidate/<version-or-name>`; start each future stable candidate from a verified
upstream stable tag plus its curated downstream queue, in its own worktree. Do not switch or overwrite another task's checkout. The PR body
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
commit, then add one **metadata seal commit** to that same PR after its
number is known. The seal commit changes exactly `scripts/fork-release/manifest.json` and
`scripts/fork-release/patch-inventory.json`; its parent is the exact product source
commit. The inventory binds the final manifest bytes, so neither file belongs in
the product commit it describes. The PR receipt binds both hashes and the seal
checks both files against their committed bytes. The manifest's `review` object pins the PR number, exact base SHA and
SHA-256 of `git diff --binary --full-index --no-ext-diff BASE SOURCE`. The PR
workflow verifies those facts, the ordered patch chain, and one focused
lifecycle/producer-consumer test invocation. It runs while the PR is draft and
does **not** build an image or access production. The resulting small evidence
artifact names the head, base, source, diff, workflow, run, attempt and check.

Generate the candidate binding from the product source checkout, rather than
typing commit, tree or diff hashes. `bind` emits a separate proposed manifest;
review and copy that file into the candidate branch, then make the metadata
seal commit. It refuses a different candidate ID, PR number or PR base on an
already bound manifest. The seal gate recomputes the binding from Git objects
and fails if any patch tree or changed-diff hash is stale. Complete and review
the matching inventory after generating the manifest, then commit both metadata
files together; a missing or unresolved inventory refuses the seal.

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
tree. A metadata reseal can reuse that changed-diff review work. A fresh
check and current-head approval are still required. Inventory decisions are
separate review work: a reusable product diff never carries forward an old
inventory hash or image receipt. `pr.py assess-live
--evidence RELEASE_PR_EVIDENCE.json` reads the public GitHub API without new
credentials and checks current PR, review, run, job and dependency records;
it rejects moved heads/bases, stale review, failed check and unresolved
dependencies. The offline `assess` command accepts independently fetched JSON
snapshots for diagnostics and tests. API unavailability blocks release
progress. Assessment output explicitly has `mergeAuthorized: false`: main or
master merge always needs the user's explicit decision, and another target
must still satisfy all of its existing gates and policies. This helper never
posts, approves, merges or changes GitHub settings.

After the exact candidate PR and checks are reviewed, the hosted OCI build is
started only by a separate `workflow_dispatch` on fork `main` with the exact
40-character candidate metadata-seal commit, or a reviewed
`release-pipeline/**` push. The normal PR-opening path cannot build it.
GitHub requires the dispatch workflow file on the default branch, so this
route begins only after the tooling has been reviewed and landed there.

The manual job now reads trusted tooling from the dispatched `main` commit and
metadata from the exact input commit. It checks the current open fork candidate
PR's head and base before using the sealed source identity. The source checkout
and OCI receipt remain bound to the manifest's exact product commit and image
bytes. This separation needs hosted qualification after the tooling lands; it
does not grant build, merge, backup, or deployment authority. Reconcile the
9.9 owner's other hosted-qualified runner fixes before adopting a candidate.

## Source and hosted proof

`manifest.json` is the single candidate source identity: base commit/tree,
ordered custom commits/trees, final commit/tree, focused lifecycle and
producer/consumer tests, and image architecture/extensions. `release.py
source-check` verifies the entire parent chain and every named test in an exact
checkout. For the existing tooling-bearing candidate shape, the workflow runs those tests
in one hosted Linux process, then uses the same product checkout to build one
OCI image. The separate immutable tooling selection above is a prerequisite for
a new upstream-based candidate that does not contain those helpers. It uses the official Docker release
preparation's OCI closure, attestation and smoke helpers; the smoke copy is
checked against the prepared config digest. The OCI payload and `receipt.json`
are uploaded together under a run/attempt-specific artifact name. No registry
push or production action occurs in CI. CI gets `contents: read` only.

The earlier `mergeguez-d2ec-qualification.yml` proved a fixed old baseline with
sealed patches and first-attempt branch/actor conditions. This lane retains
exact-source and offline contract gates, while allowing a reviewed manifest to
select each future candidate. It does not copy that task's private companion
inputs or its hosted build supervisor.

### Seal an image produced on the existing GCP host

The same OCI, source, inventory and plugin checks can consume a privately
supervised GCP build. Use `seal-gcp`; never invent GitHub workflow/run values for
that execution. The source and tooling checkouts must identify their exact
commits and be clean. Sealing refuses staged/unstaged tracked changes and
untracked source files before reading working metadata. The manifest still needs the complete
source/patch chain and inventory; the checked-in historical seed is not a 10.5
manifest. GCP source-only sealing supports `productionEligible: false` and
separate manifest/inventory files. If a review binding is present, its head is
the source commit and its base-to-source diff is recomputed; tooling HEAD is
never represented as that PR's metadata seal. A source-only preparation plan is
not a sealed image.

```sh
node scripts/fork-release/image.mjs seal-gcp \
  "$MANIFEST" "$INVENTORY" "$SOURCE_CHECKOUT" "$OCI_DIRECTORY" \
  "$BUILDKIT_DIGEST" "$IMAGE_RECEIPT" "$PRIVATE_EXECUTION_DIRECTORY/execution.json"
```

Skopeo remains the default smoke-copy transport. On a host without Skopeo, a
single build can retain its OCI output and also use Buildx's Docker exporter to
load a smoke copy under a unique task-owned tag. This requires Buildx and
BuildKit 0.13 or later; verify the actual tool versions and dual-export behavior
before using it. Pass a final `loaded` argument to `seal-gcp` only after that
load. The verifier still checks the full retained OCI artifact, then requires
the loaded image's immutable config digest to match before executing native
smoke. It never trusts the mutable tag or substitutes Docker's image store for
the artifact. No host package installation or registry push is required by this
transport. See Docker's [multiple exporter contract](https://docs.docker.com/build/exporters/#multiple-exporters).

The existing private execution owner must start the build durably on GCP,
outside the Mac SSH lifetime, and retain these regular files in an owned `0700`
directory, each with `0600` permissions:

| File                  | Supervisor-owned evidence                                          |
| --------------------- | ------------------------------------------------------------------ |
| `build-metadata.json` | Native BuildKit metadata containing `containerimage.digest`.       |
| `build.log`           | Complete native build output. Keep it private.                     |
| `build.exit`          | The completed build's native exit status; sealing requires `0`.    |
| `execution.json`      | The exact record described below, written after the build settles. |

The execution record's schema is `openclaw.fork-gcp-image-execution.v1`. Its
fields are `operationId` (32 lowercase hex digits), `attempt` (positive integer
or decimal string), numeric-string `projectNumber` and `instanceId`, exact
`toolingSha`, `sourceSha`, `sourceTree`, `manifestSha256`, `inventorySha256`,
`indexDigest`, UTC-second `builtAt`, `startedAt`, `completedAt`, integer
`buildExitCode`, and SHA-256 `buildMetadataSha256` and `buildLogSha256`. Unknown
fields are refused. Retain one operation identity across observations; reconcile
an uncertain build before another attempt. The timestamps and file hashes come
from the supervisor's observations, never candidate-supplied JSON.

This evidence directory must be outside **every** candidate mount, including a
shared parent mount; the path check alone cannot establish mount isolation.
Keep the supervisor, Docker socket and cloud credentials inaccessible to
candidate code. Use the reviewed secretless build route and an exact source
context. The native Dockerfile still needs dependency and OS acquisition:
`--network=none` is usable only with a complete verified cache/closure. Do not
remove its security updates or integrity steps to make an offline build pass.

Sealing verifies the private evidence bindings, every OCI blob and attestation,
native workspace smoke and selected plugin payload. Smoke and plugin inspection
use the verified config digest, network disabled, a read-only root and bounded
resources. Native smoke creates one container, retains its returned immutable
ID, verifies terminal success and removes only that container on success,
failure or an attached-client timeout. The GCP producer in the public image receipt contains only `kind`,
`toolingSha`, `operationId`, `attempt` and `executionSha256`; cloud identifiers,
paths and raw logs remain private. It is a trusted supervisor attestation, not a
cloud identity signature or permission to deploy. The existing coordinator
accepts this producer identity without changing backup, review, approval or
production-eligibility gates. This command does not launch a build or install a
cloud controller; those execution and isolation responsibilities remain with
the private owner.

## Private deployment interface

The proposed GitHub-to-GCP route, disposable rehearsal lifecycle, privacy
boundaries and activation prerequisites are in
[`GITHUB-GCP-DESIGN.md`](GITHUB-GCP-DESIGN.md). Its offline contracts create no
resources and grant no access. In particular, the backup used for rehearsal
must never replace current live data: unattended promotion needs a fresh
current-production capture and matching rollback under the production fence.
That private adapter work is not implemented by this coordinator.

`release.py run` is an operator-side coordinator. It requires a reviewed
production-eligible manifest, the exact Actions image receipt and OCI payload,
the reviewed inventory and exact product checkout, a private baseline and backup
policy, and a separately supplied executable adapter. It verifies OCI bytes, image
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
  --inventory-sha256 HASH --baseline-sha256 HASH --backup-policy-sha256 HASH \
  [--backup-receipt OPAQUE_ID] [--restore-receipt OPAQUE_ID] \
  [--rollback-fence-receipt OPAQUE_ID]
```

Each call returns the exact `manifestSha256`, `inventorySha256`, `baselineSha256`,
`backupPolicySha256`, `sourceSha` and `imageDigest`, plus the same `operationId` and `state` of
`not_found`, `in_progress`, `succeeded`, or `failed`. Success includes an opaque
`receiptId`. The adapter must durably deduplicate `invoke` by operation ID,
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
recreation. The bridge requires `--inventory` and binds its hash in the small output receipt.
No coordinator phase invokes this bridge automatically yet.

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
python3 scripts/fork-release/release.py run --manifest MANIFEST --inventory INVENTORY \
  --source-dir EXACT_SOURCE --baseline PRIVATE_BASELINE --backup-policy PRIVATE_POLICY \
  --image-receipt RECEIPT --pr-evidence RELEASE_PR_EVIDENCE.json \
  --oci-dir OCI_DIR --private-root PRIVATE_ROOT \
  --adapter /absolute/path/to/reviewed-adapter \
  --shared-deploy-lock /home/frmeyer/openclaw-operations/.production-deploy.lock
python3 scripts/fork-release/release.py status --manifest MANIFEST --inventory INVENTORY \
  --private-root PRIVATE_ROOT
python3 scripts/fork-release/release.py approve --manifest MANIFEST --inventory INVENTORY \
  --source-dir EXACT_SOURCE --baseline PRIVATE_BASELINE --backup-policy PRIVATE_POLICY \
  --oci-dir OCI_DIR --adapter /absolute/path/to/reviewed-adapter \
  --image-receipt RECEIPT --pr-evidence RELEASE_PR_EVIDENCE.json \
  --private-root PRIVATE_ROOT \
  --challenge PRINTED_CHALLENGE
```

After backup, restore and rehearsal, `run` stops and prints a challenge over the exact
manifest/inventory, image, exact PR evidence, baseline/policy and immutable backup,
restore and rehearsal receipts. The operator reviews
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

## Durable release contracts

[DECISION.md](DECISION.md) records the fork branch model, evidence reuse,
backup and interruption contracts, version migration dependencies, and the
separate publication/settings plan.

The seed's manifest-bound `patch-inventory.json` records its two ordered patches
and every affected path. It is not the full 9.8/9.9/10.1–10.5 inventory.

The post-9.8 grouped target and its source and migration facts are tracked in
[`GROUPED-2026.10.5.md`](GROUPED-2026.10.5.md). It is preparation evidence, not
an eligible candidate manifest.
Copy `patch-inventory.template.json` for a new reviewed candidate; nulls and
`unknown` deliberately fail admission. Keep host-supervisor qualification
separate from the container patch queue.

Run the reusable offline preflight with an exact product source checkout:

```sh
python3 scripts/fork-release/preflight.py \
  --manifest scripts/fork-release/manifest.json \
  --inventory scripts/fork-release/patch-inventory.json \
  --source-dir "$EXACT_PRODUCT_CHECKOUT"
```

It batches deterministic errors and returns nonzero on refusal. The source
checkout must contain all pinned objects and tests; it never fetches or builds.
For private backup checks, additionally supply `--image-receipt`,
`--backup-evidence`, `--baseline`, and separately reviewed positive
`--backup-max-age-seconds` / `--backup-retain-seconds` values.
Private backup evidence uses the exact field contract in `backup_checks`.
The validator cannot prove its input observations are true; the private
adapter must verify and refresh them. Only stable error codes are emitted.

`deployment-receipt.template.json` defines a sanitized completed-production
receipt. Validate a filled receipt with `--deployment-receipt` and the original
`--image-receipt`. The null template is deliberately ineligible.
The existing workflow calls this same preflight before candidate tests or an OCI
build; it explicitly retains the named upstream annotated tag object and then
checks its exact object/base identity. It also fetches missing historical origin/path
commits by their validated SHA from the fixed fork remote; adapted 9.8/9.9
snapshots need not be ancestors of a new stable candidate. Unavailable objects
refuse admission rather than weaken ledger coverage. `identity` and `gates` require
`--inventory`. `image.mjs seal|verify` takes `MANIFEST INVENTORY` first.
Image receipts use `openclaw.fork-release-image.v2`; older v1 receipts cannot
be relabeled or reused. Private progress uses `openclaw.fork-release-progress.v2`
and binds inventory, baseline and policy hashes into operation IDs and approval.
Existing active release evidence remains with its owner; adopting this tooling
requires a newly reviewed metadata seal and qualification, never an in-place
edit of old evidence. No tags are created by this stage.

### Private backup admission

The private baseline is an independently approved object containing exactly
`sourceSha`, `imageDigest`, and `mutableInventorySha256`. The policy is exactly
`{"schema":"openclaw.fork-backup-policy.v1","maxAgeSeconds":POSITIVE_INTEGER,"retainSeconds":POSITIVE_INTEGER}`.
Its values are private operational decisions; this repository chooses no defaults
and changes no retention.

Before rehearsal, before recording approval, and again under the existing
operations lock immediately before a new deploy invocation, the coordinator calls a read-only
`ADAPTER admit` using the source/image/metadata arguments above, both backup and
restore receipt IDs, and `--phase`. It has no operation ID and must perform no
mutation. A missing interface, nonzero result, timeout, malformed or stale response
refuses progress. The response has exactly:
`schema`, `manifestSha256`, `inventorySha256`, `baselineSha256`,
`backupPolicySha256`, `sourceSha`, `imageDigest`, `checkedAt`, and `evidence`.
The schema is `openclaw.fork-private-admission.v1`; `checkedAt` is UTC and within
60 seconds. `evidence` is the exact private backup-evidence contract used by
`backup_checks`. The adapter must independently observe the live production
baseline, retained archive existence/readability/checksum/size, capture/check
times and retention, and retained restore proof. It must match the persisted
backup/restore receipt IDs. The coordinator batches refusals and binds immutable
archive/restore identity into the rehearsal challenge; only `verifiedAt` and
`checkedAt` may refresh without changing that identity.

The interface does not implement the adapter or qualify private procedures.
The adapter must still prove quiescence, complete compatible database groups,
isolation, leases, runtime/host gates and safe rollback, and recheck archive
usability before restore/rollback. Fail closed until those prerequisites are
reviewed and exercised on disposable data. On interruption, reconcile an already
issued deploy using its bound operation ID before requesting a new admission.
An accepted/succeeded promotion can legitimately change the live baseline;
it must never be repeated merely to refresh admission. A not-found operation
requires fresh admission before its next permitted invocation.

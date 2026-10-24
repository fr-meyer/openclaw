# Fork release decision and staged migration

Accepted strategy, October 11, 2026. This document adds contracts to PR #15.
The October 11 plan said **9.8, then 9.9, then 10.1**. The October 20 scope
groups the post-9.8 stable changes through **2026.10.5** into one future
candidate; see [`GROUPED-2026.10.5.md`](GROUPED-2026.10.5.md). Existing release owners
keep their candidates, repairs, runtime evidence, and activation decisions.

## Branch and source model

Fork `main` is the canonical integration branch and trust anchor for reusable
tooling. It contains reviewed fork changes. It never automatically deploys.
Keep upstream history reachable through the `upstream` remote; an optional
pure mirror has no fork changes or deployment triggers. Never reset/rebase
shared `main`, published candidates, or release tags.

A new `candidate/<version>` begins at a verified upstream stable tag, then
applies a curated ordered queue. Preserve the existing 1–64 non-merge commit
contract. Integrate task branches through draft PRs with pinned dependencies.
Keep product source, tooling commit, and two-file metadata PR seal distinct.
The legacy seed remains source-only; its fork base is not a verified stable tag.

The versioned inventory binds the exact manifest bytes. Each logical patch has
a disposition, rationale, regression owner/tests and earlier queue dependencies.
Each affected path records its source commit/tree/blob, upstream baseline blob
(or null for absence), resulting candidate blob (or null for deletion), and
container/host/tooling boundary. Applied commits must equal the manifest queue
in order. Candidate diff paths must all appear in the ledger. This coverage gate
does not discover omitted historical intents: the separate inventory owner must
reconcile the previous release's full diff and excluded proof paths first.
`unknown` blocks admission. `upstreamed` and `retire` require retained decision
evidence and regression references even though they add no source commit.
Do not classify equivalence by symbol names alone.

The checked-in inventory covers only the existing seed's two patch commits,
not all downstream behavior since upstream. Import the separately researched
release inventory before any future candidate qualification. Only this exact legacy seed may omit upstream identity. A verified tag
object must match the base commit; its retained verification receipt is hashed
in the inventory. Offline validation checks identities and receipt shape;
it does not establish signer trust or review the receipt's claims.

## Existing lane, one preflight

`preflight.py` is an offline admission helper for this lane. It reads the
existing strict manifest loader and canonical source check. It collects all
independent inventory/source/evidence errors, sorts stable error codes, and
prints no private values. A malformed manifest prevents dependent source
checks, while independently unreadable inputs still appear together.
A successful preflight never authorizes a build, merge, backup, or deployment.

Partial/promisor object stores are refused before source probes so older Git
cannot silently fetch missing objects. Provide a complete local object store.

The existing workflow invokes this entrypoint before focused tests or image
preparation. Candidate metadata is sealed in exactly two files, manifest and
inventory, above the pinned product source. This avoids a circular hash: the
inventory hashes the final manifest; PR/image/private evidence then hashes both.
The seal verifies committed bytes and source/blob coverage. The workflow retains
the named upstream tag object and checks it against the ledger's exact tag/base.
It acquires missing historical origin/path objects from the fixed fork by exact
validated commit SHA, so adapted prior-release snapshots remain verifiable
outside the new candidate ancestry. Missing history blocks qualification.

Image evidence and private progress use v2 schemas. Old unbound v1 evidence is
refused, never rewritten as proof. The coordinator checks the full source/ledger,
PR evidence and OCI before private state creation, and binds inventory, baseline
and backup policy into resumable operation IDs and the approval challenge.
Before rehearsal/approval and immediately before deploy under the existing shared
lock, a bounded read-only private `admit` interface must establish fresh baseline,
archive and restore observations. Immutable backup identity must match rehearsal.
The private adapter remains absent and unqualified, so this contract cannot
authorize production on its own. No additional workflow or runner is introduced.
The 9.9 owner retains runner repairs; reconcile those only after their exact
hosted qualification through the parent.

## Evidence reuse and invalidation

| Evidence                 | Reuse requires                                                                                                  | Invalidation                                                                                                        |
| ------------------------ | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Product diff review      | Same PR/base, source tree and binary diff                                                                       | Product/base/dependency change; current-head approval still needed after a reseal                                   |
| Focused/native tests     | Same source tree, selected tests, tooling and dependency inputs                                                 | Any changed test input, native contract or failure repair                                                           |
| OCI build/smoke          | Retained exact OCI bytes; matching manifest, producer run/attempt, index/image/config digests                   | Source, Docker input, architecture/plugin selection or digest changes; never rebuild during promotion               |
| Patch decisions          | Same source/baseline/candidate blobs, dependency order and reviewed ledger hash                                 | Any identity or disposition change, unknown entry, missing regression proof                                         |
| Backup/restore/rehearsal | Same complete mutable inventory, production baseline, archive checksum and candidate digest; fresh verification | Absent/expired archive, stale capture/check, shortened retention, changed baseline/data/write fence, failed restore |
| Production approval      | Exact manifest, inventory, image/PR/private evidence hashes and baseline                                        | Any changed binding, lease/operation ambiguity, stale live evidence or expired approval                             |
| Host compatibility       | Exact installed host-tool receipt and tested RPC contract                                                       | Host update, source/interface/namespace change                                                                      |

Cheap static proof can be reused where these inputs remain equal. Record PASS,
FAIL and NOT_RUN separately; a resumed run never turns NOT_RUN into PASS.
Live baseline, locks, backup readability, expiry, retention and authorization
must be rechecked immediately before activation and after interruption.

## Backup and activation contract

Private evidence records the current production source/image and complete
mutable-inventory hash, an existing nonempty archive checksum, capture and
verification times, retention deadline, and a passing disposable restore of
that same archive against the exact candidate OCI index digest.
Supply separately reviewed maximum age and minimum remaining retention to the
preflight. It rejects absent, empty, stale, future-dated, short-retained, wrong
baseline/archive/image, or unproved restore records. It changes no retention.
These JSON records are observations; a reviewed adapter must establish archive
existence, readability, checksum, permission, complete database groups and
restorability, then recheck them under the shared deployment lock.
A backup receipt without those checks is insufficient.

Use the existing private coordinator/root and operations lock. Persist phase
intent before invoke; reconcile the same operation ID with adapter status.
If the Mac/SSH session disappears, GCP retains checkpoint state and receipts.
A later approved controller resumes from status and reconciles uncertain
operations. Persistence provides recovery, not unattended execution. Do not
add persistent credentials, a daemon, scheduler or new infrastructure here.
The adapter must retain deduplication records and a deployment lease/fence for
in-progress operations because the coordinator's process lock ends on exit.
A second release cannot rely on that released process lock to bypass the fence.

Promote the one tested OCI payload by exact index digest. Record image manifest
and Docker config digests separately. Use an immutable deployment tag pointing
at the exact product source:
`deploy/<stable-version>/<UTC timestamp>-<32-hex deployment ID>`.
Allocate a fresh ID only after authorization; fail if the tag already exists.
No editable production branch is needed. Retain the exact manifest, inventory,
image receipt/OCI bytes, tooling/workflow SHA and public deployment receipt.
The receipt template contains public identities and hashes only; backup paths,
runtime logs, locations and private receipts remain private.
The prior immutable deployment tag and private approval/fence define rollback.
If current production lacks an immutable tag/receipt, prepare a separately
approved bootstrap record for its exact existing image/data before activation.
A prior verified beta deployment identity is valid rollback provenance; do not
invent a stable version for it.
A completed receipt binds its stable version to the source-derived image
version and inventory upstream tag; producer fields are explicitly allowlisted.
A completed production receipt requires backup, restore, rehearsal, deploy and
health PASS. Rollback has its own private phase record; do not relabel a rolled
back attempt as a successful deployment.

No automatic rollback is safe without the existing no-write/one-writer fence,
compatible complete database groups, and retained prior image/data.
If accepted writes or external effects cannot be excluded, preserve evidence
and stop for operator reconciliation. Never infer rollback safety from a failed
process or readiness status.

## Version migration dependencies

The separate October 11 inventory reports 93 product/tooling paths for 9.8
plus 54 historical proof paths, and 38 additional Workboard paths for 9.9.
Its path-level evidence remains the authority. Its proposed queue order is:
safety/lifecycle; namespace attestation; managed host/controller;
Workboard exact dispatch and live-producer settlement; publisher custody and
signed review; backup/inert pins; Nowistay fingerprinted repair; Docker
packaging; test ownership.

| Intent                                                                              | Provisional disposition for 10.1         | Required regression                                                    |
| ----------------------------------------------------------------------------------- | ---------------------------------------- | ---------------------------------------------------------------------- |
| Codex config/batchWrite type projection                                             | upstreamed                               | Exact upstream blob/containment and consumer contract                  |
| Managed host/shared state, Nowistay hook, execution settlement seams                | adapt                                    | Lifecycle, ownership, live producer/consumer and settlement            |
| Namespace, custody, backup/pins, memory visibility, leases, child/egress, packaging | unknown until path-ledger reconciliation | Existing patch owner's focused regression and boundaries               |
| Historical proof and superseded harness paths                                       | unknown; retire only with evidence       | Retained provenance plus replacement regression ownership              |
| Windows PR #16 host recovery                                                        | separate host qualification              | Installed receipt and RPC compatibility; excluded from container queue |

The 9.8 patch manifest covers only its initial 14 commits. The 9.9 manifest
pins an older source before later custody/harness corrections. Neither proves
missing behavior. The missing 9.8 chat test path is a deterministic wait
correction. Preserve these facts as reconciliation blockers; do not copy
unqualified repairs or regenerate a candidate from a stale ledger.
10.1's asynchronous state APIs, isolated plugin state, installation generations,
same-image Doctor ownership, worker/plugin migration provenance and database
backup groups require owner qualification.

## Publication and settings packet

1. Review this small source package atop PR #15. Reconcile the 9.9 owner's
   qualified reusable fixes by exact commit/paths/test evidence through the
   parent; do not import its active working tree. The consolidated repair reported
   at fd41a2d7a9b122868d3896ed72135598fe667caa is source-qualified but still hosted-pending.
   Reuse its truthful command/PASS/FAIL/NOT_RUN accounting, owned mode-0700 cache
   cleanup and bounded source snapshots only after exact hosted evidence. Remove
   candidate-specific refs/baselines/CLI hashes through reviewed manifest bindings;
   preserve its 29 Vitest and five Node owners and pre-overlay CI inventory order.
   This package does not duplicate that runner. Integrate inventory research
   without starting a second inventory or an unqualified candidate build.
2. After separate publication approval, update the existing PR #15 branch
   without force, with fresh base/head and sanitized diff checks. Re-run its
   offline gates and opening/transition preflight. Review inherited
   `pull_request_target` dispatch effects and the main push triggers.
3. Main merge requires its own decision. Review the bundled inventory enforcement
   in the existing workflow, PR seal, image/ops consumers and private coordinator.
   Preserve product/tooling separation when adapting any qualified 9.9 repairs.
   Trusted base tooling must land, then the parent must reconcile the 9.9 owner's
   qualified selection interface: an immutable main tooling revision is selected
   independently of the candidate metadata seal and exact product source, with
   all identities bound in producer/consumer evidence. The manual job now
   selects trusted `main` tooling and an exact candidate metadata head
   separately, and checks that head against the live candidate PR. Hosted
   qualification and the other 9.9 runner fixes remain adoption prerequisites.
   Keep draft qualification separate from explicitly authorized image build.
4. Separately approve any ruleset/protection or production environment changes:
   require the stable named contract/security checks, forbid force/deletion of
   main and immutable release/deploy tag patterns, and require serialized,
   approved production activation. Audit bypasses and all deploy writers.
   Read-only GitHub metadata on October 11 reports main as unprotected
   with required-status enforcement off, and returns no rulesets including
   parents. Production environment and administrator-only settings were not
   audited. No settings were changed by this source package.
5. The existing hosted artifact retention is 14 days. Before expiry, under a
   separately approved publication/storage plan, transfer exact OCI bytes and
   hashed receipts to an existing durable store and read them back by checksum.
   Missing payload blocks promotion; a hash alone cannot restore an image.
   No artifact retention extension, storage provisioning, key or IAM change
   is authorized here.
6. Review/test the private adapter on disposable data, including interruption,
   uncertain invoke, busy lock/lease, backup missing/stale/retention, baseline
   change, restore failure and fenced rollback. Add a regression for each
   observed 9.8/9.9 failure at its existing owner before declaring it repaired.
   Keep each release's runtime gates and activation decision separate.

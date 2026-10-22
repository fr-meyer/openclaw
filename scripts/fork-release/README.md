# Fork release pipeline (staged)

This lane belongs only to `fr-meyer/openclaw`. The selected grouped target is
production 9.4 directly to 2026.10.5. The failed 9.8 rehearsal remains evidence,
not an admitted migration input or a prerequisite production deployment.
The checked-in manifest pins a **source-only seed** at fork main `8b1f5c8`; it
has `productionEligible: false`. A future candidate needs its own reviewed,
complete ordered patch chain, focused test selection, and explicit decision to
set that field to `true`. Never change this seed merely to match a moving branch.

## Existing-VM execution route

The current operational route uses the existing GCP VM and storage, reached
through the operator's CLI. Keep one deployment owner for dataset preparation,
rehearsal, readiness, rollback and eventual promotion. The separate
`GITHUB-GCP-DESIGN.md` VM/WIF proposal is not a prerequisite for this route and
does not authorize new infrastructure or identity changes.

Build and qualify an immutable image once with `gcp_build.py` and `image.mjs`.
Reuse the resulting image receipt for rehearsal. A later tooling improvement
does not rewrite that receipt's historical producer SHA or require rebuilding
unchanged product source. New execution evidence records its own tooling
revision alongside the original receipt hash and image digest tuple.

The image verifier stages a hash-matched readable script in a private temporary
directory, preserving the checkout's permissions and the image's normal user.
The pipeline no longer needs a host-specific Docker wrapper to handle a private
`0600` verifier checkout. Its owned temporary staging is removed after the
check, including failures; image/data/previous-operation evidence is retained.

Source tests use an isolated workspace with the source-pinned pnpm and Vitest
dependencies. Runtime images retain their production dependency selection.
Missing or stale test dependencies mean preparation is needed, not that the
production image should gain development tools. Reuse focused proof only while
its source, dependency and test-command bindings remain valid.

No successful build or image check establishes native migration, gateway
readiness, rollback or production approval. The failed 9.8 run remains useful
OOM evidence; a new Doctor needs a clean admitted input and a freshly measured
memory/disk allowance. Keep heavy builds and migrations serialized.

### Pinned source tests

On the existing GCP host, use a clean source checkout and a separately prepared
dependency workspace with matching package manifests and lockfile:

```sh
python3 scripts/fork-release/source_tests.py \
  --source "$SOURCE_CHECKOUT" --source-sha "$SOURCE_SHA" \
  --dependencies "$PREPARED_DEPENDENCY_WORKSPACE" \
  --pnpm-dir "$PREPARED_PINNED_PNPM_PACKAGE" \
  --image "$PINNED_TEST_TOOLCHAIN_DIGEST" --output "$NEW_TEST_OUTPUT" \
  --workers 1 --memory-mib 1024 --timeout 300 \
  path/to/selected.test.ts
```

This synchronous step exports tracked source without private-shaped files or
Git metadata, compares dependency manifests and pnpm 12's project-lock document,
then checks actual pnpm/Vitest/SDK versions inside a non-root, network-disabled
container. The existing pnpm package is mounted read-only and invoked directly,
so a Corepack shim cannot trigger acquisition. It runs the repository's explicit
Vitest entrypoint. Dependency
packages and source mounts are read-only; fixtures and caches use private
temporary storage. Its native timeout also bounds the container if the client
disconnects. The receipt records the source, dependency metadata, installed lock,
command, pnpm launcher hashes, native exit/OOM status and bounded log hash. This is metadata/version
proof, not an audit of every installed package byte. Missing compiled artifacts
or dependencies require their existing preparation step; no install or implicit
build is performed. Native Node suites retain their existing runner.

The adapter's dependency-free Python tests run in ordinary test discovery. Its
five native entry fixtures additionally require Linux, the prepared `yaml`
dependency and `OPENCLAW_SOURCE_TEST_PNPM_DIR` pointing to the read-only pinned
pnpm package. Set that variable when qualifying the isolated test toolchain;
without it those native fixtures are explicitly reported as skipped.

### Daily snapshot rehearsal lifecycle

`gcp_rehearsal.py daily` is the normal lifecycle for a new rehearsal on the
existing GCP VM. It selects one eligible daily snapshot by its immutable ID,
restores the complete disk, and records separate `candidate` and `rollback`
generations from that same snapshot. It delegates native checks to
`gcp_snapshot_trial.py`; there is one native supervisor and one workload
reservation. It does not promote production.

The existing manually prepared disk stays with its current deployment owner.
This lifecycle does not adopt a manually named disk, create a second owner for
that operation, or replace its evidence. Trial plan v1 remains available for
an existing owner-admitted clean input, as described below.

Prepare a private `openclaw.gcp-daily-snapshot.v1` plan with exact VM/source-disk
names and numeric IDs, the existing daily snapshot policy, an explicit maximum
snapshot age, disk/cost limits, measured resource admission limits, and the
committed tooling SHA. Its independently observed baseline descriptor binds
the original source SHA, version, index/image/config digests and supported
gateway probe contract. Do not infer baseline identity from the candidate image
or from a tag. Keep the sealed candidate image, its receipt, the tooling and
private control directory outside the disposable disk.

```sh
python3 scripts/fork-release/gcp_rehearsal.py daily prepare \
  --plan "$PRIVATE_DAILY_PLAN" --image-receipt "$SEALED_IMAGE_RECEIPT" \
  --tooling "$COMMITTED_TOOLING_CHECKOUT"
python3 scripts/fork-release/gcp_rehearsal.py daily status "$OP"
```

`OP` is the returned private operation directory. Preparation observes cloud
identities and retains the plan and selected snapshot; it does not create,
attach or mount a disk. Each cloud or mount change has a separate exact action
challenge. Inspect the target, identity, consequences and cost before approving
the printed SHA. Each challenge binds one action. The operator may apply these
actions under an existing approval that covers their exact scope; a challenge
does not require another human confirmation when that authorization exists.

```sh
python3 scripts/fork-release/gcp_rehearsal.py daily action "$OP" restore candidate
python3 scripts/fork-release/gcp_rehearsal.py daily apply "$OP" restore candidate \
  --approve "$REVIEWED_ACTION_SHA"
```

Use that same `action OP VERB GENERATION` / `apply OP VERB GENERATION --approve
SHA` pair for each step below. The verbs are `restore`, `attach`, `mount`,
`unmount`, `detach` and `delete`; generations are `candidate` and `rollback`.
There is no automatic mutation loop.

| Stage              | Required sequence                                                                                                                                                                                                                                   |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Candidate disk     | Approve `restore candidate`, then `attach candidate`, then `mount candidate`; observe each terminal result.                                                                                                                                         |
| Candidate input    | The restore owner isolates config/plugins/integrations on the direct clone and attests the complete input and mount layout. Preserve the coherent restored database groups; do not reconstruct selected files or reuse a partly migrated test copy. |
| Candidate checks   | Prepare and separately approve `doctor`; after successful settled Doctor, attest the current config with `restorationState: doctor-complete`, then prepare and approve `startup`.                                                                   |
| Candidate teardown | Archive compact diagnostics, verify every native check is stopped, then separately approve `unmount candidate`, `detach candidate`, and `delete candidate`.                                                                                         |
| Rollback disk      | After candidate deletion is verified, separately approve `restore rollback`, `attach rollback`, and `mount rollback`. This is a fresh unmigrated clone of the same selected snapshot.                                                               |
| Baseline check     | Attest the fresh isolated rollback input, then prepare and approve `rollback` using the original independently bound baseline build.                                                                                                                |
| Finish             | Archive rollback diagnostics, approve its unmount/detach/delete actions, verify deletion, then close the operation.                                                                                                                                 |

#### Release-triggered SQLite hygiene assessment

The daily lifecycle records a bounded hygiene decision on the restored
**candidate** generation. `daily prepare-check OP doctor` automatically creates
`hygiene-baseline.json` before preparing native Doctor. After Doctor settles
successfully, `daily prepare-check OP startup` creates
`hygiene-post-doctor.json` before preparing startup. To inspect the decision
before either native phase, use the same exact clean-input receipt:

```sh
python3 scripts/fork-release/gcp_rehearsal.py daily hygiene-assess "$OP" baseline \
  --clean-input "$CANDIDATE_CLEAN_INPUT"
python3 scripts/fork-release/gcp_rehearsal.py daily status "$OP"
```

For `post-doctor`, use the attested `doctor-complete` clean input after the
native Doctor result is settled. The sole daily owner validates the restored
disk, snapshot, source/image, config, mounted dataset and prior Doctor result
before collecting metadata. Assessment lists at most 128 immediate agent
directories and uses file `stat` on the conventional shared and per-agent
SQLite paths and WAL sidecars. It does **not** open SQLite, read table content,
invoke `memory status`, run Doctor, index, reset, compact, prune, check a
provider, or dispatch a cloud/Docker mutation. Custom configured database
locations are not silently counted: receipts say `default-layout-only`, so
their coverage requires a separate scoped owner inventory before proposing
maintenance. Unsupported or over-bound metadata records
`bounded_metadata_unavailable`; native Doctor continues under its own checks.
File metadata fingerprints are change detectors, not hashes of
database contents or integrity proof.

The default decision is `skipped` with a precise reason. A database or WAL
above 1 GiB prompts only a *follow-up measurement proposal*, never an automatic
checkpoint, scan or cleanup. Reset/reindex, retention deletion and compaction
require their own exact scope, verified backup, free-space/time admission and
approval. The source-version commands, conditional ordering and acceptance
criteria are in [SQLITE-HYGIENE.md](SQLITE-HYGIENE.md). Doctor's native
backup, migration and integrity requirements remain unchanged.

The private receipt binds the exact run, snapshot, restore, clean-input,
source/image and tooling identities, config, filesystem device, optional
Doctor result and a bounded file-metadata fingerprint. Repeating assessment on
an unchanged measured generation returns the original receipt. A changed
measured database refuses dispatch. An unavailable assessment keeps its
explicit skip and relies on native Doctor's own dataset checks. The prior
evidence remains immutable. Post-Doctor
records a new generation rather than rewriting baseline. `daily status` shows
receipt hashes and skip decisions without reopening any database. The stage
is tied to release rehearsal entry points, not a calendar schedule, and never
changes an active supervisor or production data.

Prepare a check without launching it, inspect its separate challenge, and only
then dispatch that exact phase:

```sh
python3 scripts/fork-release/gcp_rehearsal.py daily prepare-check "$OP" doctor \
  --clean-input "$CANDIDATE_CLEAN_INPUT" --tooling "$COMMITTED_TOOLING_CHECKOUT"
python3 scripts/fork-release/gcp_rehearsal.py daily check-action "$OP" doctor
python3 scripts/fork-release/gcp_rehearsal.py daily run-check "$OP" doctor \
  --approve "$REVIEWED_CHECK_SHA"
python3 scripts/fork-release/gcp_rehearsal.py daily status "$OP"
```

Repeat the three check commands with phase `startup` and its post-Doctor input,
then phase `rollback` and its fresh baseline input at the corresponding stages.
Startup binds the retained successful Doctor result and the same actual image,
device and mounts. Rollback binds the prior operation, original snapshot and
baseline build to a distinct restore receipt and disjoint fresh mounts. It
does not apply the candidate's Codex/version qualification to the older build.

Candidate startup checks native `/healthz`, `/startupz` and `/readyz` from
inside a network-disabled container, with loopback binding, integrations
disabled and no published ports. The baseline uses its explicitly verified
probe contract. A passing check also requires graceful native shutdown,
exit/OOM evidence and cgroup settlement; HTTP liveness alone cannot pass it.
The native checker allows 600 seconds for startup and 330 seconds for shutdown.
The daily plan requires an outer timeout of at least 960 seconds. These are
bounded checks, not a benchmark or a claim of optimal performance.

```sh
python3 scripts/fork-release/gcp_rehearsal.py daily archive "$OP" candidate
# Approve and observe candidate teardown before restoring rollback.
python3 scripts/fork-release/gcp_rehearsal.py daily archive "$OP" rollback
# Approve and observe rollback teardown before close.
python3 scripts/fork-release/gcp_rehearsal.py daily close "$OP"
```

`archive` retains bounded native logs, resource samples, intents and results in
the private operation directory outside the test disk. It does not copy
databases or create a full-disk backup. Scratch data and optional caches on a
disposable disk are rebuildable; its source snapshot, sealed image and compact
diagnostics survive its approved deletion. `close` verifies disk removal and
settled checks, and records qualification only when all three native phases succeeded. Closing
a failed rehearsal is not deployment approval.

Intent and cloud request IDs are retained before dispatch. A lost response,
unsettled native service or unproven deletion stays `unknown`; use `status` and
the same operation to reconcile it. Do not retry by creating another run or
erasing ownership files. Compute disk/attachment mutations address resource
names and do not provide a disk-ID compare-and-swap precondition. Immediate
identity rechecks and one cooperative owner narrow that race; they cannot
exclude an unrelated actor replacing a resource between observation and the
API call. Reconcile with the existing disk owner before any action, and keep
external mutations serialized for the entire operation.

If attachment succeeded but mounting did not, `detach` can prove that the exact
owned device is unmounted after a settled host failure; an uncertain mount
dispatch still blocks it. A terminal native failure before container creation
uses the shared reservation owner's proof to release the workload slot. Any
create intent without a proven outcome remains fenced.

After a definitively failed `unmount`, `detach` or `delete`, prepare a new
teardown attempt with `daily retry-prepare "$OP" VERB GENERATION`. This records
the previous failure and returns a fresh action challenge without dispatching
anything. Inspect it, then use `daily apply` with that new challenge. Prior
attempts and request IDs remain retained; uncertain or running operations
cannot take this path. There are at most eight separately approved teardown
attempts per action. Doctor, restore and mount are never retried by this command.

Production promotion remains a separate decision and must capture the fresh
current production database and its matching pre-upgrade build for backup and
rollback. Run the qualified migration on that current capture. Never replace
live production state with either rehearsal generation.

### Native checks on an existing admitted input

`gcp_snapshot_trial.py` runs one native phase on an already prepared test disk.
It never creates/restores disks, copies databases, performs production cutover,
or retries migration. Plan v1 owns one Doctor invocation; plan v2 adds the
`doctor`, `startup` and `rollback` phases used by the daily lifecycle. A
clean-input receipt comes from the restore owner after reconciliation and
sanitization. Its hash binds snapshot lineage, the appropriate baseline/state,
isolated config and exact mount permissions; a JSON attestation alone does not
establish native integrity.

```sh
python3 scripts/fork-release/gcp_snapshot_trial.py prepare \
  --plan "$PRIVATE_DOCTOR_PLAN" --image-receipt "$SEALED_IMAGE_RECEIPT" \
  --clean-input "$CLEAN_INPUT_RECEIPT" --tooling "$COMMITTED_TOOLING_CHECKOUT"
# After the deployment owner admits the concrete input/resource/failure plan:
python3 scripts/fork-release/gcp_snapshot_trial.py start "$PREPARED_OPERATION"
python3 scripts/fork-release/gcp_snapshot_trial.py status "$PREPARED_OPERATION"
```

Use the exact committed tooling checkout for preparation. The running adapter
and its shared helpers must match that revision; the retained supervisor must
match again on dispatch. Candidate phases admit only the reviewed 2026.10.5
source and immutable image identities; rollback separately admits the bound
baseline receipt. Neither replaces an image receipt's original producer
revision with the newer executor revision.

Each clean-input mount has `source`, `target`, and an explicit Boolean
`readOnly`. State, `/tmp`, and `/rehearsal/cache` must be writable. Workspace
files, sessions and mutable state remain writable because Doctor may rename or
archive them. Independent project directories may be read-only submounts below
workspace targets, including a workspace inside `/home/node/.openclaw`.
Parent mounts precede child mounts. Independent sources must be physically
disjoint on the attested test filesystem. A read-only project overlay within a
writable clone subtree must cover that subtree's own matching relative path.
The adapter checks listed roots and ancestor metadata without walking their
contents, and verifies effective Docker read/write flags before releasing the
native gate. The restore owner must establish complete input coverage and
plugin/config isolation before attesting input; an old snapshot plugin must
not override the selected image package.

The established operator retains private control receipts and the shared
workload lease. A fixed isolated Python probe uses the existing
`sudo -n -u frmeyer` route to read listed directory metadata and hash the
UID1000-owned config, including private `0700` state. It returns no config body,
does not walk directory contents, and does not change ownership or permissions.
Exact read-only `state/repos` and workspace `.git` overlays are supported.
Device aliases under `/dev` must resolve to the attested block device and
mounted filesystem; accepting an alias does not relax device identity checks.
The executor records the exact filesystem partition separately from its
verified whole-disk I/O target. Docker throttling and cgroup `io.max` validation
use that whole disk; they must not use a partition device number. The mapping
is checked through native block nodes and sysfs at admission, before container
creation and before releasing the native gate. Prior settled phase validation
uses its retained mapping, so rollback does not require a deleted candidate disk.

The original reviewed envelope retains 24 GiB, no container swap and 4 CPUs.
An explicit lower-memory rehearsal profile uses 16 GiB, no container swap,
4 CPUs and a 20 GiB host
`MemAvailable` admission floor. The 4 GiB difference bounds host headroom
against a fully anonymous 16 GiB test allocation at admission; it is not a
reservation against unrelated later host growth. The lower profile is a new
test operation with its own exact plan and result, not a live change to a
running Doctor. Select one explicit read/write pair in the private plan
(`limits` for the trial executor, `resources` for the daily lifecycle):

| Profile           | `readBps` | `writeBps` |
| ----------------- | --------- | ---------- |
| `read128-write32`  | 134217728 | 33554432   |
| `read256-write64`  | 268435456 | 67108864   |
| `read320-write128` | 335544320 | 134217728  |

The 16 GiB profile accepts explicitly selected `read256-write64` or
`read320-write128`; the 24 GiB profile retains its original first two pairs.
Other combinations and unreviewed memory/admission values are refused. There
is no default escalation or unlimited profile. The higher pair is an I/O cap,
not measured disk throughput or a promise of faster completion. The current
GCP balanced-disk allocation estimates a combined throughput ceiling close to
320 MiB/s, shared with production and other disks. Recheck attachment,
available bandwidth and production contention before selecting it for a new
operation. Fresh admission limits in the plan must cover
the measured clean input, native backup set, WAL/temp growth and host headroom.
The original fixed 24 GiB/4 CPU envelope incorporates the failed 8 GiB
rehearsal's lesson; it is not a measurement of peak demand or proof of
sufficient memory. The lower 16 GiB cap is twice that failed 8 GiB cap and
leaves host headroom under the observed approximately 21.7 GiB availability.
The previous 10.5 Doctor's 20.21 GiB cgroup peak was predominantly file cache,
so it does not prove 20 GiB of anonymous demand. Its corrected later migration
stages are unmeasured; 16 GiB may still cause a cgroup OOM. Such a failure
must retain its native logs, OOM counters, stopped copy and original backup
group, without claiming qualification or automatically retrying. SQLite's
existing disposable maintenance-connection page-cache policy is 64 MiB per
connection; this profile does not alter it, native integrity or migration
semantics.
The executor verifies effective Docker and cgroup limits before releasing the
native gate, during the run and at quiescent settlement. Each new result records
its fixed profile and first/last I/O samples; the intent retains the original
selected limits. Bounded resource logs include parent-device `io.stat` counters,
monotonic interval durations, read/write byte rates and rate-to-cap ratios.
Confirm that the host reports counters on the retained parent device before
dispatch. Missing counters before first I/O mean no observed device I/O yet;
disappearing or regressing counters fail qualification. These are block I/O
observations, not SQL progress, logical database bytes or physical disk capacity.
Use counter deltas across comparable 30–60 second windows and native stages;
single short intervals can exceed a cap because of allowed bursts. Repeated
rates near a cap suggest throttling but do not establish whole-run speedup.

Profiles remain immutable within an operation; this executor has no live-adjust
command. Never update a running supervisor, its plan/receipts, Docker limits or
`io.max`. For a successor, retain the prior operation, original intent/result
hashes, selected profile and terminal/uncertain state. The sole rehearsal owner
settles the previous writer and reconciles dataset ownership and admissible
input before preparing a fresh operation with the new explicit limits. Record
both operation IDs and intent hashes in the operator handoff, retaining the
complete profile sequence even when bounded rate logs rotate. Do not relabel
partially migrated input as clean, clear an uncertain lease, or automatically
retry a migration. Old receipts remain unchanged; success qualifies only the
profile used by that operation. Live adjustment requires a separately reviewed
transition protocol with intent-before-effect, readback and uncertainty recovery.

#### Controlled Doctor continuation on the same test copy

A failed, stopped Doctor can have modified its input. Do not call that copy
`unmigrated`. For an explicitly authorized continuation, use the existing v2
trial plan with `phase: "doctor"`, a new operation ID and the same sealed image
receipt. Set the new input receipt's `restorationState` to `doctor-interrupted`.
Supply `--check-input` with this private, hash-bound check structure:

```json
{
  "schema": "openclaw.snapshot-doctor-continuation.v1",
  "phase": "doctor",
  "doctorOperationId": "EXACT_PREVIOUS_OPERATION_ID",
  "doctorIntentSha256": "SHA256_OF_ORIGINAL_INTENT_BYTES",
  "doctorResultSha256": "SHA256_OF_ORIGINAL_TERMINAL_RESULT_BYTES",
  "reconciliation": {
    "observedAt": "POST_STOP_UTC_TIMESTAMP",
    "artifactDisposition": "incomplete-group-reconciled",
    "artifactReceiptSha256": "SHA256_OF_OWNER_ARTIFACT_RECONCILIATION",
    "artifacts": [],
    "recaptureBytes": 1,
    "originalCaptureBytes": 1,
    "additionalReserveBytes": 1
  }
}
```

The numbers above are schema placeholders, not capacity recommendations. The
sole rehearsal owner must settle the original job, then reconcile the exact
surviving artifacts. That private reconciliation records the original operation
and terminal result, bounded pre/post-stop metadata, exact source/build/group
identity, manifest status, classifications, and capacity basis. `artifacts` must
enumerate the observed backup/staging artifacts; an empty list is valid only
when the owner has established their absence. This remains an owner attestation,
not a database scan, native integrity proof, or cleanup authorization.

Classify the two native backup families separately for the sealed 10.5 source:

- **Migration group:** the deterministic ID binds version, runtime build/commit,
  target schemas, and the full sorted source path/device/inode inventory. It does
  not bind current content generations or timestamps: retaining the original
  generation after in-place migration is intentional. No `.capturing` marker and
  every expected final present means a reuse candidate; native code must still
  integrity-validate every backup. Missing a member of a completed group refuses
  continuation. A missing cleanup-registration manifest alone does not prove an
  incomplete group, since registration failure is a native warning.
- **Incomplete group/staging:** a surviving `.capturing` marker makes native code
  discard existing group finals and recapture the whole inventory. A partial
  staging file is not a resumable snapshot. After the exact owner stops, classify
  these for an explicit cleanup decision; do not preserve large obsolete files
  by default. Keep the marker, canonical databases and sidecars in place.
- **Original pre-repair capture:** a standalone `doctor --fix` attempts a fresh
  random run ID; older standalone captures are not a retry cache. Sealing checks
  stable source content generations around each snapshot and across the final
  inventory, then publishes `manifest.json` last. An admitted updater continuation
  has a separate manifest/driver/installation lineage contract. A valid original
  capture can remain essential recovery evidence even when it is not reusable.

If the migration group completed, retain it and select
`completed-group-retained` with `recaptureBytes: 0`; native validation decides
reuse. Otherwise select `incomplete-group-reconciled`. Unknown ownership,
production, active files and required rollback originals are protected. Changes
to current database content alone never justify deleting a completed group.

For a **reviewed cross-build continuation** on the same stopped test copy,
the check also includes `backupReuse` with schema
`openclaw.doctor-backup-reuse.v1`, the exact historical source SHA, image index
digest and receipt SHA, the successor source SHA and image receipt SHA, the
original backup group UUID, its manifest SHA-256 and the expected backup count.
Every enumerated artifact must be a retained `migration-backup` from that
group, classified `native-revalidation-required`, with zero recapture bytes.
The runner accepts only its pinned historical image and the newly qualified
successor image; it passes a narrower proof to the native Doctor. The native
code rechecks the full physical database inventory, original manifest and
backup identities, then performs its normal SQLite integrity and foreign-key
validation before treating the old group as reusable. The old manifest and
receipts remain unchanged; the successor writes distinct recovery evidence.
An incomplete, replaced, aliased or mismatched group is refused. This path
does not treat the interrupted working copy as an unmigrated snapshot and does
not skip the remaining Doctor migration or startup qualification.

Each artifact entry has these fields (all names are exact):

```json
{
  "path": "/mnt/isolated-test/state/example.sqlite.pre-startup-migration-GROUP.bak",
  "kind": "migration-backup",
  "classification": "not-reusable",
  "disposition": "deletion-pending",
  "reason": "Exact stopped owner's incomplete group; not needed for rollback",
  "ownerOperationId": "EXACT_PREVIOUS_OPERATION_ID",
  "device": 1,
  "inode": 2,
  "links": 1,
  "sizeBytes": 4096,
  "allocatedBytes": 4096,
  "evidenceSha256": "SHA256_OF_COMPACT_IDENTITY_AND_CLASSIFICATION_EVIDENCE",
  "nativeDiscardOnRetry": true,
  "removal": null
}
```

Kinds are `migration-backup`, `snapshot-staging`, `standalone-capture`, or
`protected`; classifications are `native-revalidation-required`, `not-reusable`,
`protected`, or `unknown`. Dispositions are `retain`, `preserve-outside-mounts`,
`deletion-pending`, or `removed`. Entries refer to exact files, never recursive
directory deletion targets. The executor rejects outside-dataset paths, duplicate
paths/inodes, overlapping entries, and disposal of reusable/protected/unknown
artifacts. Disposals require the exact predecessor owner and one hard link.
`nativeDiscardOnRetry` records membership in the current incomplete group's
native deletion set: `true`, `false`, or `null` when unresolved. Unknown membership
blocks start. A current-group final must be settled as removed or preserved
outside mounts before admission; labeling it protected or reusable does not
permit native deletion. Unrelated historical groups can remain protected with
confirmed `false` membership.

For each proposed removal, the sole cleanup owner presents the exact file
manifest, allocated bytes, ownership/inactivity proof, and consequences for
**per-action irreversible deletion approval**. Preserve compact manifests,
logs, identities and results outside successor mounts. Approval for an older
batch or general permission to retry does not approve a new batch. After
approved cleanup, reconcile actual results, including uncertain operations,
and record `removal` as `{ "manifestSha256": "...", "approvalSha256": "...",
"resultSha256": "..." }`. Those hashes reference evidence; they do not grant
authority. `deletion-pending` can be prepared but blocks start before lease
transfer. If retaining an unusable file for a specific diagnosis, record that
reason and preserve it outside successor mounts; do not move a live file.
This executor never dispatches deletion or authorizes native deletion of
unreconciled incomplete finals. The owner must clear that conflict first.

For an incomplete group, `recaptureBytes` must cover a new whole-group capture.
Separately estimate `originalCaptureBytes` for the standalone pre-repair path;
reuse of a migration group does not remove that possible allocation. Document
the native log and layout evidence for a zero estimate. The capture root is a
sibling of the state directory; do not assume it is writable merely because
state is writable, or alter mounts to suppress a required capture.
`additionalReserveBytes` is an explicit positive estimate for further work.
Admission requires freshly observed free space at least equal to **the selected
runtime floor + migration recapture + original capture + additional reserve**.
Accounting uses allocated bytes, with logical sizes also retained. Retained and
preserved bytes already consume measured free space; do not count them twice.
Neither pending nor reported removal bytes are credited to admission: only a
fresh free-space observation counts. The former floor is
retained in predecessor evidence, while the new plan explicitly selects its
own positive floor. Neither an old floor nor an estimate proves the maximum
space needed by every migration stage. The runtime floor remains enforced;
there is no automatic lowering or retry after a space failure.

The executor verifies the old service invocation and exact owned container are
terminal, and binds their original intent/result hashes, image, snapshot,
restore receipt, filesystem, mounts and process start/finish facts. A completed
successful Doctor goes to startup instead of this continuation path. Historical
supervisor helpers are read only against reviewed hashes; they are never
executed or replaced. The earlier qualified `4c57b5269d` preservation-only
reconciliation can still be read against its pinned helper manifest; new
prepare/load/start require explicit artifact accounting. Reconciliation must
postdate the terminal result.

Under the shared workload lock, continuation rechecks predecessor settlement,
requires its exact existing dataset lease, preserves its original bytes, and
records a transfer intent before installing the successor claim. A missing,
conflicting or uncertain lease is refused. An interruption can resume only the
exact recorded transfer; dispatch uncertainty stays status-only. The native
gate rechecks the predecessor and successor claim before releasing Doctor.
The result retains `continuedFrom`, including old limits and provenance; startup
must reference the successful successor, and rollback still requires a separate
unmigrated generation and matching baseline build. No old receipt is rewritten,
and the executor does not restore, copy, move or delete database artifacts.

`/usr/bin/timeout` in each selected image must be verified
before activation. Do not infer its availability from the image's base distro.

Start intent precedes systemd dispatch; repeating `start` observes the retained
operation. A missing unit or lost reply after intent stays `unknown`. Status
prints bounded timestamped native output first, then elapsed/quiet time and
service observations. Process liveness, output and completed native stages are
separate facts. The fixed wrapper keeps the cgroup alive until final memory/OOM
counters are captured and only the original init and gate processes remain;
wrapper exit zero cannot hide a killed native child. The gate uses Node timers,
so its own polling adds no transient child processes to that observation.
Failure stops only the exact owned container and preserves data, WAL, backups
and logs pending the owner's explicit teardown. Startup/readiness and rollback
have separate phase results; Doctor success does not establish them. Trial v2
retains a hash-bound private prior-Doctor reference, checks its settled native
container, and validates the appropriate candidate or baseline image binding.

Build and native trial phases share a durable heavyweight-workload reservation.
Resource-specific reservations are admitted under the same lock, so a workload
conflict cannot leave an unrelated builder or dataset reserved before dispatch.
It advances only after matching terminal service/native evidence; a canceled
build client cannot establish that its daemon-side solve ended. Unknown or
failed-build ownership remains for operator reconciliation. This cooperative
reservation covers these adapters, not older/native commands: before adopting
it, reconcile legacy work with its existing owner. Do not erase an uncertain
reservation to start another job. A disjoint idle builder cache on the test
disk is preserved and is not a conflicting database writer.

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

### Build once on the existing GCP host

`gcp_build.py` adapts the existing native Buildx builder to one durable systemd
service. It builds an image only; it does not own rehearsal, migration,
production promotion, or cleanup. Run it from the clean, reviewed tooling
checkout on GCP. Use a separate clean exact-source checkout and the generated
candidate manifest/inventory.

```sh
python3 -B scripts/fork-release/gcp_build.py prepare \
  --config "$PRIVATE_BUILD_CONFIG" \
  --private-root /var/tmp/openclaw-fork-gcp-build \
  --manifest "$MANIFEST" --inventory "$INVENTORY" \
  --source-dir "$SOURCE_CHECKOUT" --tooling-dir "$TOOLING_CHECKOUT"
python3 -B scripts/fork-release/gcp_build.py start "$OPERATION_DIRECTORY"
python3 -B scripts/fork-release/gcp_build.py status "$OPERATION_DIRECTORY"
```

For the adaptive candidate build, add `--adaptive-gateway-id` with the full
production Gateway container ID to `prepare`. It samples host memory, full
memory pressure, root/cache free space, and that container's native health
three times over ten seconds. Each sample resolves the fixed production Docker
name `openclaw-openclaw-gateway-1` and requires its full ID to match the input.
It selects one source and builder bound profile,
or prints `no_fit` and exits 2 without creating an operation. The resulting
private intent records all samples and the selected profile. `start` and the
durable service each repeat the three-sample admission before dispatch. The
existing continuous host reserve and pressure checks remain in force; the
compiler heap is fixed for the selected attempt and no running worker limits
are changed. Resume uses the recorded profile rather than selecting again.

The current implemented candidates are 6 GiB compiler heap with at least a
21 GiB MemAvailable start floor, and 12 GiB with at least a 26 GiB start floor.
Both retain at least a 10 GiB running floor and at most a 5% full-memory PSI
limit. Existing stricter config floors remain in force, including at least a
16 GiB root floor and a 44 GiB cache floor. The 21 GiB floor is informed by a
previous complete build that started at 20.53 GiB and a failed build that
consumed 8.19 GiB of host availability before stopping. The full-build working set and
peak under this exact source are **not measured**; these profiles are
qualification candidates.
Do not treat the Doctor's separate 16 GiB container limit or the compiler's
4,352 MiB V8 minimum as a whole-image build minimum. One owned, isolated
build with complete peak, pressure, Gateway health, and image-seal evidence is
required before calling a profile qualified. A `no_fit` result calls for later
fresh admission, not a lower ad hoc threshold or automatic retry.

One controlled qualification for source
`1d5ab20bea4cccce0b80b60a9ba5d5020cf08038` selects an 8 GiB aggregate
BuildKit memory and memory-plus-swap cap (no container swap), 4 CPUs, a 6 GiB
compiler heap, at least 19 GiB MemAvailable before dispatch, and the retained
10 GiB running floor. This is an experimental admission budget, not a proven
build minimum. It requires fresh Gateway health, memory-pressure and OOM
checks; it stops on a worker OOM or failed resource guard and has no automatic
retry. The worker's own cgroup and its ancestors must prove the effective
8 GiB, zero-swap, 4-CPU limits before the solve. A successful compile alone
does not qualify export, load, image verification or sealing.

The closed configuration binds the exact source/tree/tooling and metadata
hashes, stable release version, private cloud identity, existing builder
container/image/resource limits, build timestamp, timeout, and free disk/memory
reserves. `validate_config` owns its fields. Obtain identities and capacity from
current native observations; the synthetic test configuration is not a host
configuration or resource recommendation.

For a separately backed cache, the optional `cache` contract records the exact
named volume, canonical backing path, numeric filesystem device and free-space
floor. Before dispatch, the adapter verifies the local bind-volume options and
the selected builder's writable `/var/lib/buildkit` mount. Runtime samples check
the pinned device and cache free space separately from root/OCI space. If the
cache directory is root-owned, its verified parent on the same device supplies
the capacity sample. This does not create a volume, relocate Docker, authorize a
protected disk mutation, or establish a hard filesystem quota.

The single canonical private root owns the builder reservation. Preparation
does not dispatch a build. Start rechecks bindings and capacity, then fsyncs its
intent before invoking systemd. Repeating start after a lost reply observes the
same operation; it cannot dispatch again. An existing reservation is retained
for reconciliation. This excludes competing operations through this adapter,
not independent users of Docker; coordinate ownership before dispatch.

For a successor on the same builder, run `gcp_builder_handoff.py OLD_OPERATION
NEW_OPERATION` only after the old build has a validated successful execution
receipt and the new operation has been prepared but never started. The handoff
requires the same exact builder identity, the old service's terminal invocation,
and the old lease bytes. It writes an intent before atomically replacing the
lease and a completion receipt afterward. A lost reply can be reconciled by
repeating the same handoff; another lease owner or an incomplete prior build is
refused. The handoff does not dispatch a build or establish that a failed or
cancelled remote solve has stopped. Keep both operation directories and their
evidence. The successor's updated start command requires the completed handoff
receipt and fsyncs the lease before dispatch, including after a crashed
transfer. A previously prepared operation with older tooling cannot use this
path; prepare a fresh successor from the reviewed tooling revision.

When a build client fails or is cancelled, its BuildKit solve is **not**
settled by that client exit. Preserve the failed operation, inspect its
terminal service and resource records, and stop only the exact owned test
builder after confirming no other solve uses it. Prepare a distinct successor
operation with the corrected, measured admission profile. While the same
builder is still stopped, transfer its lease with:

```sh
python3 -B scripts/fork-release/gcp_builder_recovery.py \
  "$FAILED_OPERATION" "$NEW_OPERATION"
```

Recovery requires the failed invocation, nonzero native exit, absence of a
successful execution receipt, exact builder identity and a Docker stop time
after the failure. It records the stop proof, original completion hash and
atomic lease transition without deleting or rewriting the failed evidence.
For the single source-pinned qualification above, a stopped 16 GiB/18 GiB
memory-plus-swap, 7-CPU worker may transition to 8 GiB/no-swap/4 CPUs. The
transition records intent before Docker update and reconciles exact native
readback; a partially applied update permits one recorded repair attempt,
then refuses. A changed builder requires the transition proof at successor
start. The build worker has no Docker byte-rate I/O caps in this qualification;
the separate future 16 GiB Doctor rehearsal profile explicitly uses
320 MiB/s read and 128 MiB/s write and must verify effective limits before
its own launch.
If a pre-dispatch validation refuses before `start-intent.json` exists, keep
that prepared operation and its transition receipt unchanged. After publishing
and preparing corrected exact tooling, use `gcp_builder_recovery.py --prepared
OLD_PREPARATION NEW_PREPARATION` to move only its builder lease. This checks
both operations were never dispatched, binds the original transition receipt,
and atomically records the new lease and handoff. It does not restart the
worker, submit a solve or repeat the Docker resource update. The corrected
successor still needs fresh admission and effective cgroup checks at start.
The heavy-workload slot advances only to that exact successor. Start the
retained builder after the recovery receipt is durable, then run the normal
successor `gcp_build.py start` with a fresh capacity check. A changed worker,
other lease owner, live solve, missing stop proof or uncertain origin refuses.
This route neither starts/stops Docker itself nor authorizes new capacity.

Except for the exact stopped-worker transition above, the existing builder
remains unchanged. The client has its own systemd limits;
the recorded builder limits govern compilation separately. Native output is
timestamped and shown before status. Resource observations describe measured
host headroom, not builder peak allocation or semantic progress. A deadline or
reserve breach stops only this operation's client. It does not establish that
the remote BuildKit solve has settled. Cancellation requires the private
started receipt to match the live unit invocation. No uncertain operation can
produce a success receipt or automatically release the reservation.

The native Git context uses the full commit as both checksum and fragment,
with BuildKit's `fetch-by-commit=true` shallow, no-tags transport. The pinned
Buildx/BuildKit pair must support that query; do not replace it with an
unbounded raw-SHA fetch or disable native policy checks when it fails.

Before preparation and again before dispatch, the executor reads `Dockerfile`
from the exact Git source commit and requires its complete SHA-256 to match
the tooling-owned `REVIEWED_DOCKERFILE_SHA256` policy pin. That reviewed file
gives every `RUN` an explicit network mode: only the three existing acquisition
steps before candidate payload use `default`; every other step uses `none`.
Buildx therefore uses global `--network default`: BuildKit 0.32.2 treats a
Dockerfile `--network=default` as inheriting that global setting. A global
`none` would also disable those acquisition steps. Any Dockerfile byte change
requires whole-file policy review and an updated pin before another build;
instruction counts or a partial parser do not authorize the change.

GCP sealing verifies the hash-checked SLSA statement's selected image subject,
Git configuration source and resolved dependency against that same repository
and commit. Hosted local-checkout builds retain their existing producer checks.

The supervisor bounds inherited stdout draining after client exit and applies
a five-second termination grace plus a two-second join. An open pipe or an
unobserved exit cannot produce success. This settles the client supervisor;
native daemon cancellation and absence of an active solve still need owner
reconciliation before a retry.

Resource reserves are explicit operation inputs, not performance guarantees.
The first candidate attempt used a 12 GiB available-memory floor and stopped
with 11.59 GiB available; that was conservative, not evidence of imminent host
OOM. The user's acceptance of production impact supersedes that reserve.
For the existing 10 GiB worker and 512 MiB client, the revised build proposal
uses a configured 2 GiB host floor and an operator admission check for at least
12.5 GiB available, with no concurrent migration. The adapter enforces the
configured floor at start and during execution; it does not enforce the
additional operator admission budget. This is operational headroom, not a measured 10.5 peak
or a guarantee against a sudden allocation. Recheck host totals, current
allocation and pressure before dispatch; migration has its own reviewed budget.

Keep the operation directory owned and `0700`. The Buildx child uses `0022`
inside that private parent so root-created OCI exports can be read by the
supervisor. The supervisor keeps `0077`; only the exact settled metadata file
is handed back to its existing UID and normalized to `0600`. Verify actual
OCI export permissions and that exact handoff on the host
before a candidate build. This needs no recursive ownership change, credential
change, new builder, or host package installation.

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

Skopeo remains the default smoke-copy transport. The GCP builder emits one OCI
artifact with provenance and SBOM. Its `dockerExport` configuration must be
`false`: the native host probe rejected combined Docker export because the
attested result is a manifest list. Do not disable attestations to accommodate
that exporter.

On a host without Skopeo, first qualify native Docker loading of a tar archive
of the **same retained OCI layout**, using the host's actual image store. This
is a transport of existing bytes, not a second build. Pass a final `loaded`
argument to `seal-gcp` only after that load. The verifier still checks the full
retained OCI artifact, then requires the loaded image's immutable index digest
to match before executing native smoke and plugin checks on the selected
platform. Docker's containerd store reports the index for unqualified image
inspection and the selected manifest for platform-qualified inspection; neither
is the config digest. The receipt retains all three verified digests. Legacy
Skopeo transport continues to verify the smoke copy's config digest.
The verifier never trusts a mutable tag or substitutes Docker's image store for
the artifact. No host package installation or registry push is required by this
transport. A successful exporter probe alone does not qualify the candidate.

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
context. The reviewed candidate Dockerfile confines networked acquisition to
manifest/patch inputs and runtime security tools before candidate payload.
Candidate installs and builds run with networking disabled. Native frozen
installs, lifecycle execution, addon checks, security updates, and integrity
checks remain required; an acquisition cache alone is not a qualified image.

Sealing verifies the private evidence bindings, every OCI blob and attestation,
native workspace smoke and selected plugin payload. Codex checks bind the actual
CLI and platform package to the source dependency and require a bounded native
app-server handshake and clean shutdown. Workboard exercises its SQLite worker
with a synthetic write/read/close. These checks prove offline startup, not an
authenticated model turn or a migration. Smoke and plugin inspection use the
verified immutable image digest, network disabled, a read-only root and bounded
resources. Each creates one container, retains its returned immutable ID,
verifies terminal success and removes only that container on success, failure
or an attached-client timeout. The GCP producer in the public image receipt contains only `kind`,
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

The direct 9.4-to-10.5 grouped target and its source and migration facts are tracked in
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

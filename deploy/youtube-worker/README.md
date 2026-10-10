# Windows caption worker deployment

This fork owns the GCP supervisor, coordinator, worker, PowerShell adapter,
transport bridge, storage/import dependencies, Windows wrapper and deployment
transaction in this directory. GCP remains the sole scheduler and lease owner.
The external archiver is owned by `fr-meyer/agent-toolkit`, at
`skills/youtube-transcript-archive/scripts/archive_youtube_transcript.py`.
Its full commit and SHA-256 are mandatory release inputs. Compatibility is
`windows-caption-worker-v2`; worker and adapter must advance together.

This bundle can be installed independently of the OpenClaw runtime image.
Do not copy `deploy/` into the runtime image, upgrade OpenClaw incidentally or
identify a workspace's untracked scripts by its unrelated Git HEAD. Runtime
files are installed at their existing `workspace/scripts/` paths so cron argv,
data roots, scheduler identity and projections retain their existing owners.
The dedicated transport helper is `scripts/youtube_worker/openclaw-node-run`;
other lanes' helpers and Mac coordinator are untouched.

## Admission and interruption behavior

The wrapper uses the existing installed Node executable explicitly with
`--ignore-config --no-js-runtimes --js-runtimes node:<absolute-path>` and the
pinned yt-dlp `2026.08.19`. The offline `--worker-preflight` must report one
Node version >=22 and that exact extractor version. Preflight runs under the
actual worker launcher/account, once before any pending extraction, and spends
no video attempts. Account, executable paths, binary hashes and versions are
recorded in native validation evidence. No cookies or media are permitted.

Windows exit `0xC000026B`, its signed/unsigned forms and fatal wrapped diagnostics
produce `blocked_interrupted` / `worker_session_interrupted`. This takes priority
over an incidental JavaScript warning. Missing-runtime configuration, bot/auth,
rate limits and video availability retain separate classes. Shared circuits
stop caption fallback, worker probes and subsequent items. Diagnostics preserve
the primary failure before archive validation, redact credential fields before
bounding, and do not expose raw command exception chains.

## Controlled installation

1. Finish source review and isolated offline tests on the exact candidate.
   Run the required structured autoreview before committing nontrivial code.
   Commit the fork bundle and external archiver separately on their authorized
   feature branches. Main/master landing requires separate approval.
2. Produce an external release record with schema
   `openclaw.youtube.windows-release.v1`, repository `fr-meyer/openclaw`, full
   `revision`, compatibility `windows-caption-worker-v2`, and the `files` plus
   `wrapper_sha256` from:

   ```sh
   python3 deploy/youtube-worker/deployment.py inventory
   ```

   Add `archiver: {repository, revision, path, sha256}` using the canonical
   toolkit commit's actual file bytes. Never pin dirty/new bytes to an older
   commit. Hash the serialized release record; retain it outside public Git.

3. Stage the reviewed candidate for native Windows validation through the
   already authorized local repair chat, without switching desktop connections:

   ```powershell
   & .\windows\validate-candidate.ps1 -CandidateRoot <candidate-directory>
   ```

   Run it under the actual worker account/launcher. It parses the native adapter,
   compiles the worker, runs native staging/lock tests and mocked worker regressions, and executes only offline
   wrapper preflight. Retain its exact component/runtime/account receipt. No
   extraction, credential change, permission change or restart is required.

4. Stage rollback copies and the reviewed Windows files without activating them.
   During activation below, wait for GCP's `boundary_locked` receipt before the
   local Windows owner installs
   the exact reviewed adapter, archiver and wrapper into their existing paths,
   preserving rollback copies. The adapter's default archiver and wrapper paths
   remain unchanged; additional script operands must not be added to its command.
   Write the external local `.openclaw/youtube-transcript-tools/deployment.json` receipt
   with schema `openclaw.youtube.windows-assets.v1`, compatibility, fork/toolkit
   revisions and repositories, `archiver_source_path`, component SHA-256 values
   and the exact `worker_account`. Readback must match the source/rollback receipt.
   Return the installed adapter, archiver and wrapper hashes, exact `assets`,
   `worker_alive: false` and `worker_lock_free: true` as one bounded JSON receipt
   on GCP activation stdin.
5. Prepare external GCP `state/config/windows-worker.json` with schema
   `openclaw.youtube.windows-config.v1`: `agent_id`; exact node `{id,label,cwd}`;
   remote `{staging_root,adapter,archiver,wrapper}`; existing validation-canary
   `{id,archived_count}` evidence; and `assets` containing compatibility,
   `fork_revision`, `archiver_revision`, both component hashes and worker account.
   Keep live identities/configuration outside the public repository.
6. Capture a fresh read-only deployment plan. The existing source hashes form
   its mandatory preconditions. Retain autoreview, isolated-test and native
   Windows evidence hashes in a proof record bound to release hash and revision.
   All three proof records must have `state: passed`.

   ```sh
   python3 deploy/youtube-worker/deployment.py plan \
     --workspace <existing-workspace> --data-root <existing-data-root> \
     --release <release.json> --configuration <windows-worker.json>
   python3 deploy/youtube-worker/deployment.py activate \
     --workspace <existing-workspace> --data-root <existing-data-root> \
     --release <release.json> --configuration <windows-worker.json> \
     --proofs <proofs.json> --expected-current <plan.json> --journal <journal.json> \
     --await-windows
   ```

   The 60-second boundary handshake coordinates the prepared local Windows
   installation with GCP activation while holding existing coordinator and
   supervisor locks. If it expires or validation fails, restore the Windows
   rollback copies/receipt and preserve any GCP prepared journal. A separately
   captured `windows_installation` proof can be used without stdin only when
   the operator has already kept that same boundary reserved.
   Activation requires an exact clean fork commit, free supervisor/coordinator
   locks, no active Windows-node lease and no nonfinal Windows run. It retains
   preimages/modes, verifies all installed bytes, and changes only owned source,
   external Windows configuration/provenance and worker/adapter cutover hashes.
   It preserves existing scheduler, safety and notification fields. Cron checks
   the complete managed source/config inventory before admitting a new batch.

7. Validate the actual node/account/assets through the supported coordinator
   `preflight`, then observe one normally scheduled batch. Completion requires
   matching staged worker/adapter/assets, archive validation, matching bundle and
   import receipts, committed finalization, completed lease and cleared item
   bindings. Record the source revision, release hash and exact timestamps.
   An old healthy batch does not satisfy proof for the new deployment.

Rollback is explicit and between runs:

```sh
python3 deploy/youtube-worker/deployment.py rollback --journal <journal.json>
```

It refuses active leases or unexpected later drift. Coordinate restoration of
the Windows asset rollback receipt/copies before resuming scheduled work. A
prepared/interrupted deployment is recovery state; preserve its journal rather
than guessing, deleting it or launching a worker.

## Notification-only source installation

The same deployment owner has an explicit `--notification-only` variant for a
known stopped, blocked run. It does not release/resume that run or make it idle.
The ordinary full installer and rollback still require no active lease.

This variant admits one existing full-bundle baseline, then changes only
`youtube_global_windows_supervisor.py`, `youtube_worker_alerts.py`,
`youtube_safe_diagnostics.py`, `youtube_windows_deployment.py` and the existing
`state/config/windows-deployment.json` integrity receipt. That receipt records
the new GCP source revision separately from its unchanged native asset revision
and full baseline. Windows configuration bytes/modes, cutover, worker, adapter,
wrapper, archiver, checkpoints, attempts, archives and import receipts remain
unchanged. There is no Windows installation handshake or scheduler edit.

Supply `--baseline-release` for the actually installed full release. Source
review and offline proofs remain exact-candidate bound. `native_windows` must
be explicitly `inherited`, with its original evidence digest, baseline release
digest, exact assets, worker and adapter hashes; do not label a new native test
passed. A fresh operator receipt (`--readiness`) has schema
`openclaw.youtube.windows-notification-readiness.v1`, `checked_at` within 60
seconds, exact `canary_id`, `lease_id`, `node_id`, `node_connected: true`,
`assets`, actual `worker_account`, actual adapter/archiver/wrapper SHA-256
readbacks, `configuration_sha256`, `cutover_sha256`, `checkpoint_sha256`, and the existing normalized read-only `Probe`
result as `remote`. Obtain it through the existing authorized coordinator and
local Windows account; it must prove stopped worker, free OS lock, unchanged
checkpoint/staging and account/assets. Receipt data alone never replaces the
authoritative graph, reread under supervisor, same-run reconcile and coordinator
nonblocking locks. Unknown recovery/import/finalization outcomes are refused.

```sh
python3 deploy/youtube-worker/deployment.py plan --notification-only \
  --workspace <existing-workspace> --data-root <existing-data-root> \
  --release <candidate-release.json> --configuration <unchanged-windows-worker.json> \
  --baseline-release <installed-full-release.json> --readiness <fresh-readiness.json>
python3 deploy/youtube-worker/deployment.py activate --notification-only \
  --workspace <existing-workspace> --data-root <existing-data-root> \
  --release <candidate-release.json> --configuration <unchanged-windows-worker.json> \
  --baseline-release <installed-full-release.json> --readiness <fresh-readiness.json> \
  --proofs <candidate-proofs.json> --expected-current <plan.json> --journal <new-journal.json>
python3 deploy/youtube-worker/deployment.py rollback \
  --journal <recorded-journal.json> --readiness <fresh-readiness.json>
```

The read-only notification plan requires fresh readiness and runs the complete
inventory, installed graph and existing-command preflight without creating or
acquiring deployment locks. Activation repeats this preflight before its
boundary, then rereads it under all three locks; a plan never supplies live
authority. Rollback also refuses unsafe state before acquiring its boundary.

Historical leases and run manifests are streamed rather than retained as a list.
Each directory admits at most 4096 direct entries, including ignored names;
only fixed `manifest.json` children are inspected, without recursive scanning.
All records, including completed history and other nodes, must be readable JSON
objects. An explicit `node` must be an object: `null`, booleans, numbers, strings
and arrays are refused, including falsey values. Inactive leases and terminal
runs may omit historical node data. Active leases and nonterminal runs require
a nonempty string node identity; empty objects cannot establish live ownership.
Each record/read is capped at 2 MiB, and one admission has a 16 MiB
aggregate actual-read budget and a five-second monotonic budget. The installed
lifecycle still owns every graph, item, lease, staging and checkpoint decision;
its read primitives share this budget, including its repeated lease scan.
Directory and file metadata watches reject concurrent growth or replacement.
Nothing is filtered away merely to fit a budget, and no automatic retry is made.

These bounds cover the measured production inventory of 1207 lease records
(1.03 MB) and 710 manifests (3.26 MB), including repeated lifecycle reads and
the existing maximum of 25 bound items. Memory retains one parsed historical
record, at most one selected owner per directory and bounded metadata watches.
Over-budget or changed inventories require a new reviewed preparation; do not
delete history or raise a production guard during activation. Existing-command
admission retains its process/argv caps and adds a five-second scan budget.

The transaction has a 30-second total monotonic deadline, including admission,
durable writes, readback and journal commit. Kernel operations can delay signal
delivery; an expired command never reports success on return to user space.
It refuses existing commands through bounded Linux process evidence. New cron
commands take the existing supervisor lock before imports and quietly skip a
busy boundary; the reader also rejects a stale loaded supervisor. Use a normal
cron gap; do not pause scheduling. Files are individually atomic under the
existing journal, not one filesystem-wide atomic swap.

Timeout, interruption or lost response can leave a prepared or committed
journal. Inspect that recorded outcome; never repeat activation. Explicit
rollback requires the same fresh stopped-run proof and protected preimages,
restores only known before/after bytes and original modes, durably removes a
new helper, and retains the notification database/tombstones. Drift or unknown
outcomes stop recovery. Rollback retains the new startup fence while restoring
dependencies and the baseline receipt, then restores the baseline supervisor
last. The mode admits only the original full baseline; a
second notification-only upgrade needs a separately reviewed owner contract.
The journal is a private deployment artifact under the workspace's
`.openclaw/tmp/`; it cannot target runtime source, the ledger or run state.

## Explicit stopped-run recovery

Read the authoritative same active lease and all item bindings. Probe the
existing run to obtain its persisted `checkpoint_sha256`, then explicitly resume:

```sh
python3 scripts/youtube_global_windows_canary.py probe --canary-id <existing-id>
python3 scripts/youtube_global_windows_canary.py resume --canary-id <existing-id> \
  --checkpoint-sha256 <digest-from-fresh-probe>
```

The coordinator serializes resume with reconciliation and lease coordination.
It requires exact node identity/current connectivity, staged pins, free OS lock,
stopped worker and the same checkpoint bytes. The adapter passes that digest
through scalar argv; the worker repeats validation under its lock before PID,
attempt or archive changes. Only `Resume` supplies `--resume-blocked`; cron's
launch path cannot authorize a stopped/blocked checkpoint. Valid archives and
terminal skips are reused; attempts and prior logs are retained.

Initial staging is prepared in a private sibling directory and atomically
published with all source pins, a free OS lock and a pending checkpoint before
worker startup. Interruption before publication leaves no authoritative chunk;
interruption after publication uses the same explicit recovery above. Private
preparation trees are preserved. A retained/reused PID never overrides the OS
worker lock when determining liveness.

Each Windows archive attempt waits at a private stdin fence until it belongs to
a worker-owned Job Object. Descendants stay in that job; timeout cleanup waits
for the job to become empty before another attempt, and worker death closes its
non-inherited handle and kills the descendants. Unconfirmed cleanup stops the
worker. All pipe waits are bounded. Native validation exercises these paths
with temporary Python process fixtures and no provider calls.
Metadata diagnostics and offline runtime preflight use the same contained
launcher, so their timeouts cannot leave provider/runtime descendants behind.

GCP pool records and prepared journals sync both temporary file contents and
the renamed directory entry before reporting success. Newly created parent
directories and audit-event appends are synced as well. Scheduler launch
budgets count launch evidence, never unlaunched preparation conflicts.

Resume/StageLaunch RPCs are never retried automatically. An uncertain dispatch
is journaled. Repeating its checkpoint token returns `already_requested`; observe
and reconcile before any separately authorized new recovery. Do not erase that
receipt, infer lease expiry from age, release/reassign the lease manually, reset
a circuit or create a replacement batch. Fresh source circuits stop and report
their sanitized primary error.

Reconciliation first replays a matching local validated import/finalization
journal when ordinary lease completion was interrupted. Bundle/receipt/projection
hashes, outcome partition and item/lease/chunk preimages remain fenced. This
repairs both manifest and queue projections without requiring an active lease,
repackaging or replaying archived videos.

Import limits apply to compressed bytes (16 MiB), the complete decompressed tar
(128 MiB), each member (16 MiB), aggregate extracted bytes (96 MiB) and member
count (4096), including streamed gzip/zstd expansion before tar parsing. Validated
terminal outcomes are persisted into both personal and YC source projections;
blocked/incomplete items remain pending.

## Incident notification ownership

`cron` and `cron-reconcile` share the supervisor's notification operation.
The standalone Python supervisor owns `windows-notifications.sqlite3` beneath
the existing pool root; it does not open OpenClaw's control-plane database or
execute SQL on the Gateway thread. Its small SQLite schema and transactions
are external-worker primitives, with schema identity checked at admission,
EXTRA synchronization, and durable directory creation. It retains incident
tombstones rather than pruning and later rediscovering an old failure.

An incident includes the production run, its existing lease, failure
classification and affected video. Routine reconciliation timestamps, polling
counts and worker PIDs are excluded. One initial attention notice is reserved;
unchanged checks print `NO_REPLY`, with no scheduled reminder. A previously unseen
failure or affected video produces one updated notice. Returning to an already
reported incident after a restart stays quiet. A running worker may produce
one progress notice per incident, which explicitly says completion is unvalidated.
Repeated recovery attempts do not repeat that notice. Recovery
requires the matching validated import, committed canonical finalization journal,
completed lease/chunk, matching completed queue and cleared item bindings. Healthy historical runs do not
produce new success notices. Unrecognized classifications use bounded closed
text and retain distinct stable fingerprints; genuine supervisor/state failures
remain visible through the existing failed-closed path.
Partial-run notices derive classification and counts from the matching validated
import outcomes, including changes to any unfinished item, rather than a retained
pre-recovery manifest reason. Raw item diagnostics never enter the fingerprint.

Notification writers serialize across both jobs and process restarts. The
supervisor rereads lifecycle facts under its existing supervisor/coordinator
locks, commits the incident/event reservation, then writes stdout and records
`emitted` or `uncertain`. `reserved` can mean a process died before stdout.
These states describe **at-most-once emission attempts**, not exactly-once
WhatsApp delivery. A crash after reservation can lose a notice; a failed or
partially written stdout result is not automatically replayed.

The deployed command-job contract has no reliable recipient acknowledgement:
its positive delivery receipt can include downstream suppression, and its
negative receipt can include a partial send. Missing or failed scheduler
receipts therefore cannot authorize an automatic resend. Investigate an
uncertain event through the existing scheduler history and incident reference;
any further external notification requires its own authorization. The helper
never sends a message itself or alters scheduler delivery settings. Inspect
stored summaries without writes using:

```sh
python3 scripts/youtube_global_windows_supervisor.py notification-status
```

This source repair adds one managed helper to the versioned release inventory.
Full-bundle activation requires the existing between-run boundary. It cannot
replace source/configuration beneath an active pinned run. The explicit
notification-only variant above preserves those pins and uses its own narrow
admission in the same owner. Never recover extraction merely to open a
notification deployment boundary.
Preserve notification state on rollback so an old incident is not re-emitted.

## Opt-in GCP rate-limit recovery

This source adds finite recovery eligibility, not permission to extract. Installing
it leaves all grants unarmed. Existing new-batch launch limits are unchanged.
An elapsed wait alone never clears a source restriction or authorizes a Resume.

The existing GCP coordinator owns one checkpoint-bound grant per run. Its normal
five-minute reconciliation job can consume an explicitly approved grant once:

- First recovery: at least four hours after the immutable native 429 occurrence.
- A proven new 429 stops the worker again. A second recovery needs a different
  approval reference and at least eight hours after that new occurrence.
- At most two durable dispatch intents for the entire run, including legacy
  requests and uncertain outcomes. Changing video/checkpoint or restarting does
  not replenish this budget. Readiness failure before intent consumes no slot.
- A grant expires 24 hours after approval. Routine polls never extend its due or
  expiry times. Offline/busy readiness can wait until expiry; changed bindings,
  checkpoint or failure class hold the grant for review.
- Keep the three-attempt per-video cap. An exhausted rate-limited item holds
  before dispatch, rather than letting the worker pass it and extract later items.
- A validated optional UTC `--retry-after-at` can only extend the policy wait.
  A deadline more than 24 hours after the occurrence holds instead of being
  shortened. Current extractor stderr does not preserve HTTP headers; do not
  infer a returned reset time or make a provider call to obtain one.
- Auth, bot, configuration, interruption and unexpected failures cannot arm rate
  timers. Their existing explicit manual recovery contracts remain separate.

After separate recovery authorization and a fresh supported Probe, an operator
can arm a single future continuation without immediately calling Resume:

```sh
python3 scripts/youtube_global_windows_canary.py arm-rate --canary-id <existing-id> \
  --checkpoint-sha256 <fresh-digest> --approval-reference <recorded-one-attempt-approval>
python3 scripts/youtube_global_windows_canary.py recovery-status --canary-id <existing-id>
python3 scripts/youtube_global_windows_canary.py cancel-rate --canary-id <existing-id> \
  --checkpoint-sha256 <armed-digest>
```

The explicit `resume` command accepts the same `--approval-reference` and optional
`--retry-after-at`; it creates a rate grant if absent and dispatches only if due
and freshly fenced. Existing non-rate manual Resume remains checkpoint-bound.
A dispatched checkpoint always returns `already_requested`, never a second RPC.
Expired/held receipts cannot be renewed by polls or overwritten with a new grant;
operator review is required. Cancel changes only an undispatched grant to held.

`resume-requests/<checkpoint>.json` remains the external-tool request contract,
now with v2 approval/occurrence/deadline/ordinal fields. Existing v1 receipts stay
byte-exact and count toward the run-wide budget. The owner validates at most 64
receipts, 64 KiB each and 1 MiB total; malformed or excessive histories hold.
The same per-run reconcile and pool coordinator locks serialize CLI, cancellation
and both supervisor paths. After awaited readiness, the owner rereads authority
and writes/fsyncs intent before the one no-retry adapter RPC. A lost reply retains
uncertain intent. Only observation/normal reconciliation follows; no replay.

Fresh checks preserve the active lease, every item/node binding, the stopped
worker/free OS lock, staged worker/adapter/URL/native pins and checkpoint bytes.
Valid archives, terminal skips, attempts and logs are reused. Successful output
uses the existing validated packaging/import/finalization path. No lease reset,
replacement batch, credential change, Windows install or notification mutation
belongs to this recovery.

The separate `--coordinator-only --baseline-deployment <installed-receipt>`
deployment variant can update only GCP canary/supervisor/source verification and
the deployment receipt while preserving a stopped run and all native/notification
bytes. It validates the exact installed e9 notification or compatible coordinator
baseline, captures resume-request directory absence/content/modes, and refuses
armed or unconfirmed intent. Full-bundle and notification-only deployment
contracts remain unchanged. Activation and recovery need separate approvals;
activation never arms a grant.

## Offline tests

Use the workspace's approved `openclaw-worktree-test-isolated` helper against
the full fork worktree, with its existing local image and no-network container:

```sh
python3 -m unittest discover -s deploy/youtube-worker/tests -p 'test_*.py' -v
```

Run the canonical toolkit archive tests in the same disposable environment
using separately staged exact source inputs. Never bind dependencies from the
live Gateway or execute uploaded candidate tests in that container.

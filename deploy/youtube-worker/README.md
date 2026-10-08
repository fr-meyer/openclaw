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
Activation continues to require the existing between-run boundary. It cannot
replace source/configuration beneath an active pinned run. Prepare the exact
release, review and offline evidence now; separately approve same-run recovery
and normal finalization before attempting a later idle deployment boundary.
Preserve notification state on rollback so an old incident is not re-emitted.

## Proposed bounded rate-limit recovery policy

This notification repair does not install a retry timer or authorize extraction.
`waiting_network_cooldown` currently opens a circuit and exits without a
deadline. New-batch launch intervals and daily limits do not define HTTP 429
recovery timing. Elapsed waiting is eligibility for an approved attempt, never
proof that the source restriction cleared.

A separately reviewed coordinator policy can use these finite bounds:

- First explicit recovery: not before four hours after the immutable recorded
  429 occurrence, with fresh same-lease/checkpoint/node/lock/pin proofs.
- A new 429 stops immediately. A second recovery requires separate approval
  and eight hours after that new occurrence. Permit at most two recovery
  dispatch intents for the entire run, including uncertain outcomes, across
  changing videos and checkpoints; do not replenish that budget on restart.
- Preserve the existing per-video attempt cap. If the rate-limited item already
  exhausted it, hold for review instead of skipping it and continuing extraction.
- A valid future structured `Retry-After` must never be shortened. A value
  beyond a proposed 24-hour planning horizon becomes a manual hold, not a
  downward-clamped wait. The current stderr-only contract does not retain this
  header, so no returned reset time can be inferred from it.
- Bot, authentication, configuration and unexpected failures remain explicit
  manual holds. No timer, circuit reset, replacement batch or route change
  can authorize their recovery.

Implement any future deadline/budget in GCP's existing coordinator and recovery
receipt contract, leaving Windows checkpoint bytes and staged components intact.
Routine polling must not move the immutable occurrence/deadline. Reuse the
existing durable intent-before-RPC/no-replay semantics, and consume no recovery
slot for readiness failures before dispatch.

## Offline tests

Use the workspace's approved `openclaw-worktree-test-isolated` helper against
the full fork worktree, with its existing local image and no-network container:

```sh
python3 -m unittest discover -s deploy/youtube-worker/tests -p 'test_*.py' -v
```

Run the canonical toolkit archive tests in the same disposable environment
using separately staged exact source inputs. Never bind dependencies from the
live Gateway or execute uploaded candidate tests in that container.

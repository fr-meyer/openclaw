# Grouped stable candidate: production 9.4 to 2026.10.5

The image seal inspects the loaded OCI image with the network disabled. It
requires selected plugin descriptors and compiled entries, checks Codex plugin
host/API and Doctor contracts, and verifies the actual bundled CLI against the
exact source dependency: **Codex 0.160.0** for this candidate. The bounded native
app-server initialize/initialized handshake must report that version and exit
cleanly. This integration uses the app-server protocol, without a separate
Codex SDK dependency. The external-binary compatibility floor of 0.149.0 does
not replace the exact bundled version. Workboard's packaged SQLite worker must
write/read synthetic data and close through its native broker. Results stay in
the image receipt. These offline checks do not prove an authenticated model turn
or a data migration; the native Doctor rehearsal supplies migration proof.

Source-only preparation, updated October 21, 2026. The failed 9.8 rehearsal is
retained evidence only; production remains under its separate owner. This file
does not select a deployable source, publish an image, or authorize production.

## Existing owners and source anchor

- Reuse fork [release-pipeline PR #15](https://github.com/fr-meyer/openclaw/pull/15)
  and its grouped preparation follow-up
  [PR #17](https://github.com/fr-meyer/openclaw/pull/17) for tooling.
  [PR #18](https://github.com/fr-meyer/openclaw/pull/18) owns the isolated
  10.5 product source. The 9.9 owner has
  [`prep/v2026.9.9-source-only`](https://github.com/fr-meyer/openclaw/tree/prep/v2026.9.9-source-only).
  Continue these existing work items rather than creating another candidate.
- The official signed tag [`v2026.10.5`](https://github.com/openclaw/openclaw/releases/tag/v2026.10.5)
  peels to `1b58cb9a1b4f4353e1add63c8506db4d890962e8`. Its tagged
  `package.json` says version `2026.10.5`, Node `>=24.16.0 <25 || >=26.1.0`,
  and `pnpm@12.9.0`. Verify the retained tag/signature receipt before admitting
  a candidate.
- Reconcile [9.9](https://docs.openclaw.ai/releases/2026.9.9) and stable
  [10.1](https://docs.openclaw.ai/releases/2026.10.1),
  [10.2](https://docs.openclaw.ai/releases/2026.10.2),
  [10.3](https://docs.openclaw.ai/releases/2026.10.3),
  [10.4](https://docs.openclaw.ai/releases/2026.10.4), and
  [10.5](https://docs.openclaw.ai/releases/2026.10.5) behavior into the final
  target. Do not apply beta tags. [`9.33`](https://github.com/openclaw/openclaw/releases/tag/v2026.9.33)
  is a separate gateway-only extended-stable September line. GitHub's official
  10.4...10.5 compare is diverged (2,704 ahead, 463 behind); reconcile content
  and patch intent against the exact 10.5 tree rather than merging tag history.

## Stable release content reconciliation

The following upgrade, recovery and security owners were inspected in the
exact official 10.5 base. They retain the listed stable-release behavior.
This is a scoped content check, not a claim that every divergent commit is
equivalent. The fork patch ledger separately records each custom behavior.

| Stable release | Behavior retained in the 10.5 base                                                                                                                                                                                   | Source owner and remaining qualification                                                                                                                                                                                         |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 9.9            | Snapshot timestamp drift is admitted only after file identity and content checks. Read-only opening of corrupt agent databases preserves quarantine recovery.                                                        | `src/infra/sqlite-snapshot-file.ts`; `src/state/openclaw-agent-db-readonly-open.ts`. Native backup/restore remains required.                                                                                                     |
| 10.1           | State schema 20 defaults historical delivery attempts to unknown; interrupted one-shot recovery requires proof that delivery never started.                                                                          | `src/state/openclaw-state-db-cron-delivery-migration.ts`; `src/cron/store/run-recovery.kernel.ts`. Restart and rollback must not replay uncertain sends.                                                                         |
| 10.2           | Unsupported native cloning supports a guarded byte-copy fallback; owners supplying `beforeByteCopy` admit space before that fallback. Built-in credential redaction scans complete text across old chunk boundaries. | `src/infra/sqlite-file-copy.ts`; `src/logging/redact.ts`. Preserve native copy guards; check representative installed-provider compaction behavior separately.                                                                   |
| 10.3           | Prepared update rehearsals defer bookkeeping version stamps while retaining real config migrations. pnpm service entrypoints prefer the verified stable package link.                                                | `src/config/io.meta.ts`; `src/daemon/program-args.ts`. Qualify the installed updater against the candidate; candidate fixes cannot change an already-running old updater.                                                        |
| 10.4           | Doctor can admit an already prepared private disposable copy. Tlon distinguishes group-DM claims from privileged sender identity.                                                                                    | `src/commands/doctor-update-rehearsal-inventory.ts`; `extensions/tlon/src/monitor/index.ts`. Check configured policy plugins; older pending Tlon DMs without recorded sender provenance require the documented resend procedure. |
| 10.5           | Agent schema 25 moves canonical-session validation to its writer contract. EmbeddingGemma format changes trigger a one-time rebuild only for affected indexes.                                                       | `src/state/openclaw-agent-canonical-validation-migration.ts`; `extensions/memory-core/src/memory/manager-reindex-state.ts`. Doctor, startup and applicable memory rebuild still need runtime proof.                              |

The stable schema progression is 9.9 state 19/agent 24, 10.1 state 20,
10.4 agent 24, and 10.5 agent 25. A history entry first naming a beta is
not the stable introduction date. Keep both Codex compatibility checks:
the documented installed-plugin minimum 2026.9.7 and the selected plugin's
host/API requirements for 10.5. Workboard's pre-July data bridge and
Sessionsboard data also need their native plugin migration/rollback contracts;
do not silently import or discard older plugin data.

## Migration and qualification boundaries

- The direct 9.4-to-10.5 transition must admit the actual input schemas and
  migrate to shared state schema 20 and agent schema 25. Native Doctor and
  startup must validate the complete migration on a disposable copy of a
  **fresh current-production backup**.
  Schema 20's cron delivery-attempt fence leaves uncertain sends unknown;
  never replay them merely because a rehearsal or rollback restarted. Rollback
  needs the matching pre-upgrade data and build, and must account for writes
  accepted after capture.
- If EmbeddingGemma is configured, the 10.5 formatting change requires its
  documented one-time vector rebuild. Do not apply that work to installations
  that do not use it. Check the installed OpenClaw Codex plugin against the
  official 2026.9.7 minimum, verify the separately pinned CLI version as above,
  and inspect policy plugins before activation.
- Build the product from the exact official base plus a reviewed ordered fork
  patch queue. Reconcile each retained 9.8/9.9 behavior against 10.5's source,
  including migration, state ownership, host compatibility, Workboard, backup,
  packaging, and regression owners. The existing seed inventory is incomplete;
  unresolved entries remain blocked. Keep the product source, trusted tooling,
  metadata seal, and OCI digest distinct in evidence.
- Use one isolated rehearsal from a verified snapshot or disposable restore,
  native Doctor, bounded patch and producer/consumer tests, startup/readiness,
  and a fenced rollback exercise. Keep application logs and native output with
  timestamps and phase/stall observations. Liveness alone is not evidence of
  migration progress. Measure comparable elapsed time and I/O before calling
  a path faster or optimized. Preserve all native integrity and security checks.
- Capture a new current-production backup and validate its identity, freshness,
  retention, completeness, and restore before any future activation. A prior
  test copy must never replace live data. The private adapter and durable GCP
  execution/resume path need disposable proof and one owner before production
  eligibility can change from false.

## Apply the 9.8 rehearsal experience

The test database isolates data mutations. Its host, scratch files, Docker
storage and I/O still need separate resource accounting. A stale host-free-space
observation must not become a permanent admission rule.

1. **Prepare once.** Finish the patch decisions, focused tests and exact source
   seal before producing the image. Preserve the OCI payload, digest, plugin
   evidence and producer receipt so a retry does not rebuild the candidate.
2. **Restore once.** Prefer an identified snapshot restore over repeated file
   copies. Keep database files, native backup outputs and temporary files on
   the owned rehearsal disk. Measure free space on that filesystem separately
   from the host root; a small emergency floor is not a forecast of native
   backup space. Reuse a retained restore only after its owner has released it
   and its receipt matches the intended starting data.
3. **Distinguish the upgrade path.** Rehearse directly from current production
   9.4 to grouped 10.5, using an identified fresh 9.4 snapshot and its actual
   starting schemas. Skip 9.8 as an intermediate release. Preserve its failed,
   partially migrated copy as evidence; do not reuse it as rehearsal input or
   treat it as qualification of the direct path.
4. **Run durably.** A GCP-owned supervisor holds the operation lease and
   records phase, exact process/container identity, timestamps and exit
   receipts. The Mac submits or observes the operation; its connection does
   not own the native process. Resume reconciles the existing operation before
   launching anything.
5. **Show native evidence first.** Surface timestamped application output,
   then process liveness, CPU/I/O and last-output time. A silent SQLite backup
   verification can still be active. Report a stall or uncertainty without
   treating liveness as completion or skipping native integrity checks.
6. **Prove the complete cell.** Test the installed upgrade driver against the
   candidate, native Doctor/migration, startup/readiness, and rollback with
   the matching pre-upgrade data and build. Preserve unknown delivery outcomes.
   A later production operation must capture and migrate current live data;
   it must never promote this rehearsal database.

Bounded source tests may use a separate secretless container and synthetic
state on existing approved capacity. They do not mount production data or the
retained failed 9.8 copy. A full restored-data rehearsal is a separate operation
with an exact resource plan and owner; new paid resources or persistent access
require their own approval.

## Current disposition

The pipeline's manual job is being changed to read trusted `main` tooling and
an exact candidate metadata head, with a current PR head/base check. It still
needs hosted proof after reviewed integration. The grouped source queue is
under review in PR #18, with its per-path reconciliation and qualification
state kept in `custom-patches/`. No production-eligible manifest, sealed 10.5
OCI artifact, native restored-data rehearsal, rollback proof, comparative
benchmark, or production decision is claimed here.

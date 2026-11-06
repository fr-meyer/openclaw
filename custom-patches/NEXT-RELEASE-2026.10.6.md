# Next grouped release: OpenClaw 2026.10.6

Status: draft source preparation; production ineligible. This branch is stacked
on the 10.5 source PR and prepares the following deployment group. It carries
no 10.5 runtime, image or data qualification forward.

## Frozen inputs

| Input | Exact identity |
| --- | --- |
| Official stable release | [v2026.10.6](https://github.com/openclaw/openclaw/releases/tag/v2026.10.6), published 2026-10-22 12:53:10 UTC |
| Annotated tag object | `3494baecba2366a89fa703158a2c2b5c9edcd6ba` (GitHub reports verified signature) |
| Upstream source | `fe06181dc5ecc01cf8904abbfc26925925efefbc` |
| Upstream tree | `de35137f62064ebdfd93c7d146b78b05a0332ff1` |
| Common upstream 10.5 base | `1b58cb9a1b4f4353e1add63c8506db4d890962e8` |
| Carried fork source | `7f3ac1fbfd3691546c5b1fd247680a3d00851c76`, from [PR #18](https://github.com/fr-meyer/openclaw/pull/18) |
| Pipeline dependency | [PR #17](https://github.com/fr-meyer/openclaw/pull/17); future exact 10.6 binding pending |

The official target is a direct descendant of official 10.5: 294 commits ahead,
zero behind, 1,669 changed paths. The fork contributes 22 commits and 142 changed
paths relative to that common base. The inventory records all 142 paths by exact
base/fork/target/result blobs, including 13 paths changed on both sides. Two
textual conflicts were resolved: Doctor backup handling and a CLI test fixture.
The retained 10.5 reconciliation file is historical evidence.

If PR #18 advances before the next release freezes, compare its new commits and
explicitly reconcile them here. This draft does not move the active 10.5 branch.

## Carried fork behavior

- Managed-flow authority, exact cancellation claims, recovery, packaged Mergeguez
  controller parity and authenticated worker-namespace readback.
- Superseded worktree lease fencing, config backup rotation and memory cancellation.
- Egress header/failed-upgrade protections, MCP/Nowistay compatibility and process
  identity cleanup.
- STRICT ANY vector migration and slow embedding authority-renewal spacing.
- Full source/image identity checks and the original restricted backup-reuse path.
- Pinned native acquisition, offline candidate execution, inert publisher,
  native addon checks, Node 24.22.1 and compiler serialization.
- Dreaming/cron phase diagnostics from the current 10.5 source.

`reconciliation-2026.10.6.json` is the complete path inventory. Exact byte
retention establishes source preservation; tests against changed dependencies
remain necessary. No current-main integrity optimization is claimed included
without ancestry or content proof against this stable commit.

## Compatibility and limits

| Area | Target contract and remaining evidence |
| --- | --- |
| Schemas | State 20 / agent 25 remain unchanged; recovery behavior changes, so all applicable stores still need native migration/completion inspection. |
| Runtime | Node `>=24.22.1 <25` or `>=26.12.1`; pnpm 12.15.0 with its package.json integrity pin. |
| Codex | Managed binary remains 0.160.0; plugin API/build metadata advances to 2026.10.6. External app-server floor 0.149.0 is a separate contract. Verify actual binary, plugin and bounded offline protocol initialization. |
| Workboard | Peer floor `>=2026.10.6`; test parent-completion claim eligibility for review/running cards and persistence. |
| Matrix / Nowistay | Matrix crypto remains 0.6.6 with matching asset hashes; MCP SDK remains 1.32.0. Native addon and retained SDK regressions remain required. |
| Reuse | `REUSE_NOT_QUALIFIED_10_6`: the existing parser accepts only its reviewed 10.5 transition. Normal new-release backup capture remains available without that proof. Cross-version reuse needs a reviewed compatibility path; do not relabel receipts or change the allowlist to pass. |
| Startup wait | Upstream `src/plugins/services.ts` is byte-identical between 10.5 and 10.6. Dreaming still awaits cron reconciliation; no fix for the current service wait is established. |
| Pipeline | This source planner identifies 10.6. The active executor/profile/receipt contracts remain owned by PR #17; future exact binding and synthetic qualification are pending. |

10.6 adds eligible missing-deletion-journal recovery with verified originals even
in disposable rehearsals. The merged backup owner requires both
`!crossBuildReuse` and `!requireSnapshots` before accepting previously verified
snapshots. A migration reuse proof cannot authorize a same-schema repair.
Final Doctor inspection checks required held stores before completion. Its new
container-local sealed original-capture marker avoids only that repeated capture;
repair backups and integrity still run. TMPDIR scratch routing applies when
`OPENCLAW_UPDATE_IN_PROGRESS=1`; standalone Doctor needs its own path assessment.

## Qualification sequence

1. Reconcile any later required 10.5 fixes, then freeze source, lockfile,
   Dockerfile, plugins and future pipeline SHA. In an isolated supported runtime,
   install pinned dependencies and run focused backup/recovery, CLI, managed-flow,
   worktree lease, egress, memory migration, Workboard and Nowistay tests. Added
   backup cases cover required snapshots despite prior verification, same-schema
   repair refusal with a reuse proof, and refusal of that proof on 10.6.
2. When the shared execution owner releases capacity, build/seal one immutable
   image through the existing GCP route with reviewed admission. Check OCI
   provenance/SBOM, actual Node/pnpm/Codex, plugin payload and native tools.
   Preserve cache and reconcile uncertain operations before another attempt.
3. The sole rehearsal owner chooses a READY daily production snapshot and an
   owned disposable clone. Bind image, snapshot and database generation, and
   executor. Preserve the current 10.5 clone/backups until its owner releases them;
   do not manually reconstruct selected database files.
4. Run the existing metadata-only hygiene assessment once for the bound inputs,
   recording skip reasons. No implicit writable status, full scans, reset,
   reindex, compaction, retention deletion or provider calls. Optional maintenance
   requires evidence, scoped authorization and capacity.
5. Run native Doctor with integrations disabled and required backup/integrity,
   timestamps, phase progress and memory/disk/pressure telemetry. Reassess fresh
   capacity; the intended future I/O profile is 320 MiB/s read / 128 MiB/s write,
   verified on the actual parent device. Never change an active operation's profile.
6. Verify every applicable agent's migration completion, startup/reopen without
   unexplained repeat migration, selected indexed legacy reads and synthetic
   Workboard/managed-flow behavior. Keep external queues, leases, downloads,
   cookies and messages disabled. Reuse receipts only under valid provenance.
7. Record measured elapsed time, peaks, disk use and startup results. On identity
   drift, OOM, integrity failure, incomplete recovery, lost ownership or unhealthy
   startup, preserve diagnostics and resumable data; classify reuse before retry
   and never delete incomplete artifacts automatically.

Production promotion requires separate cutover approval after qualification. Use
the current production database, a fresh matching backup and exact promoted image;
the rehearsal clone never replaces live data. Keep the prior immutable build and
matching generation for recovery. Restore/startup duration remains unknown until
measured; this plan does not reintroduce the previously held extra rollback test.

## Evidence status

Source review covers all 13 overlap paths and both conflict resolutions.
123 standalone helper/controller cases passed across focused runs (about three
seconds total). Three Matrix loopback cases first failed with sandbox EPERM, then
passed with loopback permission. This is helper proof on Node 24.18.0, not target
runtime qualification. Independent review results are recorded in the draft PR
at its exact head. Pending: supported-runtime dependency-backed tests, 10.6
executor qualification, image build/seal, native real-data rehearsal and startup.
Local Node 24.18.0 with no pnpm/node_modules cannot supply 10.6 runtime proof.

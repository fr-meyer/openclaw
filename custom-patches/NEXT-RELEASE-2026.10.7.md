# Future grouped release: OpenClaw 2026.10.6 + 2026.10.7

Status: draft source preparation, production ineligible. This group succeeds
[PR #19](https://github.com/fr-meyer/openclaw/pull/19) and its dependency repair
[PR #24](https://github.com/fr-meyer/openclaw/pull/24). Current 10.5 images,
rehearsals, receipts and production are unchanged. Their qualification does not
transfer to this branch.

## Exact inputs and patch reconciliation

| Input                                    | Identity                                                                                                                                                         |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Official stable release                  | [v2026.10.7](https://github.com/openclaw/openclaw/releases/tag/v2026.10.7), published 2026-10-24 09:53:46 UTC, not prerelease                                    |
| Verified annotated tag object            | `5c101ce5a0637df375c5f6ae49d44d0d27cc26b1`                                                                                                                       |
| Official source / tree                   | `157d8c2bc3ea2fa183afdc11088e69690bf8e64e` / `0885f6473945093107db1406d9a2ad5259db10e7`                                                                          |
| Official 10.6 ancestor                   | `fe06181dc5ecc01cf8904abbfc26925925efefbc`                                                                                                                       |
| PR #19 source                            | `a39cad2d97efae7d0c832af3d71e6ccc86f60e50`                                                                                                                       |
| PR #24 security successor / first parent | `8a2300c841024443fb38954d65eb5bff1229c0a0`                                                                                                                       |
| Later reviewed dependency repairs        | [PR #26](https://github.com/fr-meyer/openclaw/pull/26), `85a9bdc1285c338f10f5ca818abc259f6d483b5b`; only dependency, patch and relevant test-owner paths carried |

Official 10.7 adds 73 commits without divergence from 10.6. The uncommitted merge
needed no textual conflict resolution. The previous 142-path 10.5 carry inventory
and PR #24's additional hardening remain included. The new
`reconciliation-2026.10.7.json` records all 223 retained fork/security/test paths with
exact original, upstream and result blob identities. The initial merge retained
137 exact carries, 2 reviewed upstream overlaps, 4 release-binding adaptations
and 76 security carry paths (26 exact, 50 merged). A subsequent scoped development
dependency refresh and its owned regression are recorded explicitly. No custom
fix is claimed upstreamed or retired.

The two new overlaps are:

- `src/state/openclaw-state-worker-contract.ts`: retain managed-task worker
  operations and upstream typed `refused-before-open` / `unknown` lease cleanup.
- `test/vitest/vitest.gateway-server-paths.mjs`: retain all four fork runtime
  cases and both new upstream test routes.

The prior 10.6 inventory remains historical evidence. Source preservation is
distinct from dependency, native image and real-data qualification.

## Compatibility and security disposition

- **Database contracts:** state 20, agent 25 and admission protocol 1 remain
  declared. Recovery and maintenance behavior still changes; equal version
  numbers do not establish equivalent migration or resume behavior.
- **Doctor:** 10.7 adds preflight provenance reuse, invalidated by relevant
  configuration/plugin changes, work or warnings. This differs from our
  cross-build backup reuse. Upstream backup/reuse and STRICT ANY migration paths
  remain unchanged from 10.6, so retain the fork's safety fixes. The existing
  cross-build proof deliberately refuses this release; cross-version reuse needs
  separate reviewed compatibility evidence, never relabeled receipts.
- **Leases:** exited-agent cleanup distinguishes a refusal before opening from an
  unknown outcome. Preserve unrelated active readers and exact ownership checks;
  test these alongside fork managed-task operations.
- **Runtime/plugins:** Node 24.22.1+ within 24.x or 26.12.1+, pnpm 12.15.0,
  managed Codex 0.160.0. Plugin metadata and Workboard peer floor advance to 10.7.
  Do not combine older core images and newer plugins without qualification.
- **Native acquisition:** fs-safe advances 0.25 to 0.26. Its exact native assets,
  offline acquisition and image smoke remain unqualified here. Matrix crypto
  0.6.6 and MCP SDK 1.32.0 remain pinned.
- **Carried dependency repairs:** DOMPurify 3.4.17, markdown-it 15.0.3, Vite 8.3.3;
  Zod 4.6.6 with bounded retained v3 parsing and native A2UI/Discord migrations;
  reviewed parent-scoped MSAL 7.1.0 and Undici 8.12.2; Express-scoped body-parser
  2.4.0 with its qs 6.16.1 child while other consumers retain qs 6.16.0.
  Exact A2UI 0.12.0, Discord 2.5.0, Azure Identity 4.13.3 and Teams Apps 2.1.0
  consumers match the previously reviewed patches. Real managed-identity
  authentication is not newly qualified by the synthetic fixture.
- **Package age:** global strict 10,080-minute policy remains enforced. Preserve
  only the approved exact body-parser 2.4.0 exception, with manual removal after
  2026-10-29 11:39:38.614 UTC. No global age reduction or audit suppression.
- **Startup:** upstream `src/plugins/services.ts` is unchanged from 10.6. This
  release does not establish a fix for the existing plugin-service startup wait.
- **Memory Wiki:** reimport preserves the designated human Notes block, not
  arbitrary generated content. Marker/preservation regressions belong in the
  focused future qualification set.

The development-only Sigstore → make-fetch-happen 16.0.1 cache dependency is
refreshed from http-cache-semantics 4.2.0 to 4.3.0 within its declared ^4.1.1 range.
Version 4.3.0 was published October 4 and needs no age exception. This removes the
reported range for [GHSA-ch52-4w7c-c8xp](https://github.com/advisories/GHSA-ch52-4w7c-c8xp);
the vendor [disputes the advisory](https://github.com/kornelski/http-cache-semantics/issues/56),
and the exact package diff does not change max-stale handling. This is a compatible
dependency refresh, not a claimed causal fix or demonstrated production exposure.
Tests cover the actual package identity, cache API/serialization, private/no-store
storage exclusions and own-property/wildcard Vary behavior. Audits remain enforced.

Upstream release validation/npm preflight passed the release source, but its
ClawHub submission failed. That distribution defect is separate from core source
and image qualification; do not describe all upstream distribution as green.

## Evidence and remaining qualification

The original source cut retained189 focused fixture passes and the original exact
review/CI evidence at `cfd2ae456c13effacfeff797a469c39437eeb092`. The later
test-only successor changes no runtime implementation, manifest, dependency or
lockfile. The original results remain historical at that head.

A private-inode frozen workspace was then reconciled with Node24.22.1 and
pnpm12.15.0, lifecycle/pnpmfile hooks disabled. The exact fs-safe0.26 package
and Darwin ARM64 helper match registry and frozen-lock SRI, with every installed
package file verified. Source/workspace resolution stays within the owned10.7
checkout; the baseline10.6 installation remains unchanged. This is Darwin
source-test proof, not Linux image or all-native-addon qualification.

Additional focused evidence:

- 12 existing lease registration/cleanup cases pass.
- 8 new native in-memory SQLite/Kysely owner cases protect refusal-before-open
  verification retention, unknown-outcome invalidation, exact receipt identity,
  idempotence and refusal ordering. Only the separate verification-store side
  effect is mocked; actual lease rows are inspected within the original transaction.
- 5 new actual Doctor provenance-handoff cases preserve proof only for unchanged
  config without writes/plugin-generation changes, and refuse missing proof.
- 3 selected native Doctor preflight cases pass (16 explicitly filtered), covering
  restored legacy plugin refusal, real legacy-session repair/backups and unchanged
  config/plugin reads. The original cold full-file command timed out at180seconds
  after setup and5 observed passing cases; that attempt remains incomplete. The
  case active at timeout later passed6.67seconds in the selected warm command.
  Do not describe the selected pass as a full-file fix or full Doctor qualification.
- 1 managed-flow worker integration case passes. 23 MCP/Nowistay cases also pass
  through the maintained runner against the owned frozen install; these repeat
  the earlier23 and are not additional unique coverage.
- A separate exact-source capsule passes60 distinct Wiki cases:32 markdown,
  6 importer,8 ingest,10 read-retry and4 malformed-notes/pruning cases.

The full/core CI, testbox, Browser MCP, CodeQL and OpenGrep lanes remained skipped
on the draft source cut. Supporting CI passes do not replace them. Retain PR #19's
133-test and PR #24's196-test results at their original heads. No image,
real-data migration, startup or production acceptance is claimed.

Next steps, owned separately from the active 10.5 deployment:

1. Complete remaining full Doctor/backup/recovery, CLI/plugin and broader runtime
   qualification where needed. Resolve the cold full-file timeout with measured
   setup/test budgets before claiming full-file success. Qualify Linux amd64 native
   acquisition separately from Darwin source tests; keep maintained test ownership.
2. Bind the final reviewed source, Dockerfile, lockfile, plugins and a future
   exact pipeline revision. The two-parent merge source requires explicit
   ancestry validation; do not assume an old 10.6 or active 10.5 seal qualifies it.
3. Use reviewed GitHub-hosted source-only build and private unqualified-byte
   retention when configured/authorized. Do not spend the current 10.5 build or
   artifact allowance on this draft. Verify fs-safe/native assets, Codex executable
   and plugin, Workboard, OCI/SBOM/provenance and complete privacy adjudication.
4. The sole future rehearsal owner selects a READY production daily snapshot and
   disposable clone, then binds image/snapshot/data generation and executor.
   Keep the present 10.5 clone/backups intact. Run metadata-only hygiene with
   recorded skips; no implicit writable status, scan, reset, reindex or VACUUM.
5. Run required native Doctor/backups/integrity and startup/reopen checks. The
   intended future Doctor profile retains 320 MiB/s reads / 128 MiB/s writes,
   verified effective before a separately authorized launch. Record actual
   limits, peaks, stage timing and resumability; do not change active jobs.
6. Verify all applicable agents, selected legacy reads and synthetic Workboard/
   managed-flow persistence. Keep external queues, cookies, downloads and messages
   disabled. Recovery timing remains unknown until measured; the previously held
   extra rollback startup experiment is not silently reintroduced.

Production promotion requires a separate cutover decision and uses the then
current production database, not the rehearsal copy. This draft does not merge
main/master, provision infrastructure, activate maintenance or deploy anything.

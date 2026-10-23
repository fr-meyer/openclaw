# 2026.10.6 source-only merge proposal

This generator prepares separate inputs for [source PR #19](https://github.com/fr-meyer/openclaw/pull/19).
It preserves the active 10.5 candidate. `productionEligible` remains `false`;
generating inputs does not authorize an image build, rehearsal or production cutover.

## Frozen source

| Identity                                  | Exact value                                                        |
| ----------------------------------------- | ------------------------------------------------------------------ |
| Candidate merge                           | `a39cad2d97efae7d0c832af3d71e6ccc86f60e50`                         |
| Candidate tree                            | `47a3c1321ce39b50d22ec092054e54fd0afaa03a`                         |
| First parent / PR base: carried fork 10.5 | `7f3ac1fbfd3691546c5b1fd247680a3d00851c76`                         |
| Second parent / official stable 10.6      | `fe06181dc5ecc01cf8904abbfc26925925efefbc`                         |
| Official stable tree                      | `de35137f62064ebdfd93c7d146b78b05a0332ff1`                         |
| Sole common upstream 10.5 base            | `1b58cb9a1b4f4353e1add63c8506db4d890962e8`                         |
| Official annotated tag object             | `3494baecba2366a89fa703158a2c2b5c9edcd6ba`                         |
| Reconciliation blob                       | `186abc747081b09b8f7af58a37513b170af1f4b4`                         |
| Reconciliation SHA256                     | `c323daa5425d329578a392313de7677618d4fe5150ee8af399b75bd229bcf516` |

The source contract keeps official 10.6 as `baseCommit`. Its explicit `merge`
proof retains the common base, fork parent and reconciliation identity; the
candidate's ordered parents must be `[forkCommit, baseCommit]`. One applied
inventory entry represents the integration result. It does not pretend the
merge is a linear cherry-pick or replace the original semantic decisions.

Three comparisons remain separate:

- **142 paths:** the complete original fork changes against common upstream 10.5,
  retained verbatim in `semantic-reconciliation.json`, with all 22 carried commits.
- **144 paths:** the candidate's changes against official 10.6, covered by the
  generated inventory. The two additional paths are the next-release note and
  reconciliation JSON, explicitly identified in the merge evidence.
- **1,676 paths:** the PR-base-to-candidate review diff, including incoming
  upstream changes. `review.changedDiffSha256` uses the existing PR derivation
  owner and is not replaced with the smaller fork-ledger digest.

## Generate inputs

Use clean source and reviewed tooling checkouts. The source checkout must be at
the frozen merge above. The tooling checkout must include the reviewed merge
validator. The generator reads existing Git objects with lazy fetching and
replacement objects disabled; it executes no candidate code or tests.

Supply retained public PR identity and annotated-tag observations through the
existing approved acquisition route. No observation or verification timestamp
is fabricated. The generator requires the tag's reported verified signature
payload to match its local Git object, but does not itself perform a new API
query or cryptographic signature verification. PR `updated_at` is the upstream
PR update time, not the observation's acquisition time.

```sh
python3 scripts/fork-release/candidates/v2026.10.6-source-only/generate.py \
  --source "$SOURCE_CHECKOUT" \
  --tooling "$REVIEWED_TOOLING_CHECKOUT" \
  --pr-json "$PUBLIC_PR19_OBSERVATION" \
  --pr-observation-kind connector-pr-info \
  --upstream-verification-json "$UPSTREAM_106_TAG_OBSERVATION" \
  --upstream-observation-kind github-api-response \
  --output /tmp/openclaw-v106-seal-prep/a39cad2d97ef
```

The output must be a new directory. Existing proposal bytes remain unchanged.
It contains the manifest, one-entry patch inventory, original reconciliation,
merge evidence, unchanged supplied observations, annotated-tag bytes,
preparation context, native Nowistay prerequisite and an output hash manifest.
The context records the actual derivation tooling commit.

The `connector-pr-info` input uses the retained connector fields `url`, `number`,
`state`, `draft`, `updated_at`, `user.login`, `head`, `head_sha`,
`head_repo_full_name`, `base` and `base_sha`. The PR URL supplies the base
repository identity. Alternatively, `full-api-response` or
`public-identity-projection` uses GitHub API fields `number`, `html_url`, `state`,
`draft`, `updated_at`, `user.login`, and both `head`/`base` identities (`sha`,
`ref`, `repo.full_name`). The `github-api-response` tag input is the retained
official `/repos/openclaw/openclaw/git/tags/<tag-object>` response, including
its `verification` field. Alternatively, `tag-observation` uses
`openclaw.upstream-tag-observation.v1`, with repository, tag, tagObject, object
and `githubVerification` fields as in the existing 10.5 observation contract.
Adapters preserve supplied observation bytes unchanged. Missing observations
remain a prerequisite, not permission to invent them.

## Validate the resulting proposal

```sh
python3 scripts/fork-release/preflight.py \
  --manifest "$PROPOSAL/manifest.json" \
  --inventory "$PROPOSAL/patch-inventory.json" --metadata-only

python3 scripts/fork-release/preflight.py \
  --manifest "$PROPOSAL/manifest.json" \
  --inventory "$PROPOSAL/patch-inventory.json" --source-dir "$SOURCE_CHECKOUT"
```

Construction and metadata validation are not full source preflight. The latter
still requires an ordinary non-promisor checkout with every required object.
No full-preflight success is claimed for a partial checkout. Recheck the live
PR head/base and upstream identity at the later release admission boundary.
The 294-commit official stable path exceeds a generic 65-commit shallow fetch;
the workflow now acquires that history with `source_ancestry.py`: one fixed-origin,
depth-512 fetch with a 180-second timeout after the other shallow fetches. It
preserves checkout HEAD, rejects promisor repositories and verifies all relevant
ancestry. Missing history is refused, with no unbounded fetch fallback. An unrelated
shallow boundary at or before the declared common base is allowed. For an existing
ordinary checkout, the same normal entry point is:

```sh
python3 scripts/fork-release/source_ancestry.py \
  --manifest "$PROPOSAL/manifest.json" \
  --inventory "$PROPOSAL/patch-inventory.json" --source-dir "$SOURCE_CHECKOUT"
```

The hosted validation runtime is Node 24.22.1 for stable 10.6; retained lanes keep
24.21.0. This source preparation does not dispatch a hosted build.

Regression references retain the existing gate routing and the focused backup,
recovery, CLI, managed-flow, lease, egress, Workboard and memory fixtures. A
reference is not passing evidence; bind retained exact-head receipts separately.
Workboard and memory fixture subsets do not establish whole-suite qualification.
Nowistay must run separately with `node --test test/mcp-nowistay-sdk-regression.test.mjs`
against pinned MCP SDK 1.32.0; a Vitest gate does not satisfy that check.

## Remaining image and rehearsal gates

The GCP preparation policy now admits only the exact 10.6 source/tree above,
version `2026.10.6` and Dockerfile SHA256
`e2fca2f75dc0739ee1943fafacae8773f14dc7a872cdcb9201ee665966c36575`.
Its full Dockerfile differs from the accepted 10.5 file only in the OCI base-name
label (`node:24.22.1-bookworm-slim`). Existing 10.5 pins remain unchanged. The
new output tag uses `openclaw-v106-prep`; it is not an immutable image receipt.

The next build profile is explicitly **candidate-unqualified**: 8 GiB aggregate
builder memory with no container swap, 4 CPUs, 6 GiB compiler old-space, 10 GiB
available-memory admission and 2 GiB runtime floor. Existing pressure, health,
disk, ownership and cancellation checks remain. These are configured limits,
not an empirical minimum or a demonstrated fit for the changed 10.6 dependency
closure. Reconcile the current builder lease and coordinate resources with the
current deployment owner before preparing/starting a new owned operation.

The package/lock and plugin dependencies changed; the preserved 133-test source
receipt does not prove the offline Docker install, native closure or image.
A later authorized build must seal the immutable image and verify
Node 24.22.1, pnpm 12.15.0, managed Codex 0.160.0, selected `codex,workboard`
plugins and native tools in that image. Then qualify the exact image-bound
rehearsal executor and resource profile; preserve the intended future
**320 MiB/s read / 128 MiB/s write** limits and verify their effective device binding.

The existing cross-build backup-reuse contract intentionally refuses 10.6;
this generator does not widen it or transfer 10.5 backup validation. The sole
rehearsal owner selects the snapshot and database generation, metadata-only
hygiene assessment, native Doctor and startup checks. The recovery process
fixture for `lost-journal` additionally needs built `dist/entry.js`.

Do not modify current rehearsal data or reusable backups to satisfy this
proposal. Production promotion uses current production data and remains a
separate decision after real-data qualification. Recovery timing is not claimed,
and this proposal does not reintroduce the previously held extra rollback test.

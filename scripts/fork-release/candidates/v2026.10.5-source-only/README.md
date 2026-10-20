# 2026.10.5 source-only seal proposal

This proposal binds [source PR18](https://github.com/fr-meyer/openclaw/pull/18) for use with the existing [pipeline PR17](https://github.com/fr-meyer/openclaw/pull/17). `productionEligible` remains `false`. These files do not contain a sealed image or authorize deployment.

| Identity | Exact value |
| --- | --- |
| Source commit / PR head | `cb80407b3d01111996ec6abb803fd00417b535a0` |
| Source tree | `9bb03f9cd6f8221f42a1c1701824a154d6f87d55` |
| Upstream 10.5 commit / PR base | `1b58cb9a1b4f4353e1add63c8506db4d890962e8` |
| Upstream annotated tag object | `9171d0a427738902efd811c648325cf54116743c` |
| Historical fork source | `c3f9123d4bea1e6cc8b21c8742fc71e0385f7ca6` |
| Derivation tooling commit | `e0df548f6b89372f84e156ea80a64b2a53dd20d7` |
| Manifest SHA256 | `6cf4d847d8e8bf13a3dceda2eadbca5ebd21edac44ae95313317dcfcfd173319` |
| Inventory SHA256 | `b25cea61c9b22a9402ee14b8179fa9504c9dcb9d82bedb043cd79217f76ff5d7` |

## Evidence and scope

The manifest contains all ten applied commits in their actual linear order. The inventory covers the original 92 semantic paths and 36 additional paths, including all 115 paths changed against upstream. Four retired and three upstream-equivalent decisions remain separate. Per-commit evidence preserves the ledger's original reasons; additional support paths bind exact committed blobs without inventing historical decisions.

`source-preparation-manifest.json` and `semantic-reconciliation.json` retain committed source evidence unchanged. `pr18-observation.json` retains the supplied native GitHub CLI **public identity projection** unchanged; it is selected API fields, not a full raw API response. Its `updated_at` is the PR update time, not a fetch timestamp.

`upstream-verification.json` retains the supplied official annotated-tag receipt: GitHub reports `verified: true`, `reason: valid`, and verification time `2026-10-18T20:11:18Z`. Its payload and signature byte-match `upstream-tag.txt`. `upstream-local-object-binding.json` records the separate local binding. No new signature or API query is asserted.

`sha256.json` covers the 27 generated input/evidence files. The existing metadata owner validated these generated bindings. The historical source `2743fe2853a90b7f52f298734c9f7ad5e1b4ca59` passed full source preflight in an ordinary GCP checkout at 15:12:53–15:13:01 UTC on October 20, 2026. That receipt is not proof of the newer source head. Full preflight of the current head then passed on the ordinary exact-source GCP checkout from 16:05:34 to 16:05:40 UTC, with networking disabled and no candidate code execution: `passed: true`, `errors: []`, `deploymentAuthorized: false`. The historical seed remains unchanged.

## Existing verification commands

From the trusted tooling checkout, with `PROPOSAL` set to this directory and `SOURCE_CHECKOUT` to the exact candidate checkout:

```sh
python3 scripts/fork-release/preflight.py \
  --manifest "$PROPOSAL/manifest.json" \
  --inventory "$PROPOSAL/patch-inventory.json" --metadata-only

python3 scripts/fork-release/preflight.py \
  --manifest "$PROPOSAL/manifest.json" \
  --inventory "$PROPOSAL/patch-inventory.json" --source-dir "$SOURCE_CHECKOUT"
```

The following are the existing candidate checks, for the authorized secretless GCP execution route with the candidate's frozen dependencies. They are command references, not passing execution receipts or additional validation gates:

```sh
OPENCLAW_VITEST_MAX_WORKERS=2 node scripts/run-vitest.mjs \
  src/agents/worktrees/run-lease.test.ts \
  src/secrets/egress-proxy/proxy-forward.test.ts \
  src/tasks/managed-task-flow.worker.integration.test.ts \
  src/agents/mcp-http-transport.test.ts

node --test test/mcp-nowistay-sdk-regression.test.mjs
```

The native Nowistay check is required separately and remains an inventory regression reference. It imports `node:test` and asserts MCP SDK `1.32.0`; the Vitest gate does not satisfy it. Its exact test blob, invocation, and qualification requirement are in `native-nowistay-prerequisite.json`.

TaskFlow already uses the canonical owner: explicit paths through `run-vitest.mts` delegate to `test-projects-run.mts`; the database-worker inventory selects isolated `infra` fork workers. This is a static routing conclusion, not an execution result. Raw host logs and reported test timings are not included here.

## Reproduce the proposal

Use clean source and derivation-tooling checkouts at the exact commits above. The generator reads existing Git objects with lazy fetching disabled and writes only below `/tmp/openclaw-v105-seal-prep/`.

```sh
python3 "$PROPOSAL/generate.py" \
  --source "$SOURCE_CHECKOUT" \
  --tooling "$DERIVATION_TOOLING_CHECKOUT" \
  --head cb80407b3d01111996ec6abb803fd00417b535a0 \
  --pr-json "$PROPOSAL/pr18-observation.json" \
  --pr-observation-kind public-identity-projection \
  --upstream-verification-json "$PROPOSAL/upstream-verification.json" \
  --output /tmp/openclaw-v105-seal-prep/cb80407b3d01
```

The preparation context's tooling SHA identifies derivation. A later image receipt must bind the actual executing tooling checkout and producer evidence.

## Pending qualification

Exact image dependency closure, native OCI build and sealing, selected `codex,workboard` plugin checks, native Doctor on an isolated test database, startup/readiness, and rollback proof remain separate qualification. The source preflight does not prove those operations. Recheck live PR head/base at admission and bind the native Nowistay execution evidence before treating that prerequisite as satisfied.

The [existing GCP sealing contract](../../README.md#seal-an-image-produced-on-the-existing-gcp-host) owns image evidence and isolation. Credentials, configuration, and databases remain outside the image. The 9.8 rehearsal resources and production remain under their deployment owner's control.

# 2026.10.5 source-only seal proposal

This proposal binds [source PR18](https://github.com/fr-meyer/openclaw/pull/18) for use with the existing [pipeline PR17](https://github.com/fr-meyer/openclaw/pull/17). `productionEligible` remains `false`. These files do not contain a sealed image or authorize deployment.

| Identity                       | Exact value                                                        |
| ------------------------------ | ------------------------------------------------------------------ |
| Source commit / PR head        | `ae85778296da373dfe7d80101931bafac1acc9dd`                         |
| Source tree                    | `3efb0b6fdb4491462591e2f534161c2b8bab65ab`                         |
| Upstream 10.5 commit / PR base | `1b58cb9a1b4f4353e1add63c8506db4d890962e8`                         |
| Upstream annotated tag object  | `9171d0a427738902efd811c648325cf54116743c`                         |
| Historical fork source         | `c3f9123d4bea1e6cc8b21c8742fc71e0385f7ca6`                         |
| Derivation tooling commit      | `367ccf6d2d12a8cb7cfb9e06ff5f128e2238eca8`                         |
| Manifest SHA256                | `4dfce05ac50a38c7667aeaa3b88f8f60e9c6046bb48a1d361785e77ee5d4ccd2` |
| Inventory SHA256               | `cc4298057d4c61b6e1a488f06fdac93a0ea9263f87811700c0179a470cc495a8` |

## Evidence and scope

The manifest contains all twelve applied commits in their actual linear order. The inventory covers the original 92 semantic paths and 38 additional paths, including all 117 paths changed against upstream. Four retired and three upstream-equivalent decisions remain separate. Per-commit evidence preserves the ledger's original reasons; additional support paths bind exact committed blobs without inventing historical decisions.

`source-preparation-manifest.json` and `semantic-reconciliation.json` retain committed source evidence unchanged. `pr18-observation.json` retains the supplied native GitHub CLI **public identity projection** unchanged; it is selected API fields, not a full raw API response. Its `updated_at` is the PR update time, not a fetch timestamp.

`upstream-verification.json` retains the supplied official annotated-tag receipt: GitHub reports `verified: true`, `reason: valid`, and verification time `2026-10-18T20:11:18Z`. Its payload and signature byte-match `upstream-tag.txt`. `upstream-local-object-binding.json` records the separate local binding. No new signature or API query is asserted.

`sha256.json` covers the 29 generated input/evidence files. The existing metadata owner validated these generated bindings. Earlier source preflight receipts remain scoped to their original heads. This candidate adds hash-pinned Matrix native asset acquisition while retaining the unchanged upstream offline installer and addon checks. The pipeline now verifies source-pinned Codex CLI version/startup and Workboard native worker behavior inside the immutable image. Refreshed full GCP source binding is required before the next build; neither source preparation nor synthetic verifier tests establish a sealed image.

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
  --head ae85778296da373dfe7d80101931bafac1acc9dd \
  --pr-json "$PROPOSAL/pr18-observation.json" \
  --pr-observation-kind public-identity-projection \
  --upstream-verification-json "$PROPOSAL/upstream-verification.json" \
  --output /tmp/openclaw-v105-seal-prep/ae85778296da
```

The preparation context's tooling SHA identifies derivation. A later image receipt must bind the actual executing tooling checkout and producer evidence.

## Pending qualification

Exact image dependency closure, native OCI build and sealing, selected `codex,workboard` plugin checks, native Doctor on an isolated test database, startup/readiness, and rollback proof remain separate qualification. The source preflight does not prove those operations. Recheck live PR head/base at admission and bind the native Nowistay execution evidence before treating that prerequisite as satisfied.

The [existing GCP sealing contract](../../README.md#seal-an-image-produced-on-the-existing-gcp-host) owns image evidence and isolation. Credentials, configuration, and databases remain outside the image. The 9.8 rehearsal resources and production remain under their deployment owner's control.

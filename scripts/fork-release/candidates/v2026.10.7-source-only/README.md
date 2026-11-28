# 2026.10.7 source-only candidate

These separate inputs prepare future source [PR #27](https://github.com/fr-meyer/openclaw/pull/27).
They preserve the current 10.5 manifest, image policy, caller and unpublished
activation changes. `productionEligible` is false. No image, rehearsal or
production qualification transfers from an older release or source head.

## Exact source graph

The candidate is `ea99d608de6921c328d44d32c91a27f89323945f`, tree
`a4aadb99741d49d2fd3dd85a3c4b501a3eb7ecdf`. Official stable 10.7 remains
`157d8c2bc3ea2fa183afdc11088e69690bf8e64e` as `baseCommit`.
The versioned `merge` proof binds:

- Integration `4c5850e9d80d214d490dd0212ec62915ee1370aa` with ordered parents
  `[8a2300c841024443fb38954d65eb5bff1229c0a0, 157d8c2bc3ea2fa183afdc11088e69690bf8e64e]`.
- Unique common upstream 10.6 ancestor `fe06181dc5ecc01cf8904abbfc26925925efefbc`.
- Three exact linear successors: `cfd2ae456c13effacfeff797a469c39437eeb092`,
  `2ad647a6f62bebc07edd9b0f40848c223a131083`, then the candidate above.
- Separate approved security source `85a9bdc1285c338f10f5ca818abc259f6d483b5b`.

One applied inventory entry represents the complete integration result. It does
not relabel the merge as a cherry-pick. Its `originCommit` also ensures the
existing workflow's history acquisition fetches the separate security source;
the bounded ancestry owner acquires the integration and all successors.

The committed source ledger covers 223 result paths, including the complete
152-path prior fork delta and 76 selected security-source paths. Those sets
overlap. The candidate inventory covers all 225 changes against official 10.7;
the additional two paths are the new release note and the ledger itself.
All five source/result blob columns are checked, including file modes for exact
fork/security carries. A null security column means a path was not selected for
security carry, rather than claiming it is absent from that source.
Disposition explanations and textual-conflict judgments still require source
review; this validator does not turn those judgments into runtime evidence.

`upstream-verification.json` preserves the existing GitHub verified-tag
observation. Its payload and signature match the exact local annotated tag
`5c101ce5a0637df375c5f6ae49d44d0d27cc26b1`. This is retained GitHub evidence
plus local byte binding, not a new local GPG verification. The inventory pins
the complete observation hash.

## Checks and remaining admission

From a reviewed tooling checkout:

```sh
python3 scripts/fork-release/preflight.py \
  --manifest scripts/fork-release/candidates/v2026.10.7-source-only/manifest.json \
  --inventory scripts/fork-release/candidates/v2026.10.7-source-only/patch-inventory.json \
  --metadata-only
```

For full source preflight, replace `--metadata-only` with
`--source-dir "$EXACT_107_SOURCE_CHECKOUT"`. The source must be an ordinary,
non-promisor checkout with all declared objects and exact source HEAD. The
existing local partial checkout is refused; no configuration exception or
successful full-preflight receipt is implied. Missing history is acquired only
through the existing bounded `source_ancestry.py` owner, with the security source
also included in the inventory's history set. Do not silently enable lazy fetch.

The hosted validation Node selection is 24.22.1 for this 10.7 lane; retained
10.5 selection stays 24.21.0 and 10.6 stays 24.22.1. The current image-build
source allowlist is not expanded by this source-binding change. Linux native
acquisition, image-policy admission, immutable image qualification and isolated
real-data rehearsal remain separate future work. Gate paths are selected source
tests, not assertions that every suite or platform passed.

The branch `task/v107-source-binding` does not match the image workflow's
`release-pipeline/**` push trigger. This proposal adds no workflow permissions,
dispatch, upload, secret, storage or production activation.

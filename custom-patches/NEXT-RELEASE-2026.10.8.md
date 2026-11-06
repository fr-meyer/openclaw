# Future grouped release: OpenClaw 2026.10.6 + 2026.10.7 + 2026.10.8

Status: local source integration draft, SOURCE_ONLY_UNQUALIFIED. No image build,
native acceptance, migration/recovery or production authorization is transferred.

## Exact integration inputs

- First parent: reviewed fork 1cf0627b9df7d81f101c39d94e87c0a68ba90884,
  including Workboard exact-card/intent and replacement-claim fencing.
- Second parent: official stable10.8 dc2523e5a5c7a309517fd7fa834add938231d526,
  tree8e87ea041d88f72b77d83806b9ad05aa4f176d59, annotated tag
  e07a2f67d11717ed39aa2fa07bbe9342376ebfbf. API signature evidence is separate
  from local signature verification.
- Source merge base: official10.7 157d8c2bc3ea2fa183afdc11088e69690bf8e64e.

The complete new ledger covers the actual243-path prior fork delta and this
runbook. Historical10.5/10.6/10.7 ledgers remain immutable historical evidence.
The ledger itself is excluded from its result-blob rows to avoid self-reference.
All52 intersections merged textually without conflict:47 package manifests,
two SDK docs, the lazy plugin loader and two maintained test-route lists.

## Preserved behavior

Keep Workboard --card/--intent-run-id forwarding, ready-only exact dispatch,
atomic launch ownership, deterministic card+intent identity and claim-generation
fencing together. No SQL schema or migration implementation is added by the
carried18-file repair. Upstream10.8 does not supersede it.

Keep body-parser2.4.0/qs6.16.1 scoped to Express5.2.1, Undici8.12.2,
Zod4.6.6 with bounded retained-v3/A2UI/Discord compatibility patches, reviewed
parent-scoped MSAL7.1.0, DOMPurify3.4.17, markdown-it15.0.3 and Vite8.3.3.
Keep strict10080-minute age policy and only the existing approved exact
body-parser exception through2026-10-29T11:39:38.614Z. Retain the compatible
development-cache refresh without claiming a causal max-stale fix.

Keep both fork lazy task access and upstream immutable native-inspection
retention. Preserve upstream sandbox/exec/browser/audio containment. Retain
all managed-task and exited-owner test routes alongside upstream additions.

## Compatibility and remaining gates

Node>=24.22.1 <25 or>=26.12.1; pnpm12.15.0. Future fs-safe remains0.26.0;
managed Codex remains0.160.0. Plugin/core metadata advances coherently10.8.
State20/agent25/admission1 does not prove downgrade safety. Exercise changed
agent-lock retry, Doctor recovery and Codex native-assignment repair on
synthetic/disposable snapshot state under separate runtime authority.

Prior source tests remain bound to their original commits. Source checks here
do not qualify a Linux image, public plugin distribution or existing data.
The future pipeline still binds ea99 and the retained legacy publisher
--plan-image path admits only10.7. They must gain a separately reviewed exact
10.8 binding; their current refusal must not be bypassed or called readiness.

Build only in GitHub CI after explicit publication/build/access authority;
privately retain and test the same immutable image in isolated GCP. Promotion
requires separate production approval and fresh capacity admission. Never
rebuild merely to promote. Current10.5 qualification stays independent.

# Installed publisher compatibility for OpenClaw 9.8

This private 0.1.1 source candidate adapts the installed 0.1.0 publisher to an
asynchronous, worker-owned controller state bridge. Review,
remediation, signed ingress, head/base and broker attribution gates remain in
those existing owners. This package does not grant merge approval or enable new
TaskFlow automation.

Automatic protected merges accept only the `merge` method because the required
atomic receipt proves the exact reviewed base and head as its two parents.
Configured `squash` or `rebase` methods stop before broker invocation with an
explicit unsupported-method error until those methods have their own verified
receipt contract. External review results retain exact worker custody through
reconciliation before merge readiness is finalized or another step is dispatched.
Changing a PR base, including with the same head SHA, starts a fresh review.
Missing run observations retain worker custody even when the session entry is
absent; reopening a blocked cycle must reconcile that run before dispatch.
External signed review results now require the exact reviewed `baseSha` as well
as `headSha`; a delayed result from an earlier base is ignored. GitHub
`pull_request.edited` events can invalidate review when retargeting changes the
base. Signed GitHub pull request ingress requires `updated_at`; concurrent
initial deliveries reconcile against the committed flow using that revision.
Older revisions are ignored and ambiguous equal revisions block for explicit
owner admission. Legacy flows without a verified revision also block before an
identity change until the owner admits the exact PR head and base. Qualify the installed Mergeguez event producer against this payload
contract before enabling the controller.
Terminal review worker reports must carry `reviewedBaseSha` from the
authoritative broker evidence. Missing or different base evidence blocks merge
readiness. This worker report field does not establish that the installed
signed-event producer sends `baseSha`.

The external signing adapter must copy `reviewed_base_sha` from the same
authoritative terminal review evidence into the `baseSha` payload field before
signing the exact body. The current PR base or flow binding cannot substitute
for reviewed evidence. The available older signed envelope does not document
`baseSha`; this source candidate makes no claim about the installed adapter.
Before activation, the release owner must bind its installed absolute path and
SHA-256 to the release manifest and prove a signed matching-base callback plus
missing, stale and malformed-base rejection through the installed producer and
candidate consumer. Until then, signed review completion remains fail closed.
The candidate now preserves the signed `claimRef` and admits external review
completion only when it matches the controller's active waiting claim. A
missing, stale, or unbound claim cannot advance the flow. The installed
sender's exact path/hash and its claim-issuance contract remain activation
blockers; synthetic signed ingress proves only this candidate consumer.
Periodic recovery keeps a live waiting claim and reschedules observation
without starting another review. An expired claim blocks for owner intervention.

The Gateway bridge must report `authorityVersion: 1` and
`availability.controllerParity: true`. Canonical task creation and private
TaskFlow worker launch remain unavailable. Normal subagent launch retains its
one-hour timeout and current native owner. Flow reservation and initial ingress
deduplication occur in the existing shared-state transaction.

Every flow/run port is asynchronous and closes after accepted work settles.
The controller persists an uncertain-launch marker before invoking a native
subagent. A restart before run acknowledgement retains that reservation until
the original launch is reconciled. Unknown launches block fresh dispatch.
Missing, interrupted or ambiguous observations and incomplete cancellation remain
held; a lifecycle event or absent session cannot supply completion credit.
Startup preserves blocked flows. Workboard ownership and Markdown approval/context
remain in their existing stores.

The configured runtime source pin must still match the actual loaded file. The
pure `proposeInstalledPublisherRuntimePinMigration` helper creates exact-preimage
pin-change preconditions only. Its proposal needs the plugin-owned release/Doctor
application; it does not update configuration or qualify evaluated runtime code.
Keep the original package/config pin for rollback.

Before release, run the supported existing shared-state worker proof, bind the
release artifact and actual runtime identity, apply the exact pin migration, and
prove inert restore plus rollback of predecessor data. Retain the separate
Workboard database family, including attachments and claims. This source patch
adds no schema and does not copy, migrate, restore, publish or enable live data.

`npm test` uses synthetic asynchronous owner ports. Those tests do not execute a
Gateway, native SQLite worker, model, broker, Git transport, or scheduler.

## Local release pin transition

`src/runtime-pin-transition.mjs` supplies `createInstalledPublisherPinTransition`
for the release/Doctor owner. It is not registered at plugin startup and never
automatically changes configuration. The default adapter uses the public
`openclaw/plugin-sdk/config-mutation` owner for locking, whole-config revision
checks, validation, required durable backup and publication. It requests
`afterWrite.mode: "none"`; it does not restart or activate a runtime.
The evaluated SDK must expose `CONFIG_MUTATION_CAPABILITIES.requireDurableBackup: 1`
from the paired patched config writer. An older SDK is refused before config IO.
This feature indicator does not attest executable identity: the release manifest
must also bind the evaluated SDK, canonical writer/backup implementation and
retained applier to the same qualified image/source.

The release owner supplies its original synchronous `assertCurrent` callback.
Reverse transitions also require the original synchronous `assertRollbackSafe`
callback, which must establish the separately admitted rollback conditions.
Neither a source hash nor a configured session string grants those conditions.
The operator supplies the exact config path, config snapshot hash and unchanged
absolute installed `src/runtime.mjs` path in each request. A stale full config,
unrelated pin, unverified package, retired owner or included config is refused.
Root-file-only coverage is deliberate: include graphs need complete backup
admission before extending this component.

Forward application verifies the paired 0.1.1 runtime, entrypoint, controller,
HTTP parser, package metadata and plugin manifest. Reverse application verifies
the exact predecessor 0.1.0 package instead. The applier must execute from retained
release/image custody while the installed target is staged; replacing target
files cannot establish the identity of already evaluated applier code. Keep the
applier's source identity bound in the release manifest separately from its
target package. Do not alter the runtime source guard or loader admission.

The unpublished 0.1.1 target now binds the reviewed lint correction at
`14a2507d`; the historical `1e197fa2` candidate remains recorded separately as
`sourceQualifiedCandidate`. Its runtime hash is not rewritten. The installed
0.1.0 predecessor remains unchanged. This successor binding does not authorize
pin application or attest the external review signing adapter.

Call the returned operation with `{ direction: "forward" | "reverse",
expectedConfigPath, expectedConfigHash, expectedRuntimePath }`. An already-target
pin with the supplied current config revision returns `already-target` without
writing or rotating backups. Replaying an old input revision refuses; use an
owner reread to reconcile first. The plugin draft edits only `expectedRuntimeSha256`.
The canonical writer retains its normal metadata stamping, projection and
serialization; review the actual persisted delta on the isolated restored copy
before cutover. The reverse draft changes the pin only and does not restore
databases or undo external effects.

Any mutation attempt or post-commit failure returns an `unknown` error receipt
for reconciliation, retaining a known committed revision and the canonical
owner's publication/rollback status when present. It never automatically retries
or compensates. Receipt fields contain bounded status/digest metadata; internal
error causes retain original diagnostics and must remain in private operator
handling. The returned digest records an observation, not continuing authority.
Required backup failures prevent publication. Ordinary config writes retain
their existing best-effort backup behavior.

Focused tests use the real component and canonical backup function with inert
config/byte IO. Native configuration publication and fsync proof require the
separately admitted runner and isolated restore/release checks.

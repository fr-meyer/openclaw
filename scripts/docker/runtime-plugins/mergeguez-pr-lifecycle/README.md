# Installed publisher compatibility for OpenClaw 9.8

This private 0.1.1 source candidate adapts the installed 0.1.0 publisher to an
asynchronous, worker-owned controller state bridge. The registration entry retains
its installed source bytes. The corrective controller preserves prior worker
custody across pending launches, review results, reopened blocks and a new head or
base. Retained workers occupy capacity until exact owner reconciliation. Worker
reports return before their own run is reconciled. Unavailable run-ledger admission
holds recovery; runtime dispatch reconciles the exact run before launch or clean
detached-worktree rebinding. The HTTP reader pauses rejected bodies and removes
its listeners. Automatic merge binds the
reviewed base and head to the broker's protected merge receipt. The current atomic
broker contract supports merge commits; squash and rebase refuse before a broker
call. Signed review events can carry `baseSha`; older events consume the broker's
exact current review instead of their potentially stale findings. Review,
remediation and signed ingress remain in their existing owners. This package does
not grant merge approval or enable new TaskFlow automation.

The Gateway bridge must report `authorityVersion: 1` and
`availability.controllerParity: true`. Canonical task creation and private
TaskFlow worker launch remain unavailable. Normal subagent launch retains its
one-hour timeout and current native owner. Flow reservation and initial ingress
deduplication occur in the existing shared-state transaction.

Every flow/run port is asynchronous and closes after accepted work settles.
Unknown launches retain their committed reservation and block fresh dispatch.
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
Gateway, native SQLite worker, model, external broker, remote Git transport, or
scheduler. Worktree regressions use temporary local Git repositories.

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

The unpublished corrective 0.1.1 target binds controller `8b8f506d`, HTTP `fc46936c`,
and runtime `9822189b` SHA-256 prefixes. Its candidate source pin now names
commit `d2d65781`, whose exact tree passed the final source review. The tracked
cut manifest binds these installed targets through `publisherSourceSuccessor`
and preserves the earlier `14a2507d` binding in history. The artifact metadata
successor can be planned after its separate review and local commit; build,
installed runtime and current-state recovery qualification remain pending.

The historical `1e197fa2` candidate remains `sourceQualifiedCandidate`, and its
runtime hash is unchanged. The complete installed 0.1.0 predecessor bytes remain
unchanged, including the controller and HTTP reader retained by the rollback
fixture. Source pins do not authorize application or qualify an image.

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

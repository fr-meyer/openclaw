# Installed publisher compatibility for OpenClaw 9.8

This private 0.1.1 source candidate adapts the installed 0.1.0 publisher to an
asynchronous, worker-owned controller state bridge. The controller, HTTP parser
and registration entry retain their exact installed source bytes. Review,
remediation, signed ingress, head/base and broker attribution gates remain in
those existing owners. This package does not grant merge approval or enable new
TaskFlow automation.

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
Gateway, native SQLite worker, model, broker, Git transport, or scheduler.

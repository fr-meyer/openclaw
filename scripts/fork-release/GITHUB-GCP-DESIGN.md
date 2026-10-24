# GitHub to GCP: disposable rehearsal and controlled promotion

Status: **proposal and offline contracts; not activated**. This extends the
existing fork-release owner. It does not deploy 9.8, change production, enable
identity federation, or create resources. Source PR #18 remains unqualified.

The existing-VM CLI route in [README.md](README.md#existing-vm-execution-route)
can build, verify and prepare execution without activating this infrastructure
proposal. Its fixed Doctor executor consumes an already restored clean input;
the deployment owner still owns restore, readiness, rollback and promotion.
The OIDC plan validator below does not launch that executor or grant authority
to create a VM, change IAM, or run a migration.

## What exists

Read-only CLI inspection on 2026-10-20 established:

| Capability             | Observed state                                                                                                                                                            | Consequence                                                                                                                 |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Fork                   | Public `fr-meyer/openclaw`, repository ID `1309456040`, owner ID `26621962`                                                                                               | Treat Actions logs/artifacts as public; bind identity to numeric IDs.                                                       |
| Repository enforcement | No rulesets; `main` branch protection returned 404                                                                                                                        | Main trust cannot rely on server-enforced review yet.                                                                       |
| Actions                | Enabled; all actions allowed; default token read; workflow PR approval disabled                                                                                           | Audit/pin dependencies before privileged jobs.                                                                              |
| Environments           | `docker-release` has no protection rules. Existing 9.8 proof environment has one required reviewer, permits self-review and admin bypass, and uses custom branch policies | Neither establishes the proposed production approval boundary. Leave both unchanged.                                        |
| Account plan           | Plan not returned by API                                                                                                                                                  | Do not infer a paid tier. Environment API works; required reviewers are supported for public repositories on current plans. |
| GCP federation         | One existing proof pool and its GitHub provider are disabled; provider condition also ends in `&& false`                                                                  | No working deployment federation established. Preserve this separate proof configuration.                                   |
| Runtime                | Production VM running; disk inspection includes large persistent disks                                                                                                    | A test disk restored from a snapshot must fit its original capacity, not its used bytes.                                    |
| Build lane             | Exact source/tooling selection, OCI artifact and receipt; no GCP job or `id-token: write`                                                                                 | Existing build is preparation, not automatic production deployment.                                                         |
| Private coordinator    | `release.py`, `preflight.py`, `ops_gate.py`; adapter supplied externally                                                                                                  | No qualified GitHub-to-GCP adapter or independent cleanup controller was found in this source.                              |

These are observations, not settings changes. Recheck them before activation.
The upstream-only Labeler failure does not establish a fork authentication problem.

## Execution and ownership

1. **Build once.** Keep PR tests secretless. From reviewed tooling, resolve the
   exact candidate and run the necessary focused tests; build one OCI artifact.
   Verify its bytes, source/tree, tooling SHA, platform, included plugins,
   attestations and producer run/attempt. Preserve this artifact by digest
   privately for the approved promotion/rollback retention. Never rebuild it
   for promotion. A different digest requires new qualification and approval.
2. **Request rehearsal.** A manually dispatched, protected-main workflow sends
   the exact artifact and reviewed private plan to a durable GCP controller.
   The GitHub job is a client, not the lifetime owner. Mac disconnection,
   cancellation and GitHub runner loss must not stop observation or cleanup.
   Reuse the existing release coordinator's intent/status/resume model;
   implement a narrow private adapter rather than another release state owner.
3. **Restore isolated data.** Select a consistent snapshot group with known
   capture/fence provenance. Restore to new disposable data disks attached to a
   clean test VM. Never boot a production boot-disk copy: it can contain active
   services, keys and integrations. No production mount is writable from test.
   A snapshot is preferred over repeated full file copies, but is not by itself
   proof of cross-database consistency or native integrity.
4. **Run native checks.** Complete native restore/Doctor/migration and integrity
   checks, then startup/readiness and representative bounded regressions.
   Exercise rollback on disposable data with the exact prior build and
   compatible pre-migration data. The selected upgrade is directly from the
   current 9.4 baseline to 10.5; observe actual input schemas rather than
   assuming the failed 9.8 rehearsal reached state 19/agent 24. The target
   is state 20/agent 25. Unknown delivery-fence sends must never be replayed.
   EmbeddingGemma rebuilding is conditional on actual use.
5. **Finish and dispose.** Persist minimal evidence, terminate the test writer,
   and delete the exact owned test VM/disks on pass, fail or cancellation.
   Record test outcome and cleanup outcome separately. Cleanup failure means
   `cleanup_pending`, never success. No idle test VM or detached test disk is a
   desired steady state. Preserve approved source snapshots/rollback backups.
6. **Promote separately.** Review the exact artifact and rehearsal evidence.
   Require a fresh human decision and live production revalidation. Production
   is never a disposable resource and is never selected by TTL cleanup.

### Current production data, not rehearsal data

The existing coordinator's backup/restore/rehearsal receipts are **insufficient
for unattended promotion**. Do not activate that path until its private adapter
and admission contract implement the following transaction boundary:

- Under the existing production lock and single-writer fence, capture a **fresh
  backup of current production**, verify it natively, and bind its ID/digest,
  current build/digest, schema versions, mutable inventory and fence epoch to
  promotion. Verify compatibility and restore evidence before the first live
  migration. Revalidate the approved artifact and unchanged production baseline.
- Migrate current production data in place or through a fenced current-data
  cutover. Never replace it with the rehearsal snapshot or earlier restored copy.
  A change of baseline, lost fence, expired approval or changed artifact stops
  promotion; it does not silently recapture under an old approval.
- The approval challenge authorizes exactly one candidate, current baseline and
  backup policy. The fresh capture receipt is durably linked to that operation
  before mutation; if capturing changes the reviewed scope, obtain a new
  challenge. Retain the preceding build and fresh compatible backup.
- Reuse native startup/readiness plus the existing runtime tools gate. Rollback
  requires proof that candidate writers stopped and external effects/new writes
  cannot be lost or replayed. Otherwise stop for operator reconciliation.
  A failed health check alone cannot authorize restoring old data.

The production machine stays provisioned and serving outside a controlled
cutover. This is not a zero-downtime promise: a single-writer schema migration
can require a maintenance interval. HA would be a separate design and approval.

## Threat model and boundaries

Assets: production availability/data, customer content, credentials in snapshots,
release integrity, billing, and authority to promote. Threats include malicious
PR/candidate code, compromised build dependencies, forged/replayed artifacts,
misconfigured federation, interrupted controllers, and incorrect cleanup.
Repository/cloud administrators remain trusted; their compromise is a residual
risk. Native migration bugs and snapshot inconsistency require real rehearsal.

| Threat                                            | Proposed control                                                                                                                                                                               | Required proof / current state                                                                                    |
| ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| A PR obtains cloud authority                      | No OIDC/secrets on candidate jobs; separate trusted dispatch job; numeric repo/owner ID, `main` ref, dispatch event, environment, audience and exact workflow SHA in provider condition        | Offline proposed CEL is tested. Real issuer/signature/expiry/audience and negative-token tests are pending.       |
| Workflow or action supply-chain compromise        | Protect `main`, require review and dismiss stale approvals, pin actions to full verified SHAs and dependency locks where supported; privileged tooling cannot be taken from candidate artifact | Enforcement and full dependency audit pending; workflow changes need separate review.                             |
| Script/PR injection                               | Parse fixed JSON contracts; no expression interpolation of titles, branches, logs or candidate values into shell; fixed repository and explicit argv                                           | Adapter integration tests with hostile strings pending. Plan input rejects mutable identities and unknown fields. |
| Snapshot credentials exfiltrated                  | No attached/default VM service account; clean boot image; trusted offline sanitization; no production integration credentials; network/metadata restrictions below                             | No isolation policy configured here. Canary exfiltration tests and independent review required.                   |
| Candidate forges evidence                         | Trusted supervisor owns clocks, exit status, resource IDs and receipt construction; candidate cannot write its ledger or invoke cloud APIs                                                     | Public receipt projection tested; live privilege separation and evidence authentication pending.                  |
| Artifact substitution                             | Verify producer identity and exact OCI bytes/attestations, not just a supplied digest; immutable private artifact store with restricted writer, receipt binds source/tooling/image             | Existing OCI verification reusable; private store/promotion binding pending.                                      |
| Stale data or duplicate sends                     | Fresh current-production capture/fence and rollback pair; native schema/delivery-fence checks                                                                                                  | Existing coordinator cannot alone prove this; private adapter and disposable failure tests required.              |
| Retry creates duplicates or two owners            | Durable intent before request, stable operation/request ID, remote status reconciliation, one lease owner with fenced writes                                                                   | Existing coordinator models operations; cloud API/lease integration pending.                                      |
| Cleanup removes production or leaves paid orphans | Exact API IDs and immutable creation receipt, disposable role, ownership/fence check, absolute VM TTL, independent orphan reconciler                                                           | Cleanup implementation and crash tests pending; labels alone never authorize deletion.                            |
| Public logs contain data                          | Only fixed enums, bounded time and trusted source/image IDs; private raw output with separately approved access/retention                                                                      | Unknown-field, secret/PII-canary and malformed-input leak tests pass offline; end-to-end upload test pending.     |

### Federation and tooling

Use short-lived GitHub OIDC/WIF, not a downloaded service-account key. The
proposed condition produced by `gcp_rehearsal.proposed_oidc_condition` binds the
actual fork IDs, `refs/heads/main`, `workflow_dispatch`, `openclaw-rehearsal`,
the exact proposed `gcp-rehearsal.yml` workflow and its SHA, plus provider audience.
The workflow does **not** exist yet. This direct-workflow proposal deliberately
requires a reviewed condition update when its tooling commit changes.
If converted to a pinned reusable workflow, also bind `job_workflow_ref` and
`job_workflow_sha`; do not substitute the caller's SHA for the callee.

The provider must verify the signed JWT against GitHub's issuer and expiry.
This Python helper is not a JWT validator or authorization boundary. Environment
subjects do not by themselves bind a branch; explicitly check `ref`. Do not
assume one historical `sub` format across GitHub's immutable-subject rollout.

Keep build publishing, rehearsal provisioning, cleanup, and production promotion
as separate principals. Only a protected promotion environment/private approval
may reach the production adapter. The candidate runs on neither the privileged
GitHub job nor the controller host. A privileged `workflow_run` or
`pull_request_target` must never check out candidate code or execute its artifact.
The existing public build artifact contains code/image only, no production data.

### Sensitive snapshot isolation

Empty environment variables do not sanitize a production snapshot. Before any
candidate process, trusted tooling must remove/replace auth stores, API tokens,
session credentials, channel/webhook endpoints, scheduled outbound work and
credential-bearing config from the test view, and verify the result. Keep raw
snapshot access restricted to the capture/sanitizer principals. A sanitizer
cannot claim a migration proof for data it removed; enumerate that coverage gap.
Use separate synthetic fixtures to cover credential-store structure.

The candidate VM has no service account, no public IP, and no production network
route or writable production storage. Stage verified images/dependencies before
data attachment. Candidate workload networking is disabled, including DNS,
metadata endpoints and link-local access; host access is private and restricted
to the trusted controller/operator. If a test needs egress, use reviewed explicit
destinations with synthetic data in a separate test, never general internet
access with customer snapshots. Preexisting project metadata must be treated as
potentially sensitive even without a VM service account. Candidate stdout cannot
become a public serial-console log, startup-script output or GitHub log.

Raw app/native output remains private, timestamped and retention bounded. Show
native phase/log lines first to the authorized operator, followed by supervisor
diagnostics: phase start, last output, process liveness, native completion,
CPU/I/O samples, deadline and stall reason. Liveness is not progress; neither
changing byte counts nor an elapsed timer proves integrity completion. On a
stall, preserve evidence and escalate; never skip a native check to meet TTL.
Public output contains no paths, SQL, transcripts, config, environment, raw
errors, snapshot names or database hashes. Even safe-shaped fields must be
constructed by the trusted supervisor, not copied from candidate JSON.

## Disposable lifecycle and interruption

Use the current release owner plus a private cloud adapter. Its resource ledger
records operation ID, exact project/zone/type/name/**numeric ID**, creation API
request ID, absolute expiry, resource role and current owner lease/fence.
GitHub run attempts are observations, not a new operation identity.

The adapter/controller must own immediate rehearsal teardown independently of
`release.py`'s final `cleanup` phase. Today, failed restore/rehearsal stops at
`needs_operator`, and successful rehearsal waits for approval; neither reaches
that final phase. Reconcile and remove the disposable resources before reporting
the rehearsal operation terminal, and let the independent janitor recover a
controller failure. Retain its receipt for later approval. Do not keep a test
VM running while a human considers production promotion.

| Event                                   | Required reconciliation                                                                                                                                                                          |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Create request times out                | Read operation/resource state by stable request ID and expected name; reconcile accepted creation before retry. An absent process is not proof of non-execution.                                 |
| Crash between creation and ledger write | Deterministic naming, provider operation and audit evidence reconcile the resource. A matching label alone is insufficient; ambiguous ownership needs operator review.                           |
| GitHub cancellation / Mac offline       | Durable controller continues status and cleanup independently. `always()` is useful but not a cleanup guarantee.                                                                                 |
| Pass / fail                             | Persist private evidence, emit sanitized result, stop test writers, remove the owned VM, verify deletion, then remove exact unused test disks.                                                   |
| VM TTL reached                          | Absolute termination time with DELETE is the last-resort compute bound. Record interrupted result; never call it a pass. Verify disks separately.                                                |
| Orphan disk / expired run               | Independent scheduled reconciler claims a fenced cleanup lease and checks ledger, numeric IDs, role, expiry and users before deletion. Retained backups, shared disks and production are denied. |
| Cleanup failed / changed resource ID    | Keep `cleanup_pending`, alert with content-free IDs, retry only the same proven-owned resource. Do not broaden selectors or delete by name prefix.                                               |

The adapter must set and verify disk auto-delete deliberately. VM deletion does
not guarantee all disks or other billable resources disappear. An unattached
disk created before VM creation has no VM TTL; the independent reconciler is
mandatory. Starting another test is refused while owned orphan costs or an
unreconciled operation exceed the approved envelope. Ordinary cleanup never
deletes source snapshots, backups, artifact evidence or production resources.

## Resource/cost proposal and approvals

The 9.8 rehearsal demonstrated a container memory limit failure while the host
still had substantial available memory. Do not reuse its 8 GiB limit as a
qualified migration envelope, or infer process allocation from SQLite's page
cache setting. The interrupted copy is not a migration or rollback proof.

Before a future authorized rehearsal, retain native stage boundaries with
timestamps and sample the owned cgroup's current/peak memory, memory events,
anonymous/file allocation and swap alongside process liveness and native
output. Record the exact source, image, dataset and memory/swap limits. Size a
bounded run from measured stage demand plus explicit headroom and current host
reserves; no successful sizing measurement exists yet for 10.5 migration.
Inspect relevant upstream memory-demand fixes at the selected source and
exercise the native entry point without skipping integrity checks. Neither an
idle host nor a quieter log establishes progress. The build client's resource
limit and the BuildKit worker's limit are separate from migration sizing.

Tagged 10.5 includes a relevant embedding fix: native SQLite returns after
each converted row instead of retaining UDF handles across a whole-table
conversion; rebuildable cache embeddings also have a 1 MiB SQL-side limit.
Its archive migration still selects 32 complete blobs and can retain original
and replacement buffers without an aggregate byte or decompression ceiling.
These source findings do not attribute the 9.8 OOM. A successfully migrated
agent-schema-24 input skips storage-23 and snapshot-24 conversions, so qualify
the actual predecessor schema rather than assuming every old conversion runs.
Reuse existing constrained-heap embedding tests; the specific remaining
synthetic gap is archive expanded-byte and retained-batch measurement, including
interruption/resume and content preservation.

For the current preparation, retain the existing test disk and its failed
rehearsal evidence. A separate directory on its existing free space can back a
new explicitly named Buildx state volume without changing Docker's data root
or the existing builder. Buildx's pinned docker-container driver mounts
`buildx_buildkit_<node>_state`; Docker can reuse a precreated local volume with
`type=none,o=bind,device=<dedicated-directory>`. This composition needs native
mount and resource verification before use. It is not permission to mount a
database directory or delete the failed rehearsal.

Budget the cache and OCI export separately. The current executor's private
operation root and OCI output remain on root. Its optional cache contract
separately verifies the named volume, bind path and filesystem device and
guards that filesystem's free space. Native storage binding qualification
is still required; moving cache alone is not a complete root-space solution.
The proposed existing-disk layout reserves 44 GiB free for the cache filesystem
and 16 GiB on root. At the 17:14 UTC observation, those floors allowed about
48.08 GiB and 13.66 GiB of growth respectively. These are available budgets,
not measured build peaks or hard quotas. Full candidate peak usage is unmeasured.
Do not delete old test databases merely to establish a new build workspace.
Choose a bounded budget from fresh capacity and keep the migration and build
serial: they cannot each claim the same available memory or disk headroom.

No resource creation or price promise is authorized by this document. Proposed
per-run envelope: concurrency **1**, `e2-standard-4` or `e2-standard-8`, boot disk
at most **32 GiB**, data disk at least the source snapshot capacity and at most
**1024 GiB**, an initial **12-hour** absolute TTL with a **24-hour** ceiling.
These are review limits, not measured optimal sizing. Slow native checks may
need a newly approved run; a retry cannot extend the original expiry.

Price the chosen machine, zone, restored disk capacity, snapshot retention,
artifact storage/transfer and controller overhead for the entire TTL. Add a
cleanup-delay reserve. An owner must approve a numeric per-run and aggregate
monthly cost cap and maximum simultaneous allocations. The template deliberately
leaves cost figures null; test fixture amounts are synthetic, not estimates.
Metering may lag: Google spend caps for eligible APIs do not stop persistent
Compute Engine/storage charges. Enforce resource quotas, TTL and cleanup;
never disable the production project's billing as a spending control.

| Approval needed before activation | Exact scope to review                                                                                                                                                                                                                                                                                                                                                                                                             |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GitHub settings and workflow      | Main rules/reviews, pinned workflow/actions, separate rehearsal and production environments, selected branches, reviewer identity, prevent self-review, disallow admin bypass. One-person self-dispatch needs an independent reviewer or a reviewed private approval route; do not silently relax the gate.                                                                                                                       |
| WIF / service accounts            | Provider issuer/audience/mappings/condition; exact principal bindings. Setup needs pool/provider administration and possibly API-enable permissions; these must not be runtime roles. Existing disabled proof pool remains untouched.                                                                                                                                                                                             |
| Rehearsal project/network         | Prefer a separately approved isolated project. Same-project separation needs a reviewed permission boundary; do not assume labels are an IAM boundary or every API supports resource conditions. No firewall/IAP/network change is made here.                                                                                                                                                                                     |
| Runtime cloud permissions         | Narrow adapter identity: approved snapshot `compute.snapshots.get/useReadOnly`; test-only `compute.disks.create/get/use/delete`, `compute.instances.create/get/delete/attachDisk`, required zone operation reads and subnet use. Add list only for the owned-resource reconciler. Exact custom roles and resource applicability require an API dry-run/review; no Editor/Owner grants. No candidate SA or production disk access. |
| Artifact/evidence access          | Restricted artifact reader/writer and private evidence object permissions; approved locations, encryption, access audit, retention and deletion policy. No bucket, secret or key is provisioned here.                                                                                                                                                                                                                             |
| Production promotion              | Separate operator/adapter authority, shared production lock, current-data backup/fence, rollback pairing and human challenge. No automatic production rollout is enabled.                                                                                                                                                                                                                                                         |
| Capacity and cost                 | Approved machine/zone/disk envelope, fresh unit prices, per-run/monthly caps, controller cost, TTL, cleanup owner and alert recipient. No priced estimate yet.                                                                                                                                                                                                                                                                    |

## What this PR implements and how to qualify it

`gcp_rehearsal.py` is an **offline scaffold**. It validates proposed source/image
identities, finite resource/cost limits, snapshot size and absolute expiry;
renders a proposed OIDC condition; and projects content-free observations.
It imports no cloud SDK, reads no credentials and executes no cloud command.
The CLI always emits `activationAuthorized: false`, even for a valid plan.
The incomplete template fails validation.

```sh
python3 -m unittest discover -s scripts/fork-release -p 'test_gcp_rehearsal.py'
python3 scripts/fork-release/gcp_rehearsal.py PRIVATE_PLAN.json
```

Offline tests cover fixed identity claims, mutable digest/ref rejection,
expiry without retry extension, cost/capacity bounds and private-field/canary
leak refusals. These tests do not prove WIF enforcement, snapshot isolation,
cleanup, native migration or rollback. Before activation, implement the private
adapter against the existing coordinator and exercise on synthetic disposable
data: wrong-repo/ref/env/workflow/audience tokens; artifact swap/replay;
private-data/metadata/DNS egress canaries; forged phase output; controller loss
before/after each cloud request; duplicate resume; disk retention and numeric-ID
drift; expired ownership; current-data change before promotion; lost write fence;
failed startup/readiness and compatible/incompatible rollback. Observe zero
remaining owned test compute/disks after each scenario. Then qualify a permitted
sanitized snapshot rehearsal with native checks.

Benchmark phases separately against a comparable prior run: provisioning,
snapshot restore, native migration/Doctor, startup/readiness, rollback and
cleanup; record dataset size, resources, cold/warm cache and outcome. No
"fastest" or "optimized" claim is supported yet.

## Official references checked

- [GitHub OIDC claims](https://docs.github.com/en/actions/reference/security/oidc)
  and [Google deployment federation](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines).
- [GitHub environment protection](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)
  and [secure Actions use](https://docs.github.com/en/actions/reference/security/secure-use).
- [Snapshot restore](https://docs.cloud.google.com/compute/docs/disks/restore-snapshot),
  [VM service accounts](https://docs.cloud.google.com/compute/docs/access/service-accounts),
  [VM deadlines](https://docs.cloud.google.com/compute/docs/instances/limit-vm-runtime),
  and [disk retention on deletion](https://docs.cloud.google.com/compute/docs/instances/deleting-instance).
- [Spend-cap limitations](https://docs.cloud.google.com/billing/docs/how-to/budgets-spend-caps).

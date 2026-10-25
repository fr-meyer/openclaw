# Hosted image build and retained-image qualification

## Private hosted retention preparation (not activated)

The optional `.github/actions/retain-private-oci` composite is disabled by
default and has no workflow caller. Existing build triggers, permissions and
application pins are unchanged. Activation is a separate operator action; this
source does not create cloud identities, IAM grants, secrets or storage.

The intended caller step is named `Retain private OCI archive`, after successful
Docker output and the existing resource collector's completion. Its condition
must permit private retention when privacy refuses, but never run after a failed
Docker solve. The caller supplies an independently approved exact workflow SHA,
source/tree and private input/output paths. It needs `contents: read`,
`id-token: write` and `attestations: write`. Those additional permissions are not
present in the current build workflow.

The preparation keeps these responsibilities separate:

1. `private_oci_bundle.py prepare-from-build` streams a canonical uncompressed
   tar without copying the OCI blobs. It contains five bounded original JSON
   documents and the complete unchanged OCI graph. The whole archive, including
   tar overhead, is at most 2 GiB. Its write-once receipt is outside the archive
   directory. No seal or successful privacy result is fabricated.
2. The SHA-pinned existing `actions/attest` action signs the archive digest with
   the original GitHub workflow/run identity. This publishes provenance and the
   archive hash, not image bytes, cloud paths, capabilities or suspect values.
   It does not push an image or create a public artifact.
3. `private_oci_signing.py` defaults to offline canonical-request preparation.
   Explicit future signing uses the operator's existing identity and the fixed
   IAM Credentials `signBlob` API; it does not impersonate a service account,
   create keys or change access. PUT signatures include the exact object,
   method, expiry, `x-goog-content-length-range: 1,2147483648` and
   `x-goog-if-generation-match: 0`. GET signatures pin the object generation.
   Only private write-once capability envelopes receive the URL.
4. `private_oci_transfer.py` defaults to validation. Explicit PUT/GET streams
   pinned bytes, refuses redirects/retries and retains uncertain outcomes. Its
   plan and capability are private, and diagnostics never print URLs, headers,
   OAuth tokens or response bodies. A failed acknowledgement is reconciled
   against the exact object generation; it does not authorize a rebuild.

The single temporary secret contains a closed capability envelope, not a general
GCP credential. A repository-level secret is not isolated to one workflow by
itself. The approved activation must restrict the event, actor, source, workflow
head and run attempt, and preserve the current secretless candidate-build
boundary. The composite exposes its capability only to the final transfer step.

The provider's size-range header is a server-side PUT constraint. Local parsing
does not authenticate a signature or prove live enforcement. The signing
helper's explicit `probe` mode uses only an approved 8-byte plan with a
120-second capability: oversized body must fail, a changed signed range must
fail authentication, the valid body must create a generation, and a second
create must fail. Unexpected responses stop immediately. It never deletes the
probe. A real image capability must not be issued until this separately
authorized native test passes and the probe generation is reconciled and
removed after its upload URL expires. Synthetic tests are not that proof.

For later inspection, `hosted_image_context.py prepare` is offline and cannot
authenticate provenance. Explicit `capture` runs the installed native GitHub
attestation verifier and fixed canonical run/job API owner. It checks the
original workflow/ref/run/attempt, successful Docker step, actual attested tar,
unchanged OCI closure and original resource evidence. A failed upload step may
remain failed while the same signed bytes are recovered; failed Docker output
cannot pass. Caller-supplied `authenticated: true` JSON is not accepted.

Linux verification uses the separately approved, hash-pinned official GitHub CLI
2.98.0 at the tooling checkout's
`.local/qualification-tools/gh-2.98.0/bin/gh`. Its exact 41,377,954-byte executable
is verified before use. There is no caller-selected executable, PATH fallback or
system package upgrade. Preparing this source does not download or install it on
the receiver. A receiver without a GitHub login must supply the original signed
public attestation bundle using the paired `attestationBundlePath` and
`attestationBundleSha256` plan fields. Native verification snapshots the bounded
private input and uses GitHub CLI's `--bundle` mode, retaining normal signature,
subject and producer-identity checks. A bundle is untrusted signed input, not a
saved verification result. Existing public run/job checks still run. No login or
credential copy is needed for that path, and credentials are never forwarded to
the candidate image.

The existing coordinator has an explicit hosted mode:

```bash
python3 scripts/fork-release/gcp_image_reinspection.py --mode hosted \
  --plan /private/hosted-plan.json --plan-sha256 PLAN_SHA256 \
  --state-dir /private/owner/32_HEX_INSPECTION_ID \
  --resource-admission /private/fresh-admission.json \
  --resource-admission-sha256 ADMISSION_SHA256
```

The outer hosted plan binds the nested original-hosted plan and its hash; the
signed archive supplies original resources. No CLI override may replace them.
The local inspection ID is not a fabricated GCP build operation. Explicit
`capture-retained-hosted-origin`, `qualify-retained-hosted` and
`verify-retained-hosted` image-owner commands reuse existing privacy, static,
resource, native runtime and layout checks. They retain original producer facts
separately from the later inspector and reauthenticate on verification. GCP
remains the driver default and its entrypoints reject hosted plans.

Private bytes must arrive on existing test storage with their archive hash,
generation and size verified. Native execution remains behind clean complete
privacy, static checks and fresh owner admission. Qualified output feeds the
existing deployment handoff without rebuilding scanner-only changes. Production
cutover remains separate. No real image or live provider qualification is
established by this source preparation.

## Prepared private retained-image route

This source implements a private GCP reinspection entry point; no build,
retention operation, transfer, native image execution or production activation
has been performed by this preparation. GitHub-hosted builds remain the normal
route. Failed hosted OCI bytes still expire with their runner, and no private
hosted-to-GCP delivery or registry credential is configured. The public artifact
route accepts qualified code-only output only.

For one separately authorized GCP build, the existing adapter can retain its
original OCI under `/var/tmp/openclaw-fork-gcp-build/<operation>/oci` in a private
`0700` operation parent. This is root-backed storage; the separately configured
BuildKit cache can be on test storage. Do not move output through a symlink or
reuse a production database path. The exact security-successor source/tree is
admitted separately without changing older source or next-release pins.

Run the trusted tooling checkout's fixed coordinator after the original build
has settled and the host owner has reconciled workload ownership:

```bash
python3 scripts/fork-release/gcp_image_reinspection.py \
  --plan /private/owner/base-plan.json --plan-sha256 BASE_PLAN_SHA256 \
  --state-dir /private/owner/32_HEX_INSPECTION_ID \
  --original-resources /private/owner/build-resources.json \
  --original-resources-sha256 ORIGINAL_RESOURCE_SHA256 \
  --resource-admission /private/owner/fresh-admission.json \
  --resource-admission-sha256 FRESH_ADMISSION_SHA256
```

The example paths are operator placeholders, not provisioned locations. The
state parent and inputs must be private and owned. `base-plan.json` has exactly
`schema: openclaw.retained-gcp-input.v1`, `manifestPath`, `inventoryPath`,
`sourceDir`, `ociDir`, `executionPath`, `originalToolingSha`, `executionSha256`
and `inspectionToolingSha`. Paths are absolute and separate from candidate
source/OCI. Current tooling must be a clean checkout of the pinned revision.
The image owner authenticates the genuine original GCP execution, source/tree,
review, Dockerfile/build inputs and original OCI directory. Historical build
success or resource facts are never invented from hosted logs.

The coordinator invokes the existing owners in this order:

1. `image.mjs capture-retained-gcp-origin BASE_PLAN CAPTURE` preserves original
   producer, source, reproducible build time and tooling separately from later
   inspection metadata. It does not execute candidate code.
2. `hosted_privacy.py` performs the complete bounded image scan, with the tracked
   public-member plan and explicit `--qualify-public-members`. Only exact whole
   member bytes at reviewed source/path/hash/size/rule bindings qualify. All
   path qualifications also require a regular file and its complete matching
   bytes; another `.env`, a link, changed bytes, or metadata never qualifies
   through that record. Public package origin alone does not establish benign
   semantics. The pinned entries retain the reviewed docs, synthetic fixtures,
   historical expired certificate-test key and client telemetry distinctions.
   Other findings remain blockers. The optional `--public-comparisons` mode
   alone remains diagnostic and does not remove findings.
3. `image.mjs qualify-retained-gcp QUALIFICATION_PLAN OUTPUT_DIR` retains
   independent privacy/static outcomes. Complete structural inspection permits
   safe static OCI/SBOM/provenance diagnosis even when findings remain;
   malformed or incomplete inputs block dependent readers. Native checks run
   only after clean privacy, exact export closure and static verification pass.
4. A fresh independently pinned host-owner admission is checked again at each
   actual native start, including after image import/container creation. It
   binds source/index/current tooling, capacity, ownership and absence of
   competing heavy work. Its validity is at most five minutes. If traversal or
   import consumes that window, obtain fresh owner evidence before native work;
   do not extend an old receipt. No thresholds or host probes live in this driver.
5. Native intent precedes execution. Non-promotable facts and a separate native
   execution capture precede final admission and the existing image-v2 receipt.
   `image.mjs verify-retained-gcp QUALIFICATION_PLAN RECEIPT` revalidates all
   bound reports, original build, OCI graph and full root metadata without
   executing the image again. Ordinary `verify` refuses retained receipts.

If static verification or import outlasts that window, the qualifier uses a
file-only owner refresh at the actual boundary. It creates
`OUTPUT_DIR/resource-refresh/NN-request.json` privately (`NN` is `01` through
`03`) and waits at most 60 seconds measured with a monotonic clock. The existing
host owner supplies `NN-admission.json` and then atomically publishes the private
write-once `NN-response.json`. No paths, commands or executable hooks are accepted
from the response; this mechanism does not perform a host check itself.

The request schema is `openclaw.retained-resource-request.v1` with exactly
`qualificationId`, `originalOperationId`, `nonce`, `boundary` (`import`,
`workspace` or `plugins`), `sourceSha`, `indexDigest`, `inspectionToolingSha`
and `requestedAt`. The response schema is
`openclaw.retained-resource-response.v1` with exactly `qualificationId`, `nonce`,
`requestSha256` and `resourceAdmissionSha256`. The fresh admission uses the existing
resource schema, must be issued at or after the request and remain fresh when
consumed. Publish the response last, after both complete files have mode 0600;
never expose partial files. Final qualification binds every consumed request,
response and admission hash, with each historical guard time. Missing, late,
wrong, stale or replayed evidence blocks native execution and preserves owned
cleanup. Invalid original identity/hash is refused immediately rather than
refreshable. No import or build is repeated to obtain a fresh admission.

The optional pinned base-plan field `smokeTransport: "loaded"` selects the
existing GCP Docker-loading contract; omission keeps Skopeo. The private owner
first requires clean privacy and passing static verification, then streams the
same retained OCI into the existing Docker store through the already approved
scoped wrapper. The qualifier adds no importer, package install, credentials or
access change. Loaded mode verifies the immutable OCI index and Linux amd64
selection; it does not confuse the index with the config digest. The selected
transport is bound in admission, native execution and later verification.

The coordinator's fixed summary contains passed/failed/blocked outcomes and no
raw child output or suspect contents. Stage input/output hashes and exclusive
claims prevent changed or concurrent resumes. A completed resume verifies only;
an uncertain native attempt blocks retry. A pre-native refusal preserves the
OCI for a separately reconciled inspection rather than triggering a rebuild.

The final `handoff.json` names the existing OCI, immutable image/config/index,
original producer, current inspection tooling, final receipt/hash and admission.
The sole deployment owner must run `verify-retained-gcp` before consuming the
image-v2 receipt in the existing release handoff. No additional image build is
needed for scanner/verifier-only corrections. Changes to application or image
content require a new build and separately scoped authority. All receipts retain
`productionAuthorized: false`; this route neither promotes nor deploys.

`image.mjs inspect-layout` and `hosted_reinspection.py` remain non-promotable
static/diagnostic contracts. They cannot replace authenticated origin capture,
native admission or the final retained-image verification above. All export
requires every required check to pass; public export does not become a private
retention shortcut.

GitHub-hosted Ubuntu 24.04 x64 is the default location for future fork image
builds. Build once, verify Linux amd64 bytes and provenance, then use that same
immutable image in the separately owned GCP rehearsal. Production promotion is
a separate decision and uses current production data. Moving the build stage
does not require rebuilding an already qualified image.

## Entry point and activation

The existing `Fork PR and release qualification` workflow owns this stage.
Normal execution is a manual dispatch from trusted fork `main`, naming the
exact metadata-seal commit of the current open `candidate/*` PR based on `main`.
Its source graph, patch inventory, focused tests and current PR binding must
pass before building. The existing reviewed `release-pipeline/**` preparation
lane retains its contract and cannot export an image through the manual gate.

Do not rename or retarget a stacked preparation PR to evade these conditions.
Tooling in draft PR #20 is not active on `main`; adoption still requires the
normal review/merge decision. Source PR #19 remains an unchanged preparation
branch, not a dispatchable metadata seal. No main merge is implied here.

The build context is the exact canonical fork Git SHA, with its checksum in
the URL. It contains no local checkout files generated by source tests. CI
does not mount production databases, configuration, cookies or provider
credentials. It has `contents: read`, no registry login, package-write or GCP
credentials, and no persistent credential setup. GitHub's ephemeral action
tokens still support repository/artifact operations.

## Resource qualification

The default worker is Docker-container BuildKit with an aggregate **8 GiB
memory / 8 GiB memory-plus-swap** limit, **4 CPUs**, and a **6144 MiB tsdown
old-space** setting. Heap is not total process memory. Internal compiler
serialization remains a source property, checked in the candidate's tests;
the worker CPU cap does not serialize every compiler task.

`hosted_resources.py` verifies the exact setup action's local worker and its
effective cgroup ancestry before solve. It samples host memory/PSI/free disk,
worker memory peak/anonymous/file/cache/events, CPU and I/O every five seconds,
through OCI export, load and native smoke. It finishes within the 90-minute
job budget. Docker enforces the memory/CPU cap; sampled violations reject the
qualification before publication. The collector is not an active host-pressure
kill switch and does not claim to observe every sub-five-second event.

Admission uses 10 GiB available memory (8 GiB worker cap plus 2 GiB host
allowance). The 8 GiB free-disk floor estimates output/load margin: prior OCI
0.71 GB, transient load stream 2.02 GB, loaded image 2.386 GB, plus 2 GiB reserve
and rounding. Runtime floors are 2 GiB memory and disk. These are engineering
margins, **not proven cold-build requirements**. Dependency/cache/intermediate
layer peaks are still measured during qualification; a cold build can fail.
No production reserve or database-clone allocation is added to this runner.

The October 23 metadata-only runner check observed Ubuntu 24.04 x86_64, four
CPUs, 15.615 GiB total RAM, 14.720 GiB available RAM and 85.800 GiB free disk.
Docker client/server was 28.0.4 and Buildx 0.38.0. These observations belong to
that runner; every build checks its own current capacity. Related serialized
10.5 compilation peaked at 6.55 GiB, while full cold 10.6 usage remains unknown.

## Focused source gates

Both source-test steps dispatch the inventory's TypeScript gates through the
repository Vitest wrapper and native `.test.mjs`/`.e2e.mjs` gates through
the trusted tooling's shared `native_tests.mjs` runner. That helper executes
`node --test --test-concurrency=1`. An empty selection refuses qualification;
native-only selections never start an unfiltered Vitest run. The older MCP
producer keeps its declared native Nowistay companion when it is not already
selected explicitly. Any runner or missing-file failure stops the step.

The normal source suite owns these security regressions through its isolated
`native-security.test.ts` adapter. The workflow reports completed Vitest selections
only after they pass; the helper then avoids executing the adapter's members twice
and retains unrelated native owners. Missing required members or an absent adapter
cannot qualify as an empty success. The helper must be present in the exact trusted
base/tooling tree before these callers run.

Native children receive only the maintained platform/runtime environment allowlist,
not inherited provider credentials, proxies or fixture project overrides. For A2UI,
the helper resolves Ajv from the frozen MCP SDK's declared dependency and requires
version 8.20.0. No extra install, provider call or local developer path is used.
These source regressions do not establish real-data migration or production startup.

## Verification and privacy boundary

1. Verify source/patch contracts and focused dependency-backed tests.
2. Build one Linux amd64 OCI directory with SBOM and maximum SLSA v1 provenance.
3. Inspect every OCI layer and image metadata before native smoke or upload.
   `hosted_privacy.py` never extracts layer paths or executes image content.
   Unsupported/incomplete inspection and recognized private-state/credential
   findings refuse publication. Reports contain rule identifiers, location/blob
   hashes and fixed syntax flags, never matching contents or fingerprints of
   arbitrary suspect values. Pattern checks are not proof that arbitrary
   committed data is non-sensitive; `.dockerignore` is not such proof either.
4. `image.mjs` verifies OCI bytes, exact Git provenance and selected image,
   then performs secretless native/plugin/Codex/Workboard fixture smoke.
5. Finish resource telemetry and bind all receipts to the same source,
   tooling, image index and run/attempt with `hosted_export.py`.

### Complete detection with bounded diagnostics

The `openclaw.hosted-privacy.v2` report separates complete traversal from retained
diagnostic samples. Reaching a diagnostic cap does not stop detection. Counts
describe rule-per-scan-unit observations: overlapping chunks and path/body checks
share an archive member's rule set; JSON keys, strings and metadata values have
their own units. They are not counts of credentials or globally unique paths.

The report retains at most 64 rule-distributed detail samples. A separate index
retains at most 4,096 unique rule/location/blob rows and at most 512 KiB of compact
JSON. Both truncation states are explicit; counting and traversal continue after
either cap. Identity sets stay bounded. Existing blob, expansion, member, JSON
and layer budgets still apply. Unsupported or incomplete input remains a failed,
incomplete inspection even when no finding has been observed yet.

Any unqualified aggregate finding refuses publication, including when detail
samples are empty or truncated. The CLI exit, export admission and both independent
bundle inspections use the aggregate decision. Publication requires a complete
scan, a consistent zero aggregate and matching identities. A v1 report is not
silently reinterpreted as this proof; preserve historical reports under their
original producer and schema.

The exact public GnuTLS self-test qualification and the source-pinned reviewed
member plan both require complete matching member bytes and apply only to their
named rules. The GnuTLS record also pins the layer. Other rules on the same member
still run. Generated assets and dependencies receive no blanket exemption.

The on-disk receipt stays within 1 MiB. Standard output is bounded NDJSON: a
summary followed by detail and location-index batches. Existing Actions logs
retain these diagnostics even when the scanner exits unsuccessfully, so a future
explicitly authorized diagnostic run can preserve its complete counts and capped
location evidence without publishing its image. Keep the final record types and
offsets when downloading those logs; do not treat a truncated index as a complete
list of finding locations. No extra artifact upload or storage allowance is
needed for this route. A failed scan still prevents native/seal/export steps.

New hosted seals require a Git-context marker. Existing legacy receipts stay
readable, but markerless receipts cannot pass the new hosted export gate.
The receipt records the OCI index, selected image and configuration digests;
use the appropriate verified digest when importing or selecting a container.

Public CI logs are visible while the build runs. No provider/runtime secrets
are supplied. Automatic Docker build-record and build-summary uploads are
disabled. Final output inspection does not retroactively protect information
printed by build commands, so only reviewed public source belongs in this lane.

## Controlled output and cost

Both manual inputs default to false:

- `export_public_artifact`: request the complete verified OCI image and receipts
  as a **public** Actions artifact.
- `artifact_storage_approved`: record that included storage allowance was
  verified or the exact storage cost was separately approved.

Requesting export without the storage decision refuses before checkout/build.
Upload runs only after successful privacy, resource and native qualification,
with one-day retention and no failed/incomplete artifact upload. It never
pushes a registry image. Without export, results expire with the runner and
cannot be used for later deployment; this is verification-only execution.

Before upload, `hosted_bundle.py` revalidates the bound qualification and
receipt hashes and prepares a ZIP containing only the OCI layout and its four
required receipts. It checks the exact OCI closure and hashes each file while
copying, rejects links/extras/changed files, and caps the complete archive at
**2,147,483,648 bytes (2 GiB)**, including ZIP headers and receipts. Oversized
or incomplete preparation produces no uploadable result. The fresh output
directory contains one read-only ZIP, named exactly like the artifact (without
a filename extension), and the helper checks its hash and size again before
upload. The bundle receipt stays outside the uploaded file.

The pinned `actions/upload-artifact` v7 supports `archive: false`: it sends
that one file unchanged and uses its basename as the artifact name. There is
no extra ZIP wrapper or estimated compression overhead. The workflow also
compares the returned upload digest with the prepared ZIP hash; a mismatch
fails the run, but this post-upload check cannot retract already disclosed
bytes. The staging directory is owned by this job and no other writer is
admitted between preparation and upload. This does not defend against a
compromised runner administrator.

The cap bounds this artifact's bytes, not the account's total invoice. At a
storage rate of $0.25/GiB-month, two GiB for one day is about $0.01613–$0.01786
for 28–31-day months before allowance. Retention processing, billing rate and
other account use are not controlled by this code. A proposed $0.02 storage
budget is therefore an approval decision, not a guaranteed bill ceiling. The
public artifact audience and the storage decision remain separate from source
review and main adoption; defaults stay off.

Standard public hosted compute is free. Image artifact storage is a separate
account allowance/cost decision; it has not been established for this account.
No external BuildKit cache upload, paid runner, new credential or registry
visibility change is part of this stage. Private registry delivery remains an
unqualified alternative, not an automatic fallback.

After authorized export, download the exact run/attempt artifact and verify
the ZIP digest against the run's prepared/uploaded digest. The direct artifact
is ZIP content even though its artifact filename has no extension; extract it
to a fresh isolated directory before checking its receipt hashes and OCI/native
verification again through the existing image consumer. Then hand the immutable
image to the sole rehearsal owner. Never
substitute a rebuilt image, metadata-only proof or rehearsal database for the
qualified artifact and current production data.

## Failure and resume

One run/attempt owns one fresh builder and output directory. Failure stops
qualification; automatic retries or promotion are absent. Preserve compact
CI evidence, distinguish compilation from export/load/seal, and correct the
cause before another authorized attempt. No retained cross-run build cache is
assumed; public storage/cost and exact-input cache policy must be qualified
before adding one. Native data integrity and rehearsal startup remain separate
requirements and are not satisfied by image fixture tests.

## Detection, adjudication and future private delivery

Detection still traverses all bounded image layers and metadata; diagnostic
sample limits do not stop counting. Adjudication is narrower: exact reviewed
public fixture version/source, member path, full byte hash/size and named rule
can qualify that observation. Other rules, changed files/versions and unknown
sensitive observations remain blocking. The hosted workflow selects the reviewed
member plan only for its exact source85 commit. Other releases retain normal
scanning until their own policy is reviewed. Synthetic regressions prove that
this qualification cannot hide CI authentication, copied credential files or
sensitive content left beneath whiteouts. No detector match alone establishes
a leak, and public provenance alone does not prove harmlessness.

The source85 plan also includes exact documentation examples from Debian
security u4 `HTTP::Tiny` and `@npmcli/redact`, and the WebSocket endpoint-rejection
test installed under `@openclaw/ai`. Their complete member bytes and installed
paths were matched. The public archive version identifies the evidence
counterpart; it does not assert the installed package version.

The same plan separately pins 24 compiled members from the authenticated
source85 build: three contain dynamic userinfo expressions, and 21 raw matches
cross distinct object-property templates. Complete cached member reads found
one URL-pattern span per file; reviewed static parsing and syntax observations
support those exact lexical dispositions. These records cite original build
provenance, not downloaded public whole-file counterparts. Only `credential_url`
is qualified, after matching the complete member path, size and hash. Changed
output requires a new review. This does not prove absence of arbitrary split or
encoded secrets; the raw detector and all other rules remain unchanged.

The fourth hosted build used a checksum-bound public Git context, public base
images/packages/assets and nonsecret build arguments. Git checkouts disabled
credential persistence, and the Docker context was fetched separately. No GCP
login, database mount or runtime-secret input was configured. The CI job still
had GitHub authentication; optional Git-auth secret identifiers in provenance
are not token values or proof of layer exposure. Moving public Debian/npm and
builder/scanner inputs are not fully described by the application lockfile.

GitHub can remain the default build location. The unconfigured permanent step
is private immutable artifact retention/delivery: reviewed source → hosted build
and provenance → private quarantine → privacy/static/native qualification →
same digest in isolated rehearsal → separately approved promotion using current
production data. Private retention permits diagnosis, not execution of an
unqualified image. Keep delivery/promotion credentials out of candidate jobs;
a new private destination, identity, access/retention/cost or transfer requires
separate approval. No such mechanism is enabled by this preparation.

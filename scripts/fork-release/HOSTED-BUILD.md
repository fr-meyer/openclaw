# Hosted image build stage

## Inactive diagnostic and reinspection preparation

These commands collect evidence; they do not activate another build, authenticate
an asserted producer, create a release seal, grant export, or deploy production.
The existing workflow still requires clean privacy before native execution and
all qualification receipts before public upload. No private CI transfer is enabled.

`hosted_privacy.py --public-comparisons public-member-comparisons-v105.json`
adds exact, source-bound member comparisons to its normal OCI inspection. The
checked-in plan names 60 reviewed public counterparts with exact paths, complete
file hashes, byte counts and specific rules. A complete matching read produces
diagnostic evidence only: findings and pass/fail decisions are unchanged. Changed,
incomplete or repeated differing members never match. Reports contain expected
public hashes and hashed locations, never unexpected content hashes or values.
The plan excludes ambiguous content and the unresolved private-key/runtime-path
observations. Matching a path or recognizing a dependency is insufficient.

The non-executing layout entry point is:

```text
node scripts/fork-release/image.mjs inspect-layout MANIFEST INVENTORY SOURCE OCI ORIGIN PRIVACY INSPECTION_TOOLING_SHA PERFORMED_AT OUTPUT
```

It reuses the existing OCI/SBOM/provenance verifier without loading an image or
running Docker, plugins or native smoke. The bound privacy receipt must have
completed structural inspection within the reader's budgets; nonzero findings
can remain. Malformed, incomplete or mismatched inputs block this diagnostic.
Its fixed-reason receipt is explicitly non-promotable and is not a native seal.

`hosted_reinspection.py` accepts independently pinned receipt hashes for the
original build, original resources and later inspection reports. It preserves
the original source/tree, image/config/index digests, producer, tooling and build
time; later scanner revisions and execution times are separate fields. An old
native seal alone cannot establish a new native execution. A separately pinned
execution capture must bind its receipt, original build, verifier revision and
time. Missing captures remain blocked. Even complete supplied evidence remains
diagnostic with `export: none`; trusted origin capture/admission and promotion
integration are not activated by this contract. Never rewrite old failed receipts.

For a future reviewed workflow, privacy, safe static verification and resource
collection should retain separate passed/failed/blocked outcomes. A privacy
finding must not suppress safe static diagnostics; a structural refusal still
blocks dependent readers. Native execution stays conditional on clean privacy
and static verification, and export stays conditional on every required pass.
This diagnostic fan-out is preparation, not a change to the active workflow.

The existing GCP adapter retains OCI bytes under
`/var/tmp/openclaw-fork-gcp-build/<operation>/oci` inside a private `0700` parent.
That output is on root by default; the separately configurable builder cache is
not an OCI retention destination. Current qualification source pins do not admit
the dependency-security successor automatically. A future GCP selection needs
exact-source/profile review and fresh host, production-health, builder-ownership
and filesystem measurements. Moving the output to test storage or receiving a
failed hosted image would be a separate reviewed change, not a symlink workaround.

GitHub-hosted failed OCI output still expires with its runner. There is no
configured private registry, GCP credential or private artifact delivery route.
The approved public artifact is for qualified code-only output; it must not be
used to retain an unqualified image. Private retention needs its own bounded
destination, access, size and retention decision before another build.

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

Only the exact public GnuTLS self-test qualification is currently supported. It
requires the pinned layer, member path, complete member SHA and size, and applies
only to the verified private-key test vectors. Other rules on that member still
run. Generated assets and dependencies receive no blanket exemption.

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

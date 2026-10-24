# Hosted CI qualification for the next 10.6 image

## Recommendation and boundary

The reusable implementation contract is now [HOSTED-BUILD.md](../../HOSTED-BUILD.md).
The metadata-only hosted check on preparation revision
`0f86e614d7e9e647a0add7f55b7841d07a33047d` observed 4 CPUs, 15.615 GiB RAM
and 85.800 GiB free disk; no image was built. The assessment below distinguishes
that evidence from the still unqualified full image.

Prefer a GitHub-hosted build to avoid competing with the production Gateway.
Use the resulting immutable image for the separately owned isolated GCP rehearsal,
then promote those same verified bytes after the production decision. Do not run
a self-hosted CI runner on the production VM to claim isolation.

This is preparation. No hosted 10.6 image has been built, sealed or inspected.
Current 10.5 tooling, source and data remain unchanged. The source is frozen at
`a39cad2d97efae7d0c832af3d71e6ccc86f60e50`, tree
`47a3c1321ce39b50d22ec092054e54fd0afaa03a`; the previous prepared tooling revision
is `04e804c73ede79d4984167e50913710bfbc1b8b9`.

## Requirements versus measurements

| Item                         | Evidence / requirement                                                                                                                                                                                                                                             |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Platform                     | Workflow uses Ubuntu 24.04 x64 and builds `linux/amd64`; no emulation is needed.                                                                                                                                                                                   |
| Standard public runner       | GitHub currently documents 4 CPUs, 16 GB RAM, 14 GB SSD. Actual free storage must be measured; documentation is not a cold-build disk measurement.                                                                                                                 |
| Prepared worker profile      | 8 GiB aggregate BuildKit memory, no container swap, 4 CPU and 6144 MiB tsdown old-space for exact 10.6. These are limits, not proven requirements.                                                                                                                 |
| Measured related compilation | Serialized 10.5 source `84d65b446d66cd5db5b9c533bd158e9062968692` reached a whole-worker peak of 7,031,795,712 bytes (6.55 GiB), without OOM. Docker compiler step took 154.3 seconds. The run later stopped on production health; it did not finish the image.    |
| Successful cached build      | A later same-source cached solve took 76 seconds plus 81 seconds for sealing, with recorded peak 1.82 GiB. Compiler layers were cached; this is not a cold-build requirement.                                                                                      |
| Output sizes                 | Earlier OCI directories were about 0.70–0.71 GB compressed; one successful load streamed 2,015,573,504 uncompressed tar bytes. Loaded unique image layers were about 2.386 GB in an older inventory.                                                               |
| Working disk                 | The retained GCP BuildKit cache was about 31.01 GB and included reusable historical work. It is neither a single-build requirement nor proof that 14 GB is sufficient. Full cold-build peak disk allocation is unmeasured.                                         |
| 10.6 measurements            | Full-image RAM, disk peak and build duration remain unmeasured. The preserved 133 source tests do not qualify the image.                                                                                                                                           |
| Runtime/tooling              | Node 24.22.1, source-pinned pnpm 12.15.0, Docker Engine/Buildx/BuildKit, Python 3 and OCI smoke transport. Managed Codex remains 0.160.0. Hosted workflow currently installs Skopeo and requires version 1.13.3; availability on the actual runner needs checking. |

The GCP 10 GiB available-memory admission, 16 GiB root-free and 44 GiB cache-free
floors belong to the shared-VM policy. They are not empirical hosted-runner
requirements. Do not add current production usage again to a `MemAvailable`
budget, or use a 16 GiB Doctor cap to size the compiler.

## Implemented hosted route and remaining qualification

The existing workflow can build an OCI directory with SBOM and provenance, verify
its source/config/image digests, load and smoke the exact image, exercise Codex
initialization and Workboard SQLite fixtures, and export the payload with its
receipt. It does not deploy production or use real databases. Its 90-minute job
also installs source-test dependencies, so dependency workspace, BuildKit cache,
OCI export and loaded image storage overlap on one runner.

The reusable hosted stage uses the exact committed Git context, bounded
compiler/worker limits, privacy inspection and resource evidence for future
builds. It disables implicit build-record/summary uploads. Current 10.5 source,
image and pinned active execution are unchanged; no rebuild is implied. A PR-20-only, permission-free capacity check prints
runner/tool metadata; it performs no checkout, dependency install, container
creation, build, cache upload or artifact upload.

The trusted dispatch contract remains unchanged: the normal manual build runs
from `main` and expects an open `candidate/*` PR based on `main`, with a
metadata-only seal above the source. PR #19 is a stacked `prep/*` source PR and
PR #20 contains unadopted tooling. They are not directly dispatchable through
that contract. A reviewed integration/adoption step is still needed; this
document does not authorize a main merge or weaken the seal contract.

Before a heavy hosted solve:

1. Resolve the trusted entry point without changing the ongoing 10.5 candidate.
2. Compare measured runner free storage with a justified workspace/layer/export/
   load budget. If no sufficient bound can be established, report that gap;
   do not assume a paid larger runner, silently delete preinstalled tools or
   declare the existing 31 GB cache to be a cold-build minimum.
3. Verify the effective worker memory/swap/CPU hierarchy and supported OCI smoke
   transport. Capture whole-build peaks and free-space minima through export,
   load and seal; no automatic retry or arbitrary minimum is implied.
4. Resolve the exact output visibility, storage cost and delivery route before
   publication. Do not create new credentials or change repository/package
   visibility as part of qualification.

## Privacy and export

The fork is **public**. Workflow logs and summaries are public, and signed-in
GitHub users with repository read access can download its Actions artifacts.
The explicit upload, disabled by default, retains the entire verified OCI
image and receipts for one day only after the public-export and storage
inputs are enabled. `push: false` prevents registry push; it does not make an
Actions artifact private.

Verified source controls include `contents: read`, non-persisted checkout
credentials, no deployment-secret inputs, and public commit/version/time/plugin
build arguments. `.dockerignore` excludes root `.env*`, Git metadata, Crabbox
state, local caches, logs and build outputs. It is not a universal personal-data
filter. Committed SQLite files include public test fixtures; no fixture or
personal database contents were inspected for this assessment. The exact Git
context avoids accidentally including ignored files generated by preceding
tests. It does not prove that every committed file is suitable for an image.

Before export, inspect the actual final layers, image configuration/history,
provenance and emitted logs for unintended personal configuration, credentials,
cookies or production data. Never pass credentials through build arguments.
Private runtime settings, databases and provider credentials stay outside the
image and are supplied only at runtime. Native smoke success and content
digests do not substitute for this privacy check. No 10.6 image exists yet, so
the check is pending.

OCI transport is straightforward: download the exact run artifact, verify its
receipt and OCI digests, load that verified image and rehearse the same digest.
No automatic GCP delivery step is currently qualified. A private registry can
be another delivery route, but its package visibility and narrowly scoped
push/pull access must be established first. Existing package-list access was
unavailable (HTTP 403, missing `read:packages`); this is not evidence that a
private registry is configured or that credentials should be broadened.

## Cost

The verified repository is public and standard hosted compute is free. That
does not establish a zero-charge artifact/cache/registry plan. GitHub documents
separate storage allowances and cache charges above the included 10 GB when a
higher cache limit is configured. No external BuildKit cache export is enabled
by this change. Existing cache metadata showed 3,667,010,114 bytes across five
entries; this does not measure remaining account artifact allowance. Account
plan fields were unavailable through the current read route.

GitHub currently documents Container Registry storage and bandwidth as free,
but usable private-package access/visibility has not been verified. Larger
hosted runners are paid and are not selected. The metadata-only capacity check
uses standard public compute with no artifact/cache/package output; a heavy
build with retained image output remains held until its cost and visibility
conditions are established.

## Primary references

- [GitHub runner capacities](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [GitHub Actions billing and storage](https://docs.github.com/en/billing/concepts/product-billing/github-actions)
- [Artifact download access](https://docs.github.com/actions/managing-workflow-runs/downloading-workflow-artifacts)
- [Container Registry billing](https://docs.github.com/en/billing/concepts/product-billing/github-packages)
- [Container Registry authentication](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
- [Docker container-driver resource options](https://docs.docker.com/build/builders/drivers/docker-container/)
- [Docker CI build/test guidance](https://docs.docker.com/build/building/best-practices/)
- [Docker provenance contents](https://docs.docker.com/build/metadata/attestations/slsa-provenance/)

The usual architecture is **build once in isolated CI → verify immutable image
and provenance → isolated rehearsal → separately approved promotion of the same
digest**. It avoids compiling on production and avoids replacing live data with
a rehearsal copy. Reproducible source inputs and immutable promotion are distinct
from a promise that every network-assisted rebuild produces identical bytes.

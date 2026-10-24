# v2026.10.6 source preparation image contract

This isolated next-release branch merges the official annotated `v2026.10.6` tag into fork source `7f3ac1fbfd3691546c5b1fd247680a3d00851c76`.
`custom-patches/manifest.json` pins its tag object, commit, and tree and names
the prior 10.5 fork source for patch reconciliation. The prior 10.5
proof, images, and runtime authority do not qualify this branch. Source
reconciliation permits image planning; `SOURCE_ONLY_UNQUALIFIED` and
`productionEligible: false` remain in force until the separate qualification
work is complete.

The Dockerfile carries the separately installed Mergeguez publisher package
from `scripts/docker/runtime-plugins/mergeguez-pr-lifecycle` at
`/app/runtime-plugins/mergeguez-pr-lifecycle`. It is inert at startup. The
package records the supplied source commit and SHA-256 of each shipped file in
`publisher-source.json`; `verify-package.mjs` checks the copied bytes. The
publisher pin transition, installed adapter, and config writer need fresh
10.6 runtime qualification before activation.

`node scripts/docker/package-current-publisher.mjs --plan-image true` refuses
while `carryForward.reconciliation` is `IN_PROGRESS`. Once every retained fork
patch has a reviewed semantic disposition, mark that field `COMPLETE_SOURCE`
in a separate reviewed commit. This classification does not transfer prior
test or runtime qualification. The plan then checks tag
object and ancestry, product version, publisher runtime hash, and each
packaged file against the clean candidate commit. It prints a Git-context
Buildx command; it does not build or publish an image.
The planned selected extensions include `codex` and `workboard`. Image
qualification must inspect the final Codex plugin payload and its 10.6
compatibility metadata; a Codex CLI executable alone is insufficient for
the native Doctor plugin migrations.

A later build runs on the established GCP route with the observed platform,
one selected UTC timestamp, and fresh task-owned metadata and OCI output paths.
Use that same timestamp for the build argument and OCI `created` label.
The plan preserves the native release workflow's OCI directory exporter
(`tar=false`, gzip level 1), full provenance and SBOM. The retained OCI index,
blobs and Buildx metadata are the artifact; a Docker daemon smoke-test copy
does not replace them.

The command uses `--network default`; BuildKit treats a Dockerfile
`RUN --network=default` as inheriting that setting, so a global `none` also
blocks acquisition. Every `RUN` declares its mode, and the executor checks the
complete reviewed Dockerfile hash before dispatch. Network access is limited
to three reviewed acquisition steps: pinned
Corepack/pnpm with manifests, lockfile and patches only, and the existing
Debian security updates and npm refresh before candidate payload copies.
Package acquisition disables lifecycle scripts and pnpmfile hooks; the native
offline production/build installs retain their allowed lifecycle scripts and
native-addon checks. Runtime Corepack uses the prepared cache and retains the
final nonroot offline pnpm check. Candidate scripts, compilation and payload
verification explicitly use `--network=none`. Optional post-payload package
install hooks also remain offline and are disabled for this candidate.

Matrix crypto 0.6.6 downloads its native library from outside the npm tarball.
Acquisition also fetches the Linux x64 or arm64 glibc asset, pinned to the
[official release asset digest](https://github.com/matrix-org/matrix-rust-sdk-crypto-nodejs/releases/tag/v0.6.6).
The offline install helper verifies those bytes again and exposes only that
asset on loopback through the downloader's supported base-URL setting. The
normal postinstall and native-addon checks still run; no dependency scripts,
package integrity checks, or frozen-install requirements are disabled.

The package cache and each acquisition stage must complete before the image
can qualify; an offline miss remains a prerequisite failure. Do not remove
native integrity or security checks to make a build pass.
BuildKit's Git-context, base-image and attestation-generator acquisition are
separate from this `RUN` network setting and must use the approved secretless
build route. The plan supplies no credentials, host mounts or SSH forwarding.

After build completion, use `verifyDockerReleaseLayout` from
`scripts/docker-release-artifacts.mjs` to verify the retained OCI closure
against the exact source SHA, version, timestamp and BuildKit digest, including
the native SBOM/provenance requirements. Retain resolved dependency evidence.
Base images are digest-pinned, but Debian package indexes, `npm@latest`, and
the build timestamp can change image bytes. Native migration,
startup/readiness, installed plugin and backup gates remain separate
requirements. Preserve the recovery plan; any extra rollback startup experiment
remains held until separately selected.

The current cut requires Node 24.22.1+ within 24.x or 26.12.1+, pnpm 12.15.0,
and managed Codex 0.160.0 with 10.6 plugin metadata. The active 10.5 executor
and receipts must not be relabeled for this target. See
`custom-patches/NEXT-RELEASE-2026.10.6.md` for the separate qualification plan.
The retained cross-build backup reuse contract remains restricted to the
original reviewed 10.5 transition and deliberately refuses 10.6.

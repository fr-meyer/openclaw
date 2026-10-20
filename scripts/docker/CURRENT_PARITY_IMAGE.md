# v2026.10.5 source preparation image contract

This isolated branch starts at the official annotated `v2026.10.5` tag.
`custom-patches/manifest.json` pins its tag object, commit, and tree and names
the prior 9.9 fork source for patch reconciliation. The prior 9.8 and 9.9
proof, images, and runtime authority do not qualify this branch. Patch
reconciliation remains in progress, so this branch is not an image candidate.

The Dockerfile carries the separately installed Mergeguez publisher package
from `scripts/docker/runtime-plugins/mergeguez-pr-lifecycle` at
`/app/runtime-plugins/mergeguez-pr-lifecycle`. It is inert at startup. The
package records the supplied source commit and SHA-256 of each shipped file in
`publisher-source.json`; `verify-package.mjs` checks the copied bytes. The
publisher pin transition, installed adapter, and config writer still need
10.5 runtime qualification before activation.

`node scripts/docker/package-current-publisher.mjs --plan-image true` refuses
while `carryForward.reconciliation` is `IN_PROGRESS`. Once every retained fork
patch has a reviewed disposition and focused source proof, mark that field
`COMPLETE_SOURCE` in a separate reviewed commit. The plan then checks tag
object and ancestry, product version, publisher runtime hash, and each
packaged file against the clean candidate commit. It prints a Git-context
Buildx command; it does not build or publish an image.

A later build must retain the exact source SHA, Buildx metadata, resolved
packages, and final image digest. Base images are digest-pinned, but Debian
package indexes, `npm@latest`, and the build timestamp can change image bytes.
The eventual target platform and timestamp must come from the deployment
environment. Native migration, startup/readiness, installed plugin, backup,
and rollback gates remain separate requirements.

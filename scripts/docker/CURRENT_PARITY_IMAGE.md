# v2026.9.9 source preparation image contract

This branch starts at the signed upstream `v2026.9.9` tag. The tracked
`custom-patches/manifest.json` records the exact upstream tag and the 9.8
product source used for a selective carry forward. The prior 9.8 proof files,
build result, and runtime authority do not qualify this branch.

The Dockerfile stages the separately installed Mergeguez publisher package from
`scripts/docker/runtime-plugins/mergeguez-pr-lifecycle` at
`/app/runtime-plugins/mergeguez-pr-lifecycle`. The package is inert at startup.
The image records the source commit and SHA-256 of each shipped file in
`publisher-source.json`; `verify-package.mjs` checks the packaged bytes after
copying them. The publisher pin transition and config writer still need runtime
qualification against 9.9 before they can be enabled or installed.

From a clean, committed source candidate, run:

```sh
node scripts/docker/package-current-publisher.mjs --plan-image true
```

The plan checks tag ancestry, the 9.9 manifest binding, the publisher runtime
hash, and each packaged file against the candidate commit. It prints an exact
Git-context Buildx command but does not run Docker, publish source, or change a
Gateway. The command's target platform, timestamp, and metadata output must be
filled from the later deployment environment. Its fork Git context requires the
candidate commit to be published there first under separately approved scope.

A later build must retain the exact source SHA, Buildx metadata, resolved
packages, and final image digest. The base images are digest-pinned, but Debian
package indexes, `npm@latest`, and the build timestamp can change image bytes.
`OPENCLAW_EXTENSIONS=workboard` selects the bundled Workboard extension; it does
not prove plugin config, database, or user-flow compatibility. Run the release
acceptance and rollback gates before promoting any image.

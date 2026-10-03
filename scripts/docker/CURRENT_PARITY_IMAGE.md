# v2026.9.8 local parity image contract

The tracked `custom-patches/manifest.json` enumerates the complete 14-commit
source composition through the qualified `1e197fa2` checkpoint. This successor
changes packaging only. It needs its own exact-source build and runtime gates.

The Dockerfile stages the private publisher package from
`scripts/docker/runtime-plugins/mergeguez-pr-lifecycle` at
`/app/runtime-plugins/mergeguez-pr-lifecycle`. It places the source commit,
package version, and SHA-256 of each of the seven shipped files in
`/app/runtime-plugins/publisher-source.json`. The final image runs
`/app/runtime-plugins/verify-package.mjs` after the copy and fails the build if
any shipped file differs. This verifier proves the seven packaged file bytes
against the local manifest; the full-SHA Git context and final image digest
provide source and image identity. A direct build with an arbitrary `GIT_COMMIT`
can mislabel source metadata and is not a qualified parity build. If
`GIT_COMMIT` is empty, the manifest records a null source commit.

The staged package is inert. The publisher pin-transition owner should use the
manifest and verifier when installing it at the configured plugin path, then
bind the actual loaded runtime source to the approved pin. The image recipe does
not edit Gateway settings, plugin config, installed data, or the rollback copy.
The package remains a separate plugin; `OPENCLAW_EXTENSIONS=workboard` selects
the Workboard bundled extension.

Run `node scripts/docker/package-current-publisher.mjs --plan-image true` from
a clean, committed successor checkout to print the exact source-linked local
build command as JSON. It checks the 14-commit ancestry, checkpoint trees,
publisher version, and publisher runtime SHA before printing. Replace the
target platform, timestamp, and metadata output placeholders only after
image-build approval and target architecture observation.
The command uses the fork Git context at the exact full successor SHA, so the
candidate commit must be available there after separately approved publication.
The command is a plan; the script never invokes Docker or publishes source.

The Node and Bun base images are digest-pinned, and pnpm installation uses the
frozen lockfile. The existing Dockerfile still performs mutable Debian
`apt-get update`/`dist-upgrade` and installs `npm@latest`; the build timestamp
and fetched package indexes also affect image bytes. Retain the Buildx metadata,
resolved package versions, final image digest, exact source commit, and staged
publisher manifest together when a build is eventually authorized. Do not infer
an image digest or runtime qualification from this source-only recipe.

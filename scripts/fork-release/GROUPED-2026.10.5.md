# Grouped post-9.8 stable candidate through 2026.10.5

The image seal inspects the loaded OCI image with the network disabled. It
requires the selected plugin descriptors and compiled entries, and checks the
Codex package version, host API compatibility, and Doctor migration contract
against the image host version. The resulting plugin evidence is retained in
the image receipt. This catches an image that contains a Codex CLI executable
but omits the OpenClaw Codex plugin. A native Doctor rehearsal still provides
the runtime migration proof.

The fork's inherited Labeler uses two upstream GitHub App secrets that are
empty in `fr-meyer/openclaw`. Its `pull_request_target` runs check out trusted
fork `main`, so changing this draft PR cannot repair its current Labeler jobs.
The reviewed workflow change selects the existing job-scoped `GITHUB_TOKEN`
only in this personal fork, keeping upstream's App-token path and the same
job permissions. It takes effect only after the workflow change reaches fork
`main`; Labeler is not a required check on this draft PR's base.

Source-only preparation, October 20, 2026. The active 9.8 rehearsal and the
separate production owner are outside this lane. This file does not select a
deployable source, publish an image, or authorize production.

## Existing owners and source anchor

- Reuse fork [release-pipeline PR #15](https://github.com/fr-meyer/openclaw/pull/15)
  for the tooling lane. The 9.9 owner has
  [`prep/v2026.9.9-source-only`](https://github.com/fr-meyer/openclaw/tree/prep/v2026.9.9-source-only).
  No 10.5 fork branch existed in the relevant branch/PR inventory on October 20.
- The official signed tag [`v2026.10.5`](https://github.com/openclaw/openclaw/releases/tag/v2026.10.5)
  peels to `1b58cb9a1b4f4353e1add63c8506db4d890962e8`. Its tagged
  `package.json` says version `2026.10.5`, Node `>=24.16.0 <25 || >=26.1.0`,
  and `pnpm@12.9.0`. Verify the retained tag/signature receipt before admitting
  a candidate.
- Reconcile [9.9](https://docs.openclaw.ai/releases/2026.9.9) and stable
  [10.1](https://docs.openclaw.ai/releases/2026.10.1),
  [10.2](https://docs.openclaw.ai/releases/2026.10.2),
  [10.3](https://docs.openclaw.ai/releases/2026.10.3),
  [10.4](https://docs.openclaw.ai/releases/2026.10.4), and
  [10.5](https://docs.openclaw.ai/releases/2026.10.5) behavior into the final
  target. Do not apply beta tags. [`9.33`](https://github.com/openclaw/openclaw/releases/tag/v2026.9.33)
  is a separate gateway-only extended-stable September line. GitHub's official
  10.4...10.5 compare is diverged (2,704 ahead, 463 behind); reconcile content
  and patch intent against the exact 10.5 tree rather than merging tag history.

## Migration and qualification boundaries

- The 9.8-to-10.5 database transition is shared state schema 19 to 20 and
  agent schema 24 to 25. Native Doctor and startup must validate the complete
  migration on a disposable copy of a **fresh current-production backup**.
  Schema 20's cron delivery-attempt fence leaves uncertain sends unknown;
  never replay them merely because a rehearsal or rollback restarted. Rollback
  needs the matching pre-upgrade data and build, and must account for writes
  accepted after capture.
- If EmbeddingGemma is configured, the 10.5 formatting change requires its
  documented one-time vector rebuild. Do not apply that work to installations
  that do not use it. Check installed Codex runtime compatibility with the
  official 2026.9.7 minimum and inspect policy plugins before activation.
- Build the product from the exact official base plus a reviewed ordered fork
  patch queue. Reconcile each retained 9.8/9.9 behavior against 10.5's source,
  including migration, state ownership, host compatibility, Workboard, backup,
  packaging, and regression owners. The existing seed inventory is incomplete;
  unresolved entries remain blocked. Keep the product source, trusted tooling,
  metadata seal, and OCI digest distinct in evidence.
- Use one isolated rehearsal from a verified snapshot or disposable restore,
  native Doctor, bounded patch and producer/consumer tests, startup/readiness,
  and a fenced rollback exercise. Keep application logs and native output with
  timestamps and phase/stall observations. Liveness alone is not evidence of
  migration progress. Measure comparable elapsed time and I/O before calling
  a path faster or optimized. Preserve all native integrity and security checks.
- Capture a new current-production backup and validate its identity, freshness,
  retention, completeness, and restore before any future activation. A prior
  test copy must never replace live data. The private adapter and durable GCP
  execution/resume path need disposable proof and one owner before production
  eligibility can change from false.

## Current disposition

The pipeline's manual job is being changed to read trusted `main` tooling and
an exact candidate metadata head, with a current PR head/base check. It still
needs hosted proof after reviewed integration. No grouped product patch queue,
eligible manifest, retained OCI artifact, native 10.5 rehearsal, benchmark, or
production decision exists in this preparation change.

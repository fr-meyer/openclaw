# V9.8 artifact preparation and consumption

This tooling targets product source `bc8b82b2cbbbb81f5abe6093e1bb3af4f1f70cdf`,
tree `ba825f670dc5ba943f7893cb267225d1f68d3110`. The source remains immutable.
Publishing a new tooling commit and starting another hosted build need separate
approval. This packet does not start an image, import its JavaScript, run Node,
execute a fixture or admit a new confinement boundary.

## Local checks

Run from the tooling checkout with a clean qualified source checkout available:

```sh
V98_QUALIFIED_SOURCE=/path/to/qualified-source \
  python3 -B -m unittest discover -s scripts/proofs/v98-parity -p 'test_*.py'
git diff --check
```

Hosted tests find the workflow's `source` checkout automatically. The validator
tests manufacture inert archive bytes and synthetic build-info; they read actual
qualified Git identity, source pins and public publisher files. They exercise
collector sealing, retention, ZIP creation and the consuming CLI. They do not
prove an actual compiled image, executable Node or runtime behavior.

## Consume a separately approved build

First fetch the terminal run JSON and artifact-list JSON through an authenticated
GitHub read for `fr-meyer/openclaw`, then download that run's exact artifact ZIP.
Keep those bytes and failed receipts. Do not derive the expected tooling commit
from a branch that may have advanced: use the exact approved packet commit.
Use a fresh output directory; the validator refuses existing output.

```sh
python3 -B scripts/proofs/v98-parity/verify-artifact.py \
  --archive /path/to/artifact.zip \
  --metadata /path/to/run-artifacts.json \
  --run-metadata /path/to/terminal-run.json \
  --source /path/to/qualified-source \
  --output /path/to/fresh-owned-validation-directory \
  --run-id "$v98_run_id" --run-attempt "$v98_run_attempt" \
  --artifact-id "$v98_artifact_id" --tooling-commit "$v98_approved_tooling_commit"
```

The caller supplies the run, attempt and artifact IDs from authenticated GitHub
reads. The validator has no network access of its own. GitHub metadata is its ZIP
identity anchor; a locally forged metadata file is not independent authentication.
The checked-in validator pins the reviewed collector and contract hashes before
executing their trusted Python bytes and bypasses bytecode caches. Any collector
or contract change requires matching validator pins and renewed review.

Exit `0` and `validation.json` status
`PREPARED_IMAGE_IDENTITY_VERIFIED; RUNTIME_UNQUALIFIED` mean the source tuple,
run/tooling/artifact/ZIP, retention evidence, compressed inventory, saved config
and every layer digest agree. Required identity-file content is independently
read from saved layers, applying overwrites and whiteouts. The Doctor API is
selected by its exact exported name; all 79 registered entries, Node/build-info
and eight publisher files are joined to those bytes. This verifies preparation
identity only. It does not certify the full transitive import/Worker closure or
a runnable filesystem.

Exit `1` records validated failure evidence with no admitted image. Exit `2`
means validation failed; no successful validation receipt is written. Keep the
ZIP, metadata and any partial owned decode for diagnosis. No failure permits
broader execution or an automatic rebuild.

The image archive stays capped at 2 GiB; evidence at 32 MiB total, 8 MiB per file,
and retention receipt at 64 KiB. Gzip inventory expansion is capped at 64 MiB.
Saved archives are capped at 4,096 members and 256 layers, tar metadata reads
at 8 MiB, and decompressed archive offsets/layer totals at 32 GiB. Unsupported
sparse payloads, backward layer reads and compiled paths beneath non-directory
parents fail closed.
Whiteouts apply before layer entries; remaining entries apply in archive order.
Hardlinks snapshot an existing direct regular target at their header encounter,
before later replacements. Forward, non-regular, self and destination-subtree
hardlink targets fail closed. The shared resolver checks parent types at every
symbolic-link hop and validates traversal before collapsing `.` or `..`.
Source and layer archives are read and hashed without host extraction or image
execution. Native policy, capability tests, six fixture phases, production
preservation, migration/restore/rollback and broker retirement/drain gates remain
separate and unqualified.

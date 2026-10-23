# Release rehearsal SQLite hygiene

The normal `gcp_rehearsal.py daily` lifecycle runs a metadata-only hygiene
assessment when it prepares Doctor and again after a successful Doctor before
candidate startup. It is release-triggered, never a calendar job. The sole
daily owner binds the immutable source/image, snapshot, restore generation,
clean-input config and database file metadata to private, write-once receipts.
`daily hygiene-assess` previews the same stage; `daily status` returns its
receipt hash and decision without reopening the database. A changed generation
refuses reuse instead of rewriting a result.

## Default and limits

The default decision is `skipped`: conventional SQLite and WAL file sizes alone
cannot prove removable space or corruption. The assessment opens no SQLite
connection, calls no memory CLI or provider, and launches no maintenance
command. It checks only the shared database and at most 128 immediate agent
directories on the attested disposable mount. It reports
`default-layout-only`; configured custom database directories require a
separate exact owner inventory. A file or WAL over 1 GiB prompts a later
measurement proposal, not an automatic scan, checkpoint or cleanup. The
assessment deadline is five minutes. Unsupported or over-bound metadata
records `bounded_metadata_unavailable` and defers optional hygiene rather
than blocking native Doctor. A measured fingerprint detects generation
changes but is not an integrity or content hash.

## When a release needs more work

The deployment owner records a separate decision with the exact database,
reclaimable-byte evidence, native command, required backup and integrity
receipt, expected downtime, temporary-space and provider-cost budget, and
approval. No optional action is implicit in Doctor success or this assessment.

- **Free SQLite pages:** after the native migration, compare DB/WAL size and
  `freelist_count × page_size` on an exclusively owned, stopped disposable
  copy. A review is useful when estimated reclaim is at least the greater of
  1 GiB or 10% of that DB. For 2026.10.5, the supported offline commands are
  `openclaw doctor --session-sqlite compact --session-sqlite-agent <id>` and
  `openclaw doctor --state-sqlite compact`. They checkpoint, `VACUUM` and
  validate. Allow at least the candidate's `2 × DB bytes + 64 MiB` temporary
  volume admission, plus the operation's other disk reserves. These commands
  repack retained data; they do not select data for deletion.
- **Derived memory problem:** `openclaw memory index --force --agent <id>`
  rebuilds derived search state. `openclaw memory reset --agent <id> --yes`
  discards only memory-owned derived tables/cache and requires a later rebuild.
  These need explicit selection, a verified backup and any embedding-provider
  cost/availability approval. Reset alone does not shrink the DB or delete
  canonical sessions.
- **Retention pressure:** preview with `openclaw sessions cleanup --dry-run`
  on a copy. `--enforce` can remove eligible history and has separate
  destructive authorization. Protected and cold archives follow their own
  rules; file size is not proof of eligibility.
- **Extension/backend difference:** confirm the exact release's sqlite-vec
  behavior and selected memory slot. LanceDB owns optional long-term memory,
  not the canonical agent session/transcript database.

Before migration, only use a verified baseline-version command on unchanged
baseline data if measured capacity or corruption prevents a safe upgrade.
Normally run candidate Doctor first: its native backup, schema migration and
integrity checks remain mandatory. Then decide whether optional compaction or
reindexing is worth the additional work. A valid current native integrity
receipt can support the same unchanged generation; no custom repeat scan is
added merely to make a second gate.

Before/after evidence includes DB and WAL bytes, free pages when measured,
scratch/free-space minima, elapsed time, native results, and a few private
session/search canaries. An optimization is an observation, not a performance
claim without comparable benchmarks. Candidate startup and readiness still
need native proof. A production rollout uses a fresh verified capture of the
then-current production database and its matching pre-upgrade build, never
the rehearsal clone. Keep the recovery plan and exact cleanup dispositions;
failed or uncertain actions remain fenced for one owner to reconcile.

This document describes optional manual decisions. The implemented default
stage deliberately cannot execute reset, reindex, compaction, retention
deletion or any production action.

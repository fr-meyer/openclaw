#!/usr/bin/env python3
"""Bounded, metadata-only SQLite hygiene assessment for a disposable rehearsal.

This module never opens SQLite, invokes OpenClaw, or changes a database. The
daily-snapshot owner validates the mount and clean-input receipt before calling
it. File metadata is a change detector, not a content or integrity proof.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import time

import release

need = release.need
MAX_AGENTS = 128
MAX_DATABASES = MAX_AGENTS + 1
ASSESSMENT_SECONDS = 300
LARGE_FILE_BYTES = 1 << 30


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def directory(path, device, *, optional=False):
    try:
        info = path.lstat()
    except FileNotFoundError:
        need(optional, 'hygiene.directory.missing')
        return False
    need(stat.S_ISDIR(info.st_mode) and info.st_dev == device and not stat.S_ISLNK(info.st_mode),
         'hygiene.directory.identity')
    return True


def file_metadata(path, device):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    need(stat.S_ISREG(info.st_mode) and info.st_dev == device and info.st_nlink == 1,
         'hygiene.file.identity')
    return {'sizeBytes': info.st_size, 'allocatedBytes': info.st_blocks * 512,
            'device': info.st_dev, 'inode': info.st_ino, 'mtimeNs': info.st_mtime_ns,
            'ctimeNs': info.st_ctime_ns}


def database_paths(state, device):
    result = [('shared', state / 'state' / 'openclaw.sqlite')]
    directory(state / 'state', device, optional=True)
    agents = state / 'agents'
    if directory(agents, device, optional=True):
        with os.scandir(agents) as entries:
            rows = []
            for entry in entries:
                need(len(rows) < MAX_AGENTS, 'hygiene.agents.bound')
                need(not entry.is_symlink(), 'hygiene.agent.symlink')
                rows.append(entry.name)
        for name in sorted(rows):
            need(name not in ('', '.', '..') and '/' not in name and '\\' not in name,
                 'hygiene.agent.name')
            agent = agents / name
            if not directory(agent, device, optional=True):
                continue
            if directory(agent / 'agent', device, optional=True):
                result.append(('agent:' + name, agent / 'agent' / 'openclaw-agent.sqlite'))
    need(len(result) <= MAX_DATABASES, 'hygiene.databases.bound')
    return result


def measure(clean, *, deadline=None):
    """Inspect exact conventional paths, one bounded directory level, and disk free space."""
    end = time.monotonic() + ASSESSMENT_SECONDS if deadline is None else deadline
    root, device = Path(clean['mountRoot']), clean['filesystemDevice']
    need(root.is_absolute() and directory(root, device), 'hygiene.root.identity')
    state_rows = [m for m in clean['mounts'] if m['target'] == '/home/node/.openclaw']
    need(len(state_rows) == 1 and state_rows[0]['readOnly'] is False,
         'hygiene.state.mount')
    state = Path(state_rows[0]['source'])
    need(root in state.parents and directory(state, device), 'hygiene.state.identity')
    records = []
    for owner, path in database_paths(state, device):
        need(time.monotonic() <= end, 'hygiene.deadline')
        db = file_metadata(path, device)
        wal = file_metadata(Path(str(path) + '-wal'), device)
        records.append({'owner': owner, 'path': str(path), 'database': db, 'wal': wal})
    available = os.statvfs(root)
    need(time.monotonic() <= end, 'hygiene.deadline')
    return {'scope': 'default-layout-only', 'contentVerified': False,
            'databasePaths': records, 'dataFreeBytes': available.f_bavail * available.f_frsize,
            'fingerprint': fingerprint(records)}


def binding(run, run_sha256, clean, clean_sha256, phase, doctor_result_sha256):
    return {'schema': 'openclaw.sqlite-hygiene-assessment.v1', 'phase': phase,
            'runSha256': run_sha256, 'sourceSha': run['image']['sourceSha'],
            'imageReceiptSha256': run['imageReceiptSha256'],
            'toolingSha': run['plan']['toolingSha'],
            'snapshotId': str(run['snapshot']['id']),
            'restoreReceiptSha256': clean['restoreReceiptSha256'],
            'cleanInputSha256': clean_sha256, 'configSha256': clean['configSha256'],
            'filesystemDevice': clean['filesystemDevice'],
            'doctorResultSha256': doctor_result_sha256}


def unavailable(run, run_sha256, clean, clean_sha256, phase, doctor_result_sha256):
    """Unsupported metadata shape skips optional hygiene, not native Doctor."""
    return {**binding(run, run_sha256, clean, clean_sha256, phase, doctor_result_sha256),
            'measuredAt': datetime.now(timezone.utc).isoformat(), 'elapsedSeconds': 0,
            'metrics': {'scope': 'unavailable', 'contentVerified': False,
                        'databasePaths': [], 'dataFreeBytes': None, 'fingerprint': None},
            'decision': {'state': 'skipped', 'reason': 'bounded_metadata_unavailable',
                         'followup': [{'kind': 'manual-owner-metadata-review'}],
                         'defaultLayoutOnly': True, 'nativeIntegrityRequired': True,
                         'requiresSeparateApproval': ['retention-delete', 'memory-reset',
                                                      'provider-reindex', 'sqlite-compact'],
                         'mutatingActionDispatched': False},
            'promotionAuthorized': False}


def assess(run, run_sha256, clean, clean_sha256, phase, doctor_result_sha256=None):
    """Return an immutable decision; optional maintenance is never dispatched here."""
    need(phase in ('baseline', 'post-doctor'), 'hygiene.phase')
    need((phase == 'post-doctor') == (doctor_result_sha256 is not None),
         'hygiene.doctor.binding')
    started = time.monotonic()
    first = measure(clean, deadline=started + ASSESSMENT_SECONDS)
    # A changed size/inode/time between observations is not a stable generation.
    second = measure(clean, deadline=started + ASSESSMENT_SECONDS)
    need(first == second, 'hygiene.database.changed_during_assessment')
    databases = [r for r in first['databasePaths'] if r['database'] is not None]
    orphan_wals = [r for r in first['databasePaths'] if r['database'] is None and r['wal'] is not None]
    followup = []
    for row in first['databasePaths']:
        if row['database'] is not None and row['database']['sizeBytes'] >= LARGE_FILE_BYTES:
            followup.append({'owner': row['owner'], 'kind': 'measure-free-pages-on-stopped-clone'})
        if row['wal'] is not None and row['wal']['sizeBytes'] >= LARGE_FILE_BYTES:
            followup.append({'owner': row['owner'], 'kind': 'check-reader-and-wal-on-stopped-clone'})
    return {**binding(run, run_sha256, clean, clean_sha256, phase, doctor_result_sha256),
            'measuredAt': datetime.now(timezone.utc).isoformat(),
            'elapsedSeconds': time.monotonic() - started, 'metrics': first,
            'decision': {'state': 'skipped',
                         'reason': ('wal_without_database_at_default_path' if orphan_wals else
                                    'no_database_at_default_paths' if not databases else
                                    'metadata_cannot_prove_reclaimable_space'),
                         'followup': followup,
                         'defaultLayoutOnly': True,
                         'nativeIntegrityRequired': True,
                         'requiresSeparateApproval': ['retention-delete', 'memory-reset',
                                                      'provider-reindex', 'sqlite-compact'],
                         'mutatingActionDispatched': False},
            'promotionAuthorized': False}

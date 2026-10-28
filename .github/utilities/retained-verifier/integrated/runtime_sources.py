"""Inert, opaque origins for the public part of a staged runtime.

These objects inspect bytes; they do not grant guest, staging or VM authority.
The fixed run57 path re-executes the reviewed inspector at its source digest.
Synthetic origins are test contracts bound to one explicit FakeIO instance.
A current-build CI origin has deliberately not been issued yet.
"""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
import re

import protocol as p

_KEY = object()
INSPECTOR_SHA256 = 'd547b87146fe104661f19174e0b0d3565b5b712a036ea57684d1dd14ff126d2f'
INSPECTOR_CAP = 32768
MATERIAL_CAPS = {
    'archive': 64 * 1024 * 1024,
    'verification': 16384,
    'host': 262144,
    'exact': 16384,
    'roster': 262144,
}
PLAN_KEYS = frozenset(('files', 'archiveSha256', 'verificationSha256',
    'hostResultSha256', 'exactResultSha256', 'sourceCommit', 'runId',
    'authorityKind', 'privateWorkerIncluded'))
ROW_KEYS = frozenset(('archivePath', 'path', 'bytes', 'mode', 'sha256'))
FILES_MAX = 8192
BYTES_MAX = 100 * 1024 * 1024
SYNTHETIC_SOURCE_COMMIT = '0' * 40
SYNTHETIC_RUN_ID = 'synthetic-contract'


def _materials(materials):
    p.require(type(materials) is dict and set(materials) == set(MATERIAL_CAPS),
              'runtime_source.material_roles')
    # Check every length and immutable byte type before hashing any input.
    for role, cap in MATERIAL_CAPS.items():
        p.require(type(materials[role]) is bytes and 0 < len(materials[role]) <= cap,
                  'runtime_source.material_cap')
    return {role: materials[role] for role in MATERIAL_CAPS}


def _digests(materials):
    return {role: p.sha(raw) for role, raw in materials.items()}


def _name(value):
    return (type(value) is str and 0 < len(value) <= 256 and
        not value.startswith('/') and '\\' not in value and '\x00' not in value and
        str(PurePosixPath(value)) == value and
        all(part not in ('.', '..') for part in PurePosixPath(value).parts) and
        re.fullmatch(r'[A-Za-z0-9_./+-]+', value) is not None)


def _rows(rows, *, signed=False):
    p.require(type(rows) is list and 0 < len(rows) <= FILES_MAX,
              'runtime_source.files_cap')
    result, paths, archives, total = [], set(), set(), 0
    for row in rows:
        p.require(type(row) is dict and set(row) == ROW_KEYS,
                  'runtime_source.row_schema')
        path, archive = row['path'], row['archivePath']
        p.require(_name(path) and _name(archive) and
                  (path == 'code/static-entry' or path.startswith(('usr/', 'lib/', 'lib64/'))),
                  'runtime_source.row_path')
        expected_archive = 'static-entry' if path == 'code/static-entry' else 'runtime/' + path
        p.require(archive == expected_archive and path not in paths and archive not in archives,
                  'runtime_source.row_closure')
        p.require(type(row['bytes']) is int and 0 <= row['bytes'] <= BYTES_MAX and
                  type(row['mode']) is int and row['mode'] in (0o444, 0o555) and
                  type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
                  'runtime_source.row_shape')
        total += row['bytes']
        p.require(total <= BYTES_MAX, 'runtime_source.expanded_cap')
        paths.add(path); archives.add(archive)
        result.append(dict(row))
    if signed:
        p.require(len(result) == 626 and total == 35563665 and
                  {'usr/bin/python3.11', 'lib64/ld-linux-x86-64.so.2',
                   'code/static-entry'} <= paths, 'runtime_source.signed_closure')
    p.require(all('/'.join(PurePosixPath(path).parts[:index]) not in paths
                  for path in paths for index in range(1, len(PurePosixPath(path).parts))),
              'runtime_source.file_parent_collision')
    return sorted(result, key=lambda row: row['path'])


def _synthetic_io(io):
    """An explicit test port cannot be an instance-relabelled native port."""
    return (type(io).__dict__.get('evidence_kind') == 'synthetic_contract' and
        getattr(io, 'evidence_kind', None) == 'synthetic_contract' and
        all(base.__dict__.get('evidence_kind') in (None, 'synthetic_contract')
            for base in type(io).__mro__))


def _plan(rows, digests, source_commit, run_id, kind):
    result = {'files': rows, 'archiveSha256': digests['archive'],
        'verificationSha256': digests['verification'],
        'hostResultSha256': digests['host'], 'exactResultSha256': digests['exact'],
        'sourceCommit': source_commit, 'runId': run_id, 'authorityKind': kind,
        'privateWorkerIncluded': False}
    p.require(set(result) == PLAN_KEYS, 'runtime_source.plan_schema')
    return result


def _inspect_signed(materials):
    path = Path(__file__).with_name('inspect_run57.py')
    raw = p.read_regular(path, INSPECTOR_CAP, expected_sha=INSPECTOR_SHA256)
    namespace = {'__name__': '_fixed_run57_runtime_inspector', '__file__': str(path)}
    exec(compile(raw, str(path), 'exec'), namespace)
    try:
        result = namespace['inspect'](*(materials[role] for role in MATERIAL_CAPS))
    except namespace['Refusal'] as error:
        raise p.Refusal(str(error)) from None
    p.require(type(result) is dict and result.get('activationAuthority') is False and
              result.get('privateVmAdmission') is False and result.get('stagePermitted') is False and
              result.get('privateWorkerIncluded') is False,
              'runtime_source.inspector_authority')
    return _plan(_rows(result['files'], signed=True), _digests(materials),
                 result['sourceCommit'], result['runId'], 'signed-run57')


class RuntimeSource:
    """A sealed origin, distinct from the capability permitting native effects."""
    __slots__ = ('_key', '_kind', '_bound_io', '_fixture_digests', '_fixture_plan', '_sealed')

    def __init_subclass__(cls, **_kwargs):
        raise TypeError('runtime_source.sealed_class')

    def __setattr__(self, name, value):
        p.require(not getattr(self, '_sealed', False), 'runtime_source.immutable')
        object.__setattr__(self, name, value)

    def __delattr__(self, _name):
        raise p.Refusal('runtime_source.immutable')

    def __init__(self, key, kind, *, bound_io=None, fixture_digests=None, fixture_plan=None):
        p.require(key is _KEY and kind in ('signed-run57', 'synthetic-contract'),
                  'runtime_source.unissued')
        self._key, self._kind, self._bound_io = key, kind, bound_io
        self._fixture_digests = fixture_digests
        self._fixture_plan = fixture_plan
        self._sealed = True

    def _issued(self):
        p.require(type(self) is RuntimeSource and getattr(self, '_key', None) is _KEY,
                  'runtime_source.unissued')

    @property
    def kind(self):
        self._issued()
        return self._kind

    def assert_for(self, cap_kind, io):
        self._issued()
        if self._kind == 'synthetic-contract':
            p.require(cap_kind == 'synthetic-contract' and io is self._bound_io and
                      _synthetic_io(io), 'runtime_source.synthetic_binding')
        else:
            # This checks compatibility only. The caller still needs an issued
            # owner/session capability before any NativeStorageIO operation.
            import guest_storage
            p.require(cap_kind == 'private-native' and
                      type(io) is guest_storage.NativeStorageIO and
                      getattr(io, 'evidence_kind', None) == 'native_fixed_storage',
                      'runtime_source.private_binding')
        return self

    def inspect_materials(self, materials):
        self._issued()
        materials = _materials(materials)
        if self._kind == 'signed-run57':
            return _inspect_signed(materials)
        p.require(p.canonical(_digests(materials)) == self._fixture_digests,
                  'runtime_source.synthetic_material_changed')
        return json.loads(self._fixture_plan)


def signed_run57_source():
    """Fixed public-subject inspection; no parameters or operational authority."""
    return RuntimeSource(_KEY, 'signed-run57')


def synthetic_source(io, materials, plan):
    """Freeze a small test fixture; never admissible for a native capability."""
    p.require(_synthetic_io(io), 'runtime_source.synthetic_io')
    materials = _materials(materials)
    p.require(type(plan) is dict and set(plan) == {'files'}, 'runtime_source.fixture_schema')
    digests = _digests(materials)
    result = _plan(_rows(plan['files']), digests, SYNTHETIC_SOURCE_COMMIT,
                   SYNTHETIC_RUN_ID, 'synthetic-contract')
    return RuntimeSource(_KEY, 'synthetic-contract', bound_io=io,
                         fixture_digests=p.canonical(digests), fixture_plan=p.canonical(result))


def ci_build_source(*_args, **_kwargs):
    """No CI issuer until the genuine current-build bootstrap chain is joined."""
    raise p.Refusal('runtime_source.ci_issuer_unissued')


if __name__ == '__main__':
    raise SystemExit('runtime_sources_no_cli')

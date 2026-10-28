"""Fixed storage side of one retained-verifier guest session.

No effects occur on import or CLI. Native IO cannot bind while the shared native
issuer is absent. All request paths are derived from an issued generation or
source constants; no shell/argv/path is accepted from an RPC request. Synthetic
IO tests exercise orchestration separately from Linux execution proof.
"""
from __future__ import annotations

import datetime as dt
from io import BytesIO
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import stat
import subprocess
import sys
import tarfile
import time

import copier
import copy_metadata_admission
import native_authority as authority
import profile
import protocol as p
import worker

# Private values are declared here so the synthetic export can replace only
# top-level fixtures while preserving every function/class definition.
TEST_UUID = '56b32afd-9976-4d21-9720-c4d5fcd02751'
TEST_DEVICE_ALIAS = '/dev/disk/by-id/virtio-ocv-integ-test-part1'
TEST_DISK_ALIAS = '/dev/disk/by-id/virtio-ocv-integ-test'
TEST_PARTITION_REQUIRED = True
BOOT_DEVICE_ALIASES = ('/dev/disk/by-id/virtio-ocv-integ-boot-absent', '/dev/disk/by-id/virtio-ocv-integ-boot')
BOOT_DEVICE_ALIAS = BOOT_DEVICE_ALIASES[0]  # Compatibility name; selection checks every candidate.
LEGACY_TEST_MOUNT = '/mnt/ocv-synthetic-unused'
RETAINED_RELATIVE = 'retained'
REPORT_RELATIVE = 'report/privacy.json'
OCI_RELATIVE = 'oci/default'
DISK_IDS = ('11', '12')
DEVICE_GROUPS = (0, 6)
FSTYPE = 'ext4'
MOUNT_TOOL = '/usr/bin/mount'
UMOUNT_TOOL = '/usr/bin/umount'
BLKID_TOOL = '/usr/sbin/blkid'
MOUNT_OPTIONS = 'ro,noload,nosuid,nodev,noexec'
MATERIALS = {
    'archive': ('public-runtime/public-tooling.tar.gz', 64 * 1024 * 1024),
    'verification': ('public-runtime/ATTESTATION-VERIFIED.private.json', 16384),
    'host': ('public-runtime/host-result.json', 262144),
    'exact': ('public-runtime/exact-worker-result.json', 16384),
    'roster': ('public-runtime/PUBLIC-RUNTIME-ROSTER.private.json', 262144),
}
CODE_NAMES = ('worker.py', 'protocol.py', 'hosted_export.py', 'hosted_privacy.py',
              'public-member-comparisons-v105-workboard.json')
SOURCE_MAX = 64 * 1024 * 1024
SOURCE_FILES_MAX = 128
MOUNTINFO_MAX = 1024 * 1024
CONTEXT_MAX = 16384
CAPTURE_MAX = 65536
ROOT_DIRECTORIES = ('run', 'tmp', 'var/tmp', 'dev/mqueue', 'proc', 'sys', 'control')
CUSTODY_ROLES = frozenset(('staging-manifest','host-snapshot','host-proof','ready-frame',
    'worker-stdout','worker-stderr','report','closeout'))


def _hex(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _identity(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_uid',
        'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def _relative(value):
    p.require(type(value) is str and value and '\\' not in value and '\x00' not in value,
              'storage.relative')
    p.require(re.fullmatch(r'[A-Za-z0-9_./+-]{1,512}', value) is not None, 'storage.relative')
    path = PurePosixPath(value)
    p.require(not path.is_absolute() and str(path) == value and
              all(c not in ('.', '..') for c in path.parts), 'storage.relative')
    return path.parts


def _mount_escape(value):
    p.require(re.search(r'\\(?!040|011|012|134)', value) is None, 'storage.mount_escape')
    table = {'040': ' ', '011': '\t', '012': '\n', '134': '\\'}
    return re.sub(r'\\(040|011|012|134)', lambda m: table[m.group(1)], value)


def parse_mountinfo(raw):
    """Bounded kernel mount records; paths are observations, never effect input."""
    p.require(type(raw) is bytes and len(raw) <= MOUNTINFO_MAX, 'storage.mountinfo_cap')
    try: text = raw.decode('utf-8')
    except UnicodeError: raise p.Refusal('storage.mountinfo_encoding') from None
    p.require(text.endswith('\n'), 'storage.mountinfo_shape')
    lines = text.splitlines()
    p.require(len(lines) <= 4096, 'storage.mountinfo_cap')
    result, seen = [], set()
    for line in lines:
        words = line.split(' ')
        p.require(len(words) >= 10 and words.count('-') == 1, 'storage.mountinfo_shape')
        at = words.index('-')
        p.require(at >= 6 and len(words) == at + 4 and words[0].isdigit() and
                  words[1].isdigit() and
                  int(words[0]) > 0 and words[0] not in seen and
                  re.fullmatch(r'(0|[1-9][0-9]*):(0|[1-9][0-9]*)', words[2]),
                  'storage.mountinfo_shape')
        seen.add(words[0])
        target, root = _mount_escape(words[4]), _mount_escape(words[3])
        p.require(target.startswith('/') and root.startswith('/'), 'storage.mountinfo_path')
        result.append({'id': int(words[0]), 'parent': int(words[1]),
            'majorMinor': words[2], 'root': root, 'target': target,
            'options': words[5].split(','), 'fstype': words[at+1],
            'source': _mount_escape(words[at+2]), 'superOptions': words[at+3].split(',')})
    return result


def validate_device_observation(value):
    p.closed(value, {'bootId', 'euid', 'machine', 'boot', 'test', 'mounts',
                      'sessionExists'}, 'storage.observation_schema')
    p.require(value['euid'] == 0 and value['machine'] == 'x86_64' and
              type(value['sessionExists']) is bool, 'storage.host_identity')
    boot = p.closed(value['boot'], {'rootMajorMinor', 'wholeMajorMinor',
        'aliasMajorMinor', 'aliases', 'fstype', 'freeBytes'}, 'storage.boot_schema')
    test = p.closed(value['test'], {'uuid', 'fstype', 'majorMinor',
        'uuidAliasMajorMinor', 'providerAliasMajorMinor', 'wholeMajorMinor',
        'providerWholeAliasMajorMinor', 'isPartition'}, 'storage.device_schema')
    numbers = (boot['rootMajorMinor'], boot['wholeMajorMinor'], boot['aliasMajorMinor'],
               test['majorMinor'], test['uuidAliasMajorMinor'], test['providerAliasMajorMinor'],
               test['wholeMajorMinor'],test['providerWholeAliasMajorMinor'])
    p.require(all(type(v) is str and re.fullmatch(r'\d+:\d+', v) for v in numbers) and
              boot['wholeMajorMinor'] == boot['aliasMajorMinor'] and
              boot['rootMajorMinor'] != test['majorMinor'] and
              boot['wholeMajorMinor'] != test['majorMinor'] and
              boot['rootMajorMinor'] != test['wholeMajorMinor'] and
              boot['wholeMajorMinor'] != test['wholeMajorMinor'] and
              boot['fstype'] == test['fstype'] == FSTYPE and
              type(boot['freeBytes']) is int and boot['freeBytes'] >= p.MIN_BOOT_FREE and
              test['uuid'] == TEST_UUID and test['majorMinor'] ==
              test['uuidAliasMajorMinor'] == test['providerAliasMajorMinor'],
              'storage.device_identity')
    p.require(type(boot['aliases']) is list and 1<=len(boot['aliases'])<=len(BOOT_DEVICE_ALIASES)
        and all(type(name) is str for name in boot['aliases'])
        and boot['aliases']==[name for name in BOOT_DEVICE_ALIASES if name in boot['aliases']]
        and len(set(boot['aliases']))==len(boot['aliases']) and
        test['wholeMajorMinor']==test['providerWholeAliasMajorMinor'] and
        type(test['isPartition']) is bool and test['isPartition'] is TEST_PARTITION_REQUIRED and
        ((test['majorMinor']!=test['wholeMajorMinor'])if TEST_PARTITION_REQUIRED else
         (test['majorMinor']==test['wholeMajorMinor'])),'storage.device_ancestry')
    p.require(type(value['mounts']) is list and len(value['mounts']) <= 4096,
              'storage.mount_count')
    for row in value['mounts']:
        p.require(type(row) is dict and 'blockWholeMajorMinor'in row and
            (row['blockWholeMajorMinor'] is None or
             (type(row['blockWholeMajorMinor']) is str and
              re.fullmatch(r'(0|[1-9][0-9]*):(0|[1-9][0-9]*)',row['blockWholeMajorMinor']))) and
            row['blockWholeMajorMinor']!=test['wholeMajorMinor'],'storage.mounted_block_ancestry')
    return value


def _code_rows(code):
    p.require(type(code) is dict and set(code) == set(CODE_NAMES), 'storage.code_roster')
    rows = []
    for name in CODE_NAMES:
        raw = code[name]
        p.require(type(raw) is bytes and len(raw) <= 262144, 'storage.code_cap')
        expected = p.CONSUMER.get(name)
        if name == 'protocol.py':
            p.require(p.sha(raw) == worker.PROTOCOL_SHA256, 'storage.protocol_pin')
        elif expected is not None:
            p.require(len(raw) == expected['bytes'] and p.sha(raw) == expected['sha256'],
                      'storage.consumer_pin')
        rows.append({'path': 'code/'+name, 'bytes': len(raw), 'sha256': p.sha(raw), 'mode': 0o444})
    return rows


def runtime_manifest(public_plan, code_rows, source_bundle_sha, profile_sha):
    """Deterministic source-known runtime closure, before physical copy IDs exist."""
    p.require(type(public_plan) is dict and type(public_plan.get('files')) is list and
              _hex(public_plan.get('archiveSha256')) and _hex(source_bundle_sha) and
              _hex(profile_sha), 'storage.runtime_plan')
    rows = []
    for row in public_plan['files']:
        p.closed(row, {'path', 'archivePath', 'bytes', 'sha256', 'mode'}, 'storage.runtime_row')
        path = '/'.join(_relative(row['path']))
        p.require(path.startswith(('usr/', 'lib/', 'lib64/')) or path == 'code/static-entry',
                  'storage.runtime_path')
        p.require(type(row['bytes']) is int and 0 <= row['bytes'] <= p.PUBLIC_MAX and
                  _hex(row['sha256']) and row['mode'] in (0o444, 0o555), 'storage.runtime_row')
        rows.append({k: row[k] for k in ('path', 'bytes', 'sha256', 'mode')})
    rows += list(code_rows)
    p.require(len(rows) == len({row['path'] for row in rows}) and len(rows) <= 8192 and
              sum(row['bytes'] for row in rows) <= p.PUBLIC_MAX, 'storage.runtime_closure')
    return {'schema': 'openclaw.private-runtime-closure.v1',
        'publicArchiveSha256': public_plan['archiveSha256'],
        'sourceBundleSha256': source_bundle_sha, 'profileSha256': profile_sha,
        'files': sorted(rows, key=lambda row: row['path'])}


def _source_manifest_rows(raw, expected, source_closure_sha):
    p.require(_hex(expected), 'storage.source_manifest_unbound')
    p.require(_hex(source_closure_sha), 'storage.source_closure_unbound')
    p.require(type(raw) is bytes and len(raw) <= 262144 and p.sha(raw) == expected,
              'storage.source_manifest_pin')
    doc = p.closed(p.decode(raw,262144), {'schema','files','sourceClosureSha256'},
                   'storage.source_manifest_schema')
    p.require(doc['schema'] == 'openclaw.native-guest-source-bundle.v1' and
              type(doc['files']) is list and 1 <= len(doc['files']) <= SOURCE_FILES_MAX and
              p.sha(p.canonical(doc['files'])) == doc['sourceClosureSha256'],
              'storage.source_manifest')
    rows,total = {},0
    for row in doc['files']:
        p.closed(row, {'path','bytes','sha256','mode'}, 'storage.source_row')
        name = '/'.join(_relative(row['path']))
        p.require(name != 'SOURCE-MANIFEST.private.json' and name not in rows and
                  row['mode'] == 0o444 and type(row['bytes']) is int and
                  0 <= row['bytes'] <= SOURCE_MAX and _hex(row['sha256']), 'storage.source_row')
        total += row['bytes'];p.require(total <= SOURCE_MAX, 'storage.source_cap')
        rows[name] = dict(row)
    p.require(all('/'.join(_relative(name)[:i]) not in rows for name in rows
                  for i in range(1,len(_relative(name)))), 'storage.source_file_parent')
    p.require(list(rows.values()) == sorted(rows.values(),key=lambda row:row['path']) and
              doc['sourceClosureSha256'] == source_closure_sha, 'storage.source_closure_pin')
    required = {x[0] for x in MATERIALS.values()} | {'code/'+x for x in CODE_NAMES} | \
               {'guest/PROFILE.template.private.json'}
    p.require(required <= set(rows), 'storage.source_roles_missing')
    return rows


def _storage_tool_hashes(pins):
    p.require(type(pins) is dict and set(pins) == {MOUNT_TOOL,UMOUNT_TOOL,BLKID_TOOL} and
              all(_hex(value) for value in pins.values()), 'storage.tools_unbound')
    return dict(pins)


class NativeStorageSession:
    """Controller-facing storage operations bound to exactly one generation."""
    def __init__(self, capability, io):
        self.cap = authority.require_capability(capability, 'storage', io)
        self.io = io
        self.base = self.cap.session_root
        self.root, self.evidence = self.base/'root', self.base/'evidence'
        self._context_raw = p.canonical(self.cap.context)
        self._staged_raw = None
        self.context_written = False
        self._used = set()
        self._preflight = self._mounted = self._unmounted = False
        self._observed = self._materials = self._plan = self._runtime = None
        self._owner_guard = None
        if hasattr(io, 'attach'): io.attach(self.cap)

    @property
    def context(self): return p.decode(self._context_raw, CONTEXT_MAX)

    @property
    def staged(self):
        return None if self._staged_raw is None else p.decode(self._staged_raw, 262144)

    def _time(self, *, cleanup=False, reserve=0):
        authority.require_capability(self.cap, 'storage', self.io)
        authority.require_time(self.cap, self.io.now(), cleanup=cleanup, reserve=reserve)

    def _once(self, label):
        p.require(label not in self._used, 'storage.operation_consumed')
        self._used.add(label)  # Intent precedes an ambiguous IO failure.

    def _join_context(self, context, *, final=False):
        p.require(type(context) is dict and context == self.context, 'storage.context_changed')
        p.require(all(context.get(k) == self.cap.owner[k] for k in
                      ('vmId', 'bootId', 'sessionId', 'unitName')), 'storage.context_owner')
        copy = dict(context)
        if not final:
            p.require(copy['inputManifestSha256'] is None and copy['workerDeadlineUtc'] is None,
                      'storage.precopy_manifest')
            copy['inputManifestSha256'] = '0'*64
            now = self.io.now()
            copy['workerDeadlineUtc'] = p.stamp(now+dt.timedelta(seconds=300))
        else: now = self.io.now()
        worker.validate_context(copy, p, now,
                                p.sha(self._materials['code']['worker.py']))

    def _runtime_facts(self):
        materials = self.io.read_source_materials()
        p.closed(materials, {'code', 'profile'}, 'storage.materials_schema')
        materials = dict(materials, runtime=self.io.read_runtime_materials())
        code_rows = _code_rows(materials['code'])
        p.require(type(materials['profile']) is bytes and
                  p.sha(materials['profile']) == profile.DESIGN_PROFILE_SHA,
                  'storage.profile_pin')
        # The source object is issued by the shared native authority, never by
        # a request's "verified" Boolean. Private and CI sources stay distinct.
        source = getattr(self.cap, 'runtime_source', None)
        p.require(source is not None, 'storage.runtime_authority_unissued')
        source.assert_for(self.cap.kind, self.io)
        public_plan = source.inspect_materials(materials['runtime'])
        plan = runtime_manifest(public_plan, code_rows,
            self.cap.owner['guestSourceSha256'], profile.DESIGN_PROFILE_SHA)
        p.require(p.sha(p.canonical(plan)) == self.context['runtimeManifestSha256'],
                  'storage.runtime_manifest_pin')
        return materials, public_plan, plan

    def preflight(self, context):
        self._time(reserve=900)
        self._once('preflight')
        guard = getattr(authority,'require_owner_guard',None)
        p.require(callable(guard), 'storage.owner_authority_unissued')
        # Storage absence is not a global SDK/session ownership assertion.
        # The shared issuer must join the independent fresh actual-owner proof.
        self._owner_guard = guard(self.cap,self.io)
        self._materials, self._plan, self._runtime = self._runtime_facts()
        self._join_context(context)
        observed = validate_device_observation(self.io.observe())
        p.require(observed['bootId'] == self.cap.owner['bootId'] and not observed['sessionExists'],
                  'storage.boot_or_session_changed')
        p.require(not any(row['majorMinor'] in (observed['test']['majorMinor'],observed['test']['wholeMajorMinor']) or
                         row['target'] == LEGACY_TEST_MOUNT or
                         row['target'].startswith(LEGACY_TEST_MOUNT+'/')for row in observed['mounts']),
                  'storage.test_already_mounted')
        self._observed = observed
        self.io.create_session()
        try:
            self.io.intent('mount')
            self.io.mount_test_readonly()
            self._mounted = True
            mount = self.io.observe_owned_mount()
            p.require(mount['uuid'] == TEST_UUID and mount['majorMinor'] ==
                      observed['test']['majorMinor'] and mount['readonly'] is True and
                      set(mount['options']) >= {'ro', 'nosuid', 'nodev', 'noexec'} and
                      mount['fstype'] == FSTYPE, 'storage.test_not_readonly')
            self._preflight = True
            return {'fresh': True, 'vmId': self.cap.owner['vmId'], 'testReadOnly': True,
                'bootFreeBytes': observed['boot']['freeBytes'],
                'diskIds': list(DISK_IDS), 'noOtherOwner': True, 'runtimeAuthoritiesBound': True}
        except BaseException:
            try: self.unmount_test_normally()
            except BaseException: pass
            raise

    def prepare(self, context):
        self._time(reserve=600)
        self._once('prepare')
        p.require(self._preflight and self.staged is None, 'storage.prepare_order')
        self._join_context(context)
        try:
            self.io.intent('prepare')
            self.io.stage_public_runtime(self._materials['runtime']['archive'], self._plan)
            self.io.stage_private_code(self._materials['code'])
            self.io.recheck_source_materials(self._materials)
            mount = self.io.observe_owned_mount()
            p.require(mount['uuid'] == TEST_UUID and mount['majorMinor'] ==
                      self._observed['test']['majorMinor'] and mount['readonly'] is True and
                      set(mount['options']) >= {'ro', 'nosuid', 'nodev', 'noexec'} and
                      mount['fstype'] == FSTYPE, 'storage.test_not_readonly')
            manifest = self.io.copy_private_inputs()
            _validate_copy_manifest(manifest)
            self.io.recheck_copied_inputs(manifest, expected_mode=0)
            staged_at = self.io.now()
            deadline = staged_at+dt.timedelta(seconds=300)
            p.require(deadline+dt.timedelta(seconds=120) <=
                      p.utc(self.cap.owner['providerStopAt']), 'storage.worker_closeout_reserve')
            props = profile.properties(self._materials['profile'], self.cap.owner['sessionId'],
                                       str(self.base))
            staged = {'inputManifest': manifest,
                'inputManifestSha256': manifest['manifestSha256'],
                'runtimeManifestSha256': p.sha(p.canonical(self._runtime)),
                'propertiesSha256': p.sha(p.canonical(props)),
                'copiesRootOwned': True, 'inputMode': 0,
                'stagedAtUtc':p.stamp(staged_at), 'workerDeadlineUtc':p.stamp(deadline)}
            self.io.write_staging_receipts(self._runtime, manifest, staged)
            self._staged_raw = p.canonical(staged)
            return self.staged
        except BaseException:
            # A normal owned unmount may be attempted once after a settled
            # preparation failure. Pending mount commands refuse that cleanup.
            try: self.unmount_test_normally()
            except BaseException: pass
            raise

    def write_public_context_once(self, raw):
        self._time(reserve=120)
        self._once('context')
        p.require(self.staged is not None and not self.context_written, 'storage.context_order')
        expected = dict(self.context, inputManifestSha256=self.staged['inputManifestSha256'],
                        workerDeadlineUtc=self.staged['workerDeadlineUtc'])
        p.require(type(raw) is bytes and len(raw) <= CONTEXT_MAX and
                  p.decode(raw, CONTEXT_MAX) == expected and p.canonical(expected) == raw,
                  'storage.context_staging_join')
        worker.validate_context(expected, p, self.io.now(),
                                p.sha(self._materials['code']['worker.py']))
        self.io.intent('context')
        self.io.write_context(raw)
        self._context_raw = p.canonical(expected)
        self.context_written = True

    def unmount_test_normally(self):
        self._time(cleanup=True)
        self._once('unmount')
        self.io.intent('unmount')
        self.io.unmount_test_normally()
        p.require(self.io.test_is_unmounted() is True, 'storage.test_still_mounted')
        self._unmounted = True

    def test_is_unmounted(self):
        self._time(cleanup=True)
        # A readback alone cannot substitute for the completed normal unmount.
        return self._unmounted and self.io.test_is_unmounted() is True

    def ready_for_worker(self, context):
        self._time(reserve=120)
        p.require(self.staged is not None and self.context_written and self._unmounted,
                  'storage.worker_before_unmount')
        self._join_context(context, final=True)
        p.require(self.io.test_is_unmounted() is True, 'storage.test_remounted')
        self.io.recheck_source_materials(self._materials)
        self.io.recheck_runtime(self._runtime)
        self.io.recheck_context(p.canonical(self.context))
        self.io.recheck_copied_inputs(self.staged['inputManifest'], expected_mode=0)
        return {'base': str(self.base), 'root': str(self.root), 'evidence': str(self.evidence),
            'contextSha256': p.sha(p.canonical(self.context)),
            'runtimeManifestSha256': self.staged['runtimeManifestSha256'],
            'propertiesSha256': self.staged['propertiesSha256'],
            'inputManifestSha256': self.staged['inputManifestSha256'],
            'stagedAtUtc':self.staged['stagedAtUtc'],
            'workerDeadlineUtc':self.staged['workerDeadlineUtc']}

    def release_copied_inputs_then_gate(self, gate, permit):
        self._time(reserve=30)
        p.require(self.context_written and self.staged is not None and self.test_is_unmounted(),
                  'storage.release_order')
        check = getattr(authority, 'require_release_permit', None)
        p.require(callable(check), 'storage.release_authority_unissued')
        check(permit, self.cap, self.context, gate)
        self._once('release')
        self.io.intent('release')
        self.io.recheck_copied_inputs(self.staged['inputManifest'], expected_mode=0)
        self.io.release_inputs_and_gate(p.canonical(gate))

    def read_exact_copied_report(self):
        self._time(cleanup=True)
        p.require(self.staged is not None, 'storage.report_before_copy')
        self._once('report')
        raw = self.io.read_copied_report()
        p.require(type(raw) is bytes and len(raw) == p.REPORT_BYTES and p.sha(raw) == p.REPORT_SHA,
                  'storage.copied_report_pin')
        return raw

    def remove_only_copied_session_files_after_custody(self, permit):
        self._time(cleanup=True)
        p.require(self.staged is not None and self.test_is_unmounted(), 'storage.cleanup_order')
        check = getattr(authority, 'require_custody_permit', None)
        p.require(callable(check), 'storage.custody_authority_unissued')
        roles = check(permit, self.cap, self.context, CUSTODY_ROLES)
        raw_manifest = p.canonical(self.staged['inputManifest'])
        p.require(set(roles) == CUSTODY_ROLES and roles['staging-manifest'] ==
                  {'bytes':len(raw_manifest),'sha256':p.sha(raw_manifest)},
                  'storage.custody_staging_join')
        self._once('remove')
        self.io.intent('remove')
        self.io.remove_copied_inputs(self.staged['inputManifest'])


def _validate_copy_manifest(manifest):
    p.closed(manifest, {'schema', 'bytes', 'files', 'entries', 'manifestSha256'},
             'storage.copy_manifest_schema')
    clean = {k: v for k, v in manifest.items() if k != 'manifestSha256'}
    p.require(manifest['schema'] == 'openclaw.nonroot-input-copy.v1' and
              p.sha(p.canonical(clean)) == manifest['manifestSha256'] and
              type(manifest['files']) is int and 1 <= manifest['files'] <= p.MAX_FILES and
              type(manifest['bytes']) is int and 0 < manifest['bytes'] <= p.PRIVATE_MAX and
              type(manifest['entries']) is list and len(manifest['entries']) == manifest['files'],
              'storage.copy_manifest')
    names, total = set(), 0
    for row in manifest['entries']:
        p.require(type(row) is dict and set(row) == {'path','bytes','sha256','dev','ino','uid','gid',
            'mode','nlink','mtimeNs','ctimeNs'}, 'storage.copy_row')
        name = '/'.join(_relative(row['path']))
        p.require(name not in names and (name == 'privacy.json' or name.startswith('oci/')) and
                  type(row['bytes']) is int and row['bytes'] >= 0 and _hex(row['sha256']) and
                  all(type(row[k]) is int and row[k] >= 0 for k in
                      ('dev','ino','uid','gid','mode','nlink','mtimeNs','ctimeNs')) and
                  row['uid'] == row['gid'] == 0 and row['mode'] == 0o444 and row['nlink'] == 1,
                  'storage.copy_row')
        if name == 'privacy.json':
            p.require(row['bytes'] == p.REPORT_BYTES and row['sha256'] == p.REPORT_SHA,
                      'storage.report_manifest_pin')
        names.add(name); total += row['bytes']
    p.require(total == manifest['bytes'] and
              {'privacy.json','oci/oci-layout','oci/index.json'} <= names,
              'storage.copy_closure')


def _open_same_filesystem(base_fd, parts, expected_device):
    current = os.dup(base_fd)
    try:
        for name in parts:
            child = os.open(name,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
                            dir_fd=current)
            try:
                info = os.fstat(child)
                p.require(stat.S_ISDIR(info.st_mode) and info.st_dev == expected_device,
                          'storage.source_directory_device')
            except BaseException:
                os.close(child);raise
            os.close(current);current=child
        return current
    except BaseException:
        os.close(current);raise


class DescriptorCopier(copier.Copier):
    """The existing bounded copier without reopening a multi-component path."""
    def _copy(self, directory, name, relative, **kwargs):
        p.require(os.fstat(directory).st_dev == self._source_device and
                  os.stat(name,dir_fd=directory,follow_symlinks=False).st_dev ==
                  self._source_device, 'storage.source_file_device')
        return super()._copy(directory,name,relative,**kwargs)

    def _directory(self, fd, relative, allowed):
        p.require(os.fstat(fd).st_dev == self._source_device, 'storage.source_directory_device')
        return super()._directory(fd,relative,allowed)

    def copy_from_fd(self, source_root_fd, report_relative, oci_relative, report_pin):
        p.require(set(report_pin) == {'bytes','sha256'}, 'storage.report_pin_schema')
        root = os.dup(source_root_fd)
        report_parent = oci = None
        before = os.fstat(root)
        self._source_device = before.st_dev
        try:
            report = _relative(report_relative)
            report_parent = _open_same_filesystem(root,report[:-1],before.st_dev)
            self._copy(report_parent,report[-1],Path('privacy.json'),
                       expected_sha=report_pin['sha256'],expected_size=report_pin['bytes'])
            oci = _open_same_filesystem(root,_relative(oci_relative),before.st_dev)
            (self.destination/'oci').mkdir(mode=0o700)
            self._directory(oci,Path('oci'),{'oci-layout':None,'index.json':None,
                                            'blobs':'blobs','ingest':'empty'})
            p.require(copier.dir_identity(os.fstat(root)) == copier.dir_identity(before),
                      'storage.source_root_changed')
            for base, dirs, _ in os.walk(self.destination,followlinks=False):
                for name in dirs:os.chmod(Path(base)/name,0o555,follow_symlinks=False)
            os.chmod(self.destination,0,follow_symlinks=False)
            result={'schema':'openclaw.nonroot-input-copy.v1','bytes':self.total,
                    'files':len(self.rows),'entries':self.rows}
            return {**result,'manifestSha256':p.sha(p.canonical(result))}
        finally:
            if report_parent is not None:os.close(report_parent)
            if oci is not None:os.close(oci)
            os.close(root)


class NativeStorageIO:
    """Authored Linux implementation; no method works before native binding.

    The shared issuer currently cannot bind this native IO. It exposes only
    fixed storage roles and derives every writable path from the capability.
    No generic command/read/path method is available to the RPC layer.
    """
    evidence_kind = 'native_fixed_storage'

    def __init__(self):
        self._cap = None
        self._source = None
        self._mount = None
        self._pending = None
        self._copy = None
        self._base_identity = self._gate_identity = None
        self._context_identity = None
        self._runtime_rows = None
        self._input_root_identity = None

    def attach(self, capability):
        p.require(self._cap is None, 'storage.io_already_bound')
        authority.require_capability(capability, 'storage', self)
        self._cap = capability

    def now(self): return dt.datetime.now(dt.timezone.utc)

    def _active(self, *, cleanup=False):
        p.require(self._cap is not None, 'storage.io_unbound')
        authority.require_capability(self._cap, 'storage', self)
        authority.require_time(self._cap, self.now(), cleanup=cleanup)
        p.require(sys.platform == 'linux' and os.geteuid() == 0 and
                  os.uname().machine == 'x86_64', 'storage.linux_root')
        boot = self._read_kernel(Path('/proc/sys/kernel/random/boot_id'), 128).strip().decode('ascii')
        p.require(boot == self._cap.owner['bootId'], 'storage.boot_changed')

    @property
    def base(self): return self._cap.session_root
    @property
    def root(self): return self.base/'root'
    @property
    def evidence(self): return self.base/'evidence'
    @property
    def test_mount(self): return self.base/'test-source'

    def _read(self, path, cap, *, immutable=False):
        before = path.lstat()
        p.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                  0 <= before.st_size <= cap, 'storage.file_identity')
        if immutable:
            p.require(before.st_uid == before.st_gid == 0 and
                      not stat.S_IMODE(before.st_mode) & 0o222, 'storage.immutable_file')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            opened = os.fstat(fd)
            p.require(_identity(opened) == _identity(before), 'storage.file_changed')
            parts, total = [], 0
            while total <= cap:
                block = os.read(fd, min(65536, cap + 1-total))
                if not block: break
                parts.append(block); total += len(block)
            after = os.fstat(fd)
        finally: os.close(fd)
        p.require(total == before.st_size and total <= cap and
                  _identity(before) == _identity(after) == _identity(path.lstat()),
                  'storage.file_changed')
        return b''.join(parts)

    def _read_kernel(self, path, cap):
        """Kernel pseudo-files have nominal sizes unrelated to their EOF."""
        p.require(path in (Path('/proc/self/mountinfo'),
                          Path('/proc/sys/kernel/random/boot_id')) or
                  (str(path).startswith('/sys/devices/') and path.name in ('dev','partition')),
                  'storage.kernel_path')
        p.require(type(cap) is int and 0 < cap <= MOUNTINFO_MAX, 'storage.kernel_cap')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            p.require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0,
                      'storage.kernel_identity')
            blocks, total = [], 0
            while total <= cap:
                raw = os.read(fd, min(65536,cap+1-total))
                if not raw: break
                blocks.append(raw); total += len(raw)
            after = os.fstat(fd)
            p.require(total <= cap and
                      (before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_gid) ==
                      (after.st_dev,after.st_ino,after.st_mode,after.st_uid,after.st_gid),
                      'storage.kernel_changed')
            return b''.join(blocks)
        finally: os.close(fd)

    def _root_chain(self, path, *, device=None):
        p.require(path.is_absolute() and path.resolve() == path, 'storage.canonical_parent')
        current = Path('/')
        for name in path.parts[1:]:
            current /= name
            info = current.lstat()
            p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
                      not stat.S_IMODE(info.st_mode) & 0o022 and not current.is_symlink(),
                      'storage.root_parent')
        if device is not None:
            p.require(path.stat().st_dev == device, 'storage.filesystem_changed')

    def _source_bundle(self):
        self._active()
        source = self._cap.source_root
        self._root_chain(source, device=os.stat('/').st_dev)
        pins = self._cap.pins
        expected = pins.get('sourceManifestSha256')
        p.require(_hex(expected), 'storage.source_manifest_unbound')
        raw = self._read(source/'SOURCE-MANIFEST.private.json', 262144, immutable=True)
        rows,values = _source_manifest_rows(raw,expected,self._cap.owner['guestSourceSha256']),{}
        for name,row in rows.items():
            target = source/name
            self._root_chain(target.parent, device=os.stat('/').st_dev)
            value = self._read(target, row['bytes'], immutable=True)
            p.require(len(value) == row['bytes'] and p.sha(value) == row['sha256'],
                      'storage.source_file_pin')
            values[name] = value
        actual, visited = set(), 0
        stack = [source]
        while stack:
            directory = stack.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    visited += 1; p.require(visited <= SOURCE_FILES_MAX*4, 'storage.source_walk_cap')
                    info = entry.stat(follow_symlinks=False)
                    p.require(info.st_uid == info.st_gid == 0 and info.st_dev == source.stat().st_dev,
                              'storage.source_owner')
                    item = Path(entry.path)
                    if stat.S_ISDIR(info.st_mode):
                        p.require(not stat.S_IMODE(info.st_mode) & 0o022, 'storage.source_parent')
                        stack.append(item)
                    else:
                        p.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                                  stat.S_IMODE(info.st_mode) == 0o444, 'storage.source_extra_type')
                        actual.add(str(item.relative_to(source)))
        p.require(actual == set(rows) | {'SOURCE-MANIFEST.private.json'}, 'storage.source_roster')
        self._source = {'manifest': raw, 'values': values}
        return values

    def read_source_materials(self):
        values = self._source_bundle()
        return {'code': {name: values['code/'+name] for name in CODE_NAMES},
                'profile': values['guest/PROFILE.template.private.json']}

    def read_runtime_materials(self):
        values = self._source_bundle()
        result = {}
        for role, (name, cap) in MATERIALS.items():
            p.require(len(values[name]) <= cap, 'storage.runtime_material_cap')
            result[role] = values[name]
        return result

    def recheck_source_materials(self, previous):
        code = self.read_source_materials()
        runtime = self.read_runtime_materials()
        p.require(code['code'] == previous['code'] and code['profile'] == previous['profile'] and
                  runtime == previous['runtime'], 'storage.source_changed')

    def _tool(self, path):
        pins = _storage_tool_hashes(self._cap.pins.get('storageTools'))
        target = Path(path)
        self._root_chain(target.parent)
        raw = self._read(target, 16*1024*1024)
        info = target.lstat()
        p.require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) & 0o111 and
                  not stat.S_IMODE(info.st_mode) & 0o022 and p.sha(raw) == pins[path],
                  'storage.tool_identity')

    def _capture(self, argv, seconds):
        """One fixed tool invocation, bounded pipes, no forced process cleanup."""
        p.require(self._pending is None and type(argv) is tuple and
                  argv[0] in (MOUNT_TOOL,UMOUNT_TOOL,BLKID_TOOL) and
                  type(seconds) is int and 0 < seconds <= 45, 'storage.command_scope')
        self._tool(argv[0])
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env={'PATH':'/usr/sbin:/usr/bin','LANG':'C','LC_ALL':'C'},
            close_fds=True, start_new_session=True)
        # Any unexpected exception after spawn is also an uncertain operation.
        # The pending marker clears only after leader, pipes and group settle.
        self._pending = child
        selector = selectors.DefaultSelector()
        streams = {'stdout': bytearray(), 'stderr': bytearray()}
        try:
            for label, stream in (('stdout',child.stdout),('stderr',child.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            end = time.monotonic()+seconds
            failed = None
            while True:
                for key, _ in selector.select(min(0.05,max(0,end-time.monotonic()))):
                    try: block = os.read(key.fileobj.fileno(), 65536)
                    except BlockingIOError: continue
                    if not block:
                        selector.unregister(key.fileobj); key.fileobj.close(); continue
                    room = CAPTURE_MAX-len(streams[key.data])
                    streams[key.data].extend(block[:room])
                    if len(block) > room: failed = 'capture_cap'
                code = child.poll()
                if code is not None and not selector.get_map(): break
                if failed or time.monotonic() >= end:
                    failed = failed or 'timeout'
                    # A live unreaped leader still owns the fresh process group.
                    # Never signal a group after its leader has been reaped.
                    if code is None:
                        try:
                            if os.getpgid(child.pid) == child.pid: os.killpg(child.pid, signal.SIGTERM)
                        except ProcessLookupError: pass
                    try: child.wait(timeout=5)
                    except subprocess.TimeoutExpired: pass
                    self._pending = child
                    raise p.Refusal('storage.command_uncertain', {'reason':failed})
            child.wait(timeout=1)
            try: os.killpg(child.pid, 0)
            except ProcessLookupError: pass
            else:
                self._pending = child
                raise p.Refusal('storage.command_group_uncertain')
            self._pending = None
            p.require(code == 0, 'storage.command_failed', {'exitCode':code,
                'stdoutBytes':len(streams['stdout']),'stderrBytes':len(streams['stderr']),
                'stdoutSha256':p.sha(bytes(streams['stdout'])),
                'stderrSha256':p.sha(bytes(streams['stderr']))})
            return bytes(streams['stdout'])
        finally:
            selector.close()
            for stream in (child.stdout, child.stderr):
                if stream is not None and not stream.closed: stream.close()

    def _device(self, alias):
        path = Path(alias)
        self._root_chain(path.parent)
        before = path.lstat()
        p.require(stat.S_ISLNK(before.st_mode) and before.st_uid == before.st_gid == 0,
                  'storage.device_alias_type')
        target = path.resolve(strict=True)
        p.require(str(target).startswith('/dev/') and target.parent == Path('/dev'),
                  'storage.device_alias_path')
        info = target.lstat()
        p.require(stat.S_ISBLK(info.st_mode) and info.st_uid == 0 and
                  info.st_gid in DEVICE_GROUPS and
                  stat.S_IMODE(info.st_mode) in (0o600,0o660),
                  'storage.device_block')
        p.require(_identity(path.lstat()) == _identity(before) and
                  path.resolve(strict=True) == target and
                  _identity(target.lstat()) == _identity(info), 'storage.device_alias_changed')
        return '{}:{}'.format(os.major(info.st_rdev),os.minor(info.st_rdev))

    def _block_ancestry(self, major_minor):
        p.require(type(major_minor) is str and re.fullmatch(r'(0|[1-9][0-9]*):(0|[1-9][0-9]*)',major_minor),
                  'storage.block_number')
        target = Path('/sys/dev/block')/major_minor
        resolved = target.resolve(strict=True)
        p.require(str(resolved).startswith('/sys/devices/'), 'storage.root_block_graph')
        own=self._read_kernel(resolved/'dev',128).strip().decode('ascii')
        p.require(own==major_minor,'storage.block_number_changed')
        partition = resolved/'partition'
        try:part_info=partition.lstat()
        except FileNotFoundError:part_info=None
        if part_info is not None:
            p.require(stat.S_ISREG(part_info.st_mode) and part_info.st_uid==part_info.st_gid==0 and
                      not stat.S_IMODE(part_info.st_mode)&0o022 and part_info.st_nlink==1,
                      'storage.partition_identity')
            part=self._read_kernel(partition,128).strip().decode('ascii')
            p.require(re.fullmatch(r'[1-9][0-9]{0,9}',part) and int(part)<2**31,
                      'storage.partition_number')
        whole = resolved.parent if part_info is not None else resolved
        p.require(str(whole).startswith('/sys/devices/'),'storage.root_block_graph')
        if part_info is not None:
            try:whole_partition=(whole/'partition').lstat()
            except FileNotFoundError:whole_partition=None
            p.require(whole_partition is None,'storage.whole_is_partition')
        raw = self._read_kernel(whole/'dev',128).strip().decode('ascii')
        p.require(re.fullmatch(r'(0|[1-9][0-9]*):(0|[1-9][0-9]*)',raw), 'storage.root_block_graph')
        return {'majorMinor':major_minor,'wholeMajorMinor':raw,'isPartition':part_info is not None}

    def _root_whole_device(self, major_minor):return self._block_ancestry(major_minor)['wholeMajorMinor']

    def _reject_test_mount_ancestry(self, rows, test_whole):
        """Reject any mounted partition of TEST, including unselected siblings."""
        p.require(type(rows) is list and len(rows)<=4096,'storage.mount_count')
        numbers={row['majorMinor']for row in rows};whole_numbers={}
        for number in sorted(numbers):
            p.require(type(number) is str and re.fullmatch(r'(0|[1-9][0-9]*):(0|[1-9][0-9]*)',number),
                      'storage.block_number')
            path=Path('/sys/dev/block')/number
            try:path.lstat()
            except FileNotFoundError:
                whole_numbers[number]=None;continue  # A genuinely absent non-block pseudo-filesystem.
            try:ancestry=self._block_ancestry(number)
            except FileNotFoundError:raise p.Refusal('storage.mounted_block_dangling')from None
            p.require(ancestry['wholeMajorMinor']!=test_whole,'storage.test_disk_mounted')
            whole_numbers[number]=ancestry['wholeMajorMinor']
        return [dict(row,blockWholeMajorMinor=whole_numbers[row['majorMinor']])for row in rows]

    def _boot_aliases(self, root_whole):
        present=[]
        for alias in BOOT_DEVICE_ALIASES:
            self._root_chain(Path(alias).parent)
            try:Path(alias).lstat()
            except FileNotFoundError:continue
            try:major=self._device(alias)
            except FileNotFoundError:raise p.Refusal('storage.boot_alias_dangling')from None
            p.require(major==root_whole,'storage.boot_alias_foreign')
            ancestry=self._block_ancestry(major)
            p.require(ancestry['isPartition'] is False and ancestry['wholeMajorMinor']==major,
                      'storage.boot_alias_partition')
            present.append(alias)
        p.require(present,'storage.boot_alias_missing')
        return present

    def _test_devices(self):
        part=self._device('/dev/disk/by-uuid/'+TEST_UUID)
        p.require(part==self._device(TEST_DEVICE_ALIAS),'storage.device_alias_changed')
        ancestry=self._block_ancestry(part)
        whole=self._device(TEST_DISK_ALIAS);whole_info=self._block_ancestry(whole)
        p.require(whole_info['isPartition'] is False and whole_info['wholeMajorMinor']==whole and
            ancestry['wholeMajorMinor']==whole and ancestry['isPartition'] is TEST_PARTITION_REQUIRED and
            ((part!=whole)if TEST_PARTITION_REQUIRED else(part==whole)), 'storage.test_parent')
        return part,whole,ancestry

    def _uuid(self):
        alias = '/dev/disk/by-uuid/'+TEST_UUID
        raw = self._capture((BLKID_TOOL,'-p','-s','UUID','-s','TYPE','-o','export','--',alias), 10)
        p.require(len(raw) <= 4096, 'storage.blkid_cap')
        try: lines = raw.decode('ascii').splitlines()
        except UnicodeError: raise p.Refusal('storage.blkid_encoding') from None
        values = {}
        for line in lines:
            p.require('=' in line, 'storage.blkid_shape')
            key, value = line.split('=',1)
            p.require(key in ('DEVNAME','UUID','TYPE') and key not in values and
                      len(value) <= 512, 'storage.blkid_shape')
            values[key] = value
        p.require(values.get('UUID') == TEST_UUID and values.get('TYPE') == FSTYPE,
                  'storage.blkid_identity')
        return values

    def _mounts(self): return parse_mountinfo(self._read_kernel(Path('/proc/self/mountinfo'),MOUNTINFO_MAX))

    def observe(self):
        self._active()
        rows = self._mounts()
        root = [r for r in rows if r['target'] == '/']
        p.require(len(root) == 1 and root[0]['root'] == '/' and 'rw' in root[0]['options'],
                  'storage.boot_mount')
        info = os.stat('/')
        major_minor = '{}:{}'.format(os.major(info.st_dev),os.minor(info.st_dev))
        p.require(root[0]['majorMinor'] == major_minor, 'storage.boot_device')
        root_info=self._block_ancestry(major_minor)
        aliases=self._boot_aliases(root_info['wholeMajorMinor'])
        test_minor,test_whole,test_info=self._test_devices()
        p.require(not any(r['majorMinor'] in (test_minor,test_whole) or r['target'] == LEGACY_TEST_MOUNT or
                          r['target'].startswith(LEGACY_TEST_MOUNT+'/')
                          for r in rows), 'storage.test_already_mounted')
        rows=self._reject_test_mount_ancestry(rows,test_whole)
        uuid = self._uuid()
        fs = os.statvfs('/var/lib')
        p.require(os.stat('/var/lib').st_dev == info.st_dev, 'storage.boot_path_device')
        return {'bootId':self._cap.owner['bootId'],'euid':os.geteuid(),
            'machine':os.uname().machine,'sessionExists':os.path.lexists(self.base),
            'boot':{'rootMajorMinor':major_minor,'wholeMajorMinor':root_info['wholeMajorMinor'],
                    'aliasMajorMinor':root_info['wholeMajorMinor'],'aliases':aliases,'fstype':root[0]['fstype'],
                    'freeBytes':fs.f_bavail*fs.f_frsize},
            'test':{'uuid':uuid['UUID'],'fstype':uuid['TYPE'],'majorMinor':test_minor,
                    'uuidAliasMajorMinor':test_minor,
                    'providerAliasMajorMinor':test_minor,'wholeMajorMinor':test_whole,
                    'providerWholeAliasMajorMinor':test_whole,'isPartition':test_info['isPartition']},'mounts':rows}

    def _owned_base(self):
        self._root_chain(self.base, device=os.stat('/').st_dev)
        info = self.base.lstat()
        p.require(stat.S_IMODE(info.st_mode) == 0o700 and
                  self._base_identity is not None and
                  (info.st_dev,info.st_ino,info.st_uid,info.st_gid) == self._base_identity,
                  'storage.session_identity')
        raw = self._read(self.base/'identity.private.json', 16384, immutable=True)
        expected = {'schema':'openclaw.native-storage-session.v1','owner':self._cap.owner,
                    'initialContextSha256':p.sha(p.canonical(self._cap.context))}
        p.require(raw == p.canonical(expected), 'storage.session_record')

    def _write_new(self, path, raw, mode):
        p.require(type(raw) is bytes and path.is_relative_to(self.base) and
                  mode in (0o400,0o444,0o600), 'storage.write_scope')
        self._root_chain(path.parent, device=os.stat('/').st_dev)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        try:
            os.fchmod(fd,mode)
            view = memoryview(raw)
            while view:
                count = os.write(fd,view)
                p.require(count > 0, 'storage.write_short')
                view = view[count:]
            os.fsync(fd)
            info = os.fstat(fd)
            p.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                      info.st_uid == info.st_gid == 0 and info.st_size == len(raw),
                      'storage.write_identity')
        finally: os.close(fd)
        parent = os.open(path.parent,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(parent)
        finally: os.close(parent)

    def _mkdir_owned(self, path, mode):
        """Set exact mode only on this call's exclusively created directory."""
        p.require(path == Path(authority.SESSION_BASE) or path.is_relative_to(self.base),
                  'storage.mkdir_scope')
        p.require(mode in (0o700,0o755), 'storage.mkdir_mode')
        self._root_chain(path.parent,device=os.stat('/').st_dev)
        os.mkdir(path,mode)
        fd=os.open(path,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            before=os.fstat(fd)
            p.require(stat.S_ISDIR(before.st_mode) and before.st_uid == before.st_gid == 0 and
                      before.st_dev == os.stat('/').st_dev and
                      _identity(before) == _identity(path.lstat()), 'storage.mkdir_identity')
            os.fchmod(fd,mode);os.fsync(fd)
            p.require(stat.S_IMODE(os.fstat(fd).st_mode) == mode and
                      _identity(os.fstat(fd)) == _identity(path.lstat()), 'storage.mkdir_changed')
        finally:os.close(fd)
        parent=os.open(path.parent,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:os.fsync(parent)
        finally:os.close(parent)

    def create_session(self):
        self._active()
        p.require(self._base_identity is None and self._pending is None,
                  'storage.session_already_created')
        parent = Path(authority.SESSION_BASE)
        try: self._mkdir_owned(parent,0o700)
        except FileExistsError: pass
        self._root_chain(parent,device=os.stat('/').st_dev)
        p.require(stat.S_IMODE(parent.stat().st_mode) == 0o700, 'storage.session_parent_mode')
        # Atomic exclusive directory creation is the durable pre-effect intent.
        # An interrupted generation is never silently reused or deleted.
        self._mkdir_owned(self.base,0o700)
        info = self.base.lstat()
        self._base_identity = (info.st_dev,info.st_ino,info.st_uid,info.st_gid)
        self._write_new(self.base/'identity.private.json',p.canonical({
            'schema':'openclaw.native-storage-session.v1','owner':self._cap.owner,
            'initialContextSha256':p.sha(p.canonical(self._cap.context))}),0o444)
        for name, mode in (('root',0o755),('evidence',0o700),('test-source',0o700)):
            self._mkdir_owned(self.base/name,mode)
        for name in ROOT_DIRECTORIES:
            target = self.root/name
            current=self.root
            for part in _relative(name):
                current/=part
                try:self._mkdir_owned(current,0o755)
                except FileExistsError:pass
                self._root_chain(current,device=info.st_dev)
                p.require(stat.S_IMODE(current.stat().st_mode) == 0o755,
                          'storage.root_directory_mode')
            self._root_chain(target,device=info.st_dev)
            p.require(stat.S_IMODE(target.stat().st_mode) == 0o755, 'storage.root_directory_mode')
        for name in ('worker.stdout','worker.stderr'):
            self._write_new(self.evidence/name,b'',0o600)
        gate = self.root/'control/admission.json'
        self._write_new(gate,b'',0o600)
        self._gate_identity = _identity(gate.lstat())
        self._owned_base()

    def intent(self, label):
        self._active(cleanup=label in ('unmount','remove'))
        self._owned_base()
        p.require(label in ('mount','prepare','context','unmount','release','remove'),
                  'storage.intent_label')
        self._write_new(self.evidence/('storage-'+label+'.INTENT.private.json'),
            p.canonical({'schema':'openclaw.native-storage-intent.v1','operation':label,
                         'owner':self._cap.owner,'atUtc':p.stamp(self.now())}),0o400)

    def _mount_rows(self):
        major,whole,_ = self._test_devices()
        rows = self._mounts()
        p.require(not any((row['majorMinor']==whole and whole!=major) or
            row['target']==LEGACY_TEST_MOUNT or row['target'].startswith(LEGACY_TEST_MOUNT+'/')
            for row in rows),
                  'storage.test_whole_mounted')
        # The one owned source mount is expected during normal unmount/custody;
        # every other mounted block device must have a different whole parent.
        self._reject_test_mount_ancestry([row for row in rows if row['majorMinor']!=major],whole)
        return major, rows, [row for row in rows if row['majorMinor'] == major]

    def mount_test_readonly(self):
        self._active()
        self._owned_base()
        p.require(self._mount is None and self._pending is None, 'storage.mount_consumed')
        major, rows, matching = self._mount_rows()
        p.require(not matching and not any(row['target'] in
                  (LEGACY_TEST_MOUNT,str(self.test_mount)) for row in rows),
                  'storage.test_already_mounted')
        p.require(major == self._device(TEST_DEVICE_ALIAS), 'storage.device_alias_changed')
        self._uuid()
        info = self.test_mount.lstat()
        p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
                  stat.S_IMODE(info.st_mode) == 0o700 and info.st_dev == os.stat('/').st_dev,
                  'storage.mountpoint_identity')
        with os.scandir(self.test_mount) as names:
            p.require(next(names,None) is None, 'storage.mountpoint_not_empty')
        self._capture((MOUNT_TOOL,'-t',FSTYPE,'-o',MOUNT_OPTIONS,'--',
                       '/dev/disk/by-uuid/'+TEST_UUID,str(self.test_mount)),45)
        facts = self.observe_owned_mount()
        p.require(facts['majorMinor'] == major, 'storage.mounted_device_changed')
        self._mount = facts

    def observe_owned_mount(self):
        self._active()
        major, rows, matching = self._mount_rows()
        p.require(len(matching) == 1 and matching[0]['target'] == str(self.test_mount),
                  'storage.owned_mount_missing_or_duplicated')
        p.require(not any(row['target'].startswith(str(self.test_mount)+'/') for row in rows),
                  'storage.nested_source_mount')
        row = matching[0]
        p.require(row['root'] == '/' and row['fstype'] == FSTYPE and
                  {'ro','nosuid','nodev','noexec'} <= set(row['options']) and
                  'rw' not in row['options'] and 'ro' in row['superOptions'] and
                  bool(os.statvfs(self.test_mount).f_flag & os.ST_RDONLY),
                  'storage.actual_mount_not_readonly')
        p.require(major == self._device(TEST_DEVICE_ALIAS), 'storage.mounted_alias_changed')
        self._uuid()
        if self._mount is not None:
            p.require(row['id'] == self._mount['mountId'], 'storage.mount_generation_changed')
        return {'uuid':TEST_UUID,'majorMinor':major,'fstype':row['fstype'],
            'readonly':True,'options':row['options'],'mountId':row['id']}

    def test_is_unmounted(self):
        self._active(cleanup=True)
        if self._pending is not None: return False
        _, rows, matching = self._mount_rows()
        return not matching and not any(row['target'] == str(self.test_mount) for row in rows)

    def unmount_test_normally(self):
        self._active(cleanup=True)
        self._owned_base()
        p.require(self._pending is None, 'storage.command_pending')
        _, rows, matching = self._mount_rows()
        if self._mount is None and not matching:
            p.require(not any(row['target'] == str(self.test_mount) for row in rows),
                      'storage.foreign_mount_at_owned_path')
            return  # Settled failed mount attempt: absence, never another effect.
        p.require(self._mount is not None and len(matching) == 1 and
                  matching[0]['target'] == str(self.test_mount) and
                  matching[0]['id'] == self._mount['mountId'], 'storage.unmount_generation')
        self._capture((UMOUNT_TOOL,'--',str(self.test_mount)),45)
        p.require(self.test_is_unmounted(), 'storage.normal_unmount_incomplete')

    def _runtime_file(self, relative, raw, mode):
        p.require(type(raw) is bytes and mode in (0o444,0o555), 'storage.runtime_write')
        parts = _relative(relative)
        p.require(relative.startswith(('usr/','lib/','lib64/')) or
                  relative.startswith('code/'), 'storage.runtime_target')
        rootfd = os.open(self.root,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent = rootfd
        try:
            for name in parts[:-1]:
                fresh=False
                try: os.mkdir(name,0o755,dir_fd=parent);fresh=True
                except FileExistsError: pass
                child = os.open(name,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,dir_fd=parent)
                try:
                    info = os.fstat(child)
                    if fresh:
                        p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
                                  info.st_dev == os.stat('/').st_dev, 'storage.runtime_parent')
                        os.fchmod(child,0o755);os.fsync(child);info=os.fstat(child)
                    p.require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o755 and
                              info.st_uid == info.st_gid == 0 and
                              info.st_dev == os.stat('/').st_dev, 'storage.runtime_parent')
                except BaseException:
                    os.close(child);raise
                if parent != rootfd: os.close(parent)
                parent = child
            fd = os.open(parts[-1],os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         mode,dir_fd=parent)
            try:
                os.fchmod(fd,mode)
                view = memoryview(raw)
                while view:
                    n = os.write(fd,view);p.require(n>0,'storage.runtime_short_write');view=view[n:]
                os.fsync(fd)
                info = os.fstat(fd)
                p.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                          info.st_uid == info.st_gid == 0 and info.st_size == len(raw),
                          'storage.runtime_file_identity')
            finally: os.close(fd)
            os.fsync(parent)
        finally:
            if parent != rootfd: os.close(parent)
            os.close(rootfd)

    def stage_public_runtime(self, archive_raw, plan):
        self._active()
        self._owned_base()
        materials = self.read_runtime_materials()
        source = self._cap.runtime_source
        source.assert_for(self._cap.kind,self)
        p.require(source.inspect_materials(materials) == plan and
                  archive_raw == materials['archive'], 'storage.runtime_source_changed')
        seen, total = set(), 0
        with tarfile.open(fileobj=BytesIO(archive_raw),mode='r:gz') as archive:
            for row in plan['files']:
                self._active()
                p.require(row['path'] not in seen, 'storage.runtime_duplicate')
                seen.add(row['path'])
                member = archive.getmember(row['archivePath'])
                p.require(member.isfile() and member.size == row['bytes'] and
                          member.mode == row['mode'], 'storage.runtime_member')
                raw = archive.extractfile(member).read(row['bytes']+1)
                total += len(raw)
                p.require(len(raw) == row['bytes'] and total <= p.PUBLIC_MAX and
                          p.sha(raw) == row['sha256'], 'storage.runtime_hash')
                self._runtime_file(row['path'],raw,row['mode'])

    def stage_private_code(self, code):
        self._active()
        self._owned_base()
        rows = _code_rows(code)
        p.require(p.sha(code['worker.py']) == self._cap.context['workerSha256'],
                  'storage.worker_source_pin')
        for row in rows:
            self._runtime_file(row['path'],code[row['path'][5:]],0o444)

    def copy_private_inputs(self):
        self._active()
        self._owned_base()
        self.observe_owned_mount()
        p.require(self._copy is None and not os.path.lexists(self.root/'input'),
                  'storage.copy_destination_exists')
        fs = os.statvfs(self.root)
        p.require(fs.f_bavail*fs.f_frsize >= p.MIN_BOOT_FREE, 'storage.copy_boot_space')
        source = os.open(self.test_mount,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        retained = None
        try:
            source_info = os.fstat(source)
            retained = _open_same_filesystem(source,_relative(RETAINED_RELATIVE),source_info.st_dev)
            fit=copy_metadata_admission.admittance(retained,REPORT_RELATIVE,OCI_RELATIVE,
                p.REPORT_BYTES,p.MAX_FILES,p.PRIVATE_MAX)
            self._write_new(self.evidence/'copy-fit.private.json',p.canonical(fit),0o600)
            result = DescriptorCopier(self.root/'input').copy_from_fd(retained,
                REPORT_RELATIVE,OCI_RELATIVE,{'bytes':p.REPORT_BYTES,'sha256':p.REPORT_SHA})
        finally:
            if retained is not None:os.close(retained)
            os.close(source)
        self.observe_owned_mount()  # Source stayed the same read-only mount generation.
        for row in result['entries']:
            info = self._copied_stat(row['path'])
            p.require(info.st_uid == info.st_gid == 0 and info.st_dev == os.stat('/').st_dev and
                      stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                      stat.S_IMODE(info.st_mode) == 0o444 and info.st_size == row['bytes'],
                      'storage.copy_destination_owner')
            row.update(mode=stat.S_IMODE(info.st_mode),nlink=info.st_nlink,
                       mtimeNs=info.st_mtime_ns,ctimeNs=info.st_ctime_ns)
        result['manifestSha256'] = p.sha(p.canonical({k:v for k,v in result.items()
                                                    if k!='manifestSha256'}))
        _validate_copy_manifest(result)
        info=(self.root/'input').lstat()
        self._input_root_identity=(info.st_dev,info.st_ino,info.st_uid,info.st_gid)
        self._copy = p.canonical(result)
        return p.decode(self._copy,262144)

    def _copied_stat(self, relative):
        parts = _relative(relative)
        fd = os.open(self.root/'input',os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent = None
        try:
            parent = copier.open_dir_at(fd,parts[:-1])
            return os.stat(parts[-1],dir_fd=parent,follow_symlinks=False)
        finally:
            if parent is not None:os.close(parent)
            os.close(fd)

    def recheck_copied_inputs(self, manifest, *, expected_mode):
        self._active(cleanup=True)
        self._owned_base()
        p.require(expected_mode in (0,0o555) and self._copy is not None and
                  p.canonical(manifest) == self._copy, 'storage.copy_manifest_changed')
        _validate_copy_manifest(manifest)
        root = (self.root/'input').lstat()
        p.require(stat.S_ISDIR(root.st_mode) and root.st_uid == root.st_gid == 0 and
                  root.st_dev == os.stat('/').st_dev and stat.S_IMODE(root.st_mode) == expected_mode,
                  'storage.copy_root_changed')
        p.require((root.st_dev,root.st_ino,root.st_uid,root.st_gid)==self._input_root_identity,
                  'storage.copy_root_replaced')
        for row in manifest['entries']:
            info = self._copied_stat(row['path'])
            p.require(stat.S_ISREG(info.st_mode) and
                (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_size,
                 stat.S_IMODE(info.st_mode),info.st_nlink,info.st_mtime_ns,info.st_ctime_ns) ==
                tuple(row[k] for k in ('dev','ino','uid','gid','bytes','mode','nlink','mtimeNs','ctimeNs')),
                'storage.copied_file_changed')
        self._check_input_roster(manifest)

    def _check_input_roster(self, manifest):
        """Prove the copied tree is closed before release or destructive cleanup."""
        expected = {row['path'] for row in manifest['entries']}
        required_dirs = {'oci','oci/blobs','oci/blobs/sha256'}
        for name in expected:
            parts = _relative(name)
            required_dirs.update('/'.join(parts[:i]) for i in range(1,len(parts)))
        allowed_dirs = required_dirs | {'oci/ingest'}
        files,dirs,visited = set(),set(),0
        root = os.open(self.root/'input',os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack = [(os.dup(root),'')]
        try:
            while stack:
                fd,prefix = stack.pop()
                try:
                    with os.scandir(fd) as names:
                        for entry in names:
                            visited += 1
                            p.require(visited <= p.MAX_FILES*5, 'storage.input_walk_cap')
                            relative = prefix+entry.name
                            info = entry.stat(follow_symlinks=False)
                            p.require(info.st_uid == info.st_gid == 0 and
                                      info.st_dev == os.fstat(root).st_dev,
                                      'storage.input_roster_owner')
                            if stat.S_ISDIR(info.st_mode):
                                p.require(relative in allowed_dirs and
                                          stat.S_IMODE(info.st_mode) == 0o555,
                                          'storage.input_directory_roster')
                                dirs.add(relative)
                                child = os.open(entry.name,os.O_RDONLY | os.O_DIRECTORY |
                                    os.O_NOFOLLOW | os.O_NONBLOCK,dir_fd=fd)
                                try:
                                    p.require(copier.dir_identity(os.fstat(child)) ==
                                              copier.dir_identity(info), 'storage.input_directory_changed')
                                except BaseException:
                                    os.close(child);raise
                                stack.append((child,relative+'/'))
                            else:
                                p.require(stat.S_ISREG(info.st_mode) and relative in expected,
                                          'storage.input_file_roster')
                                files.add(relative)
                finally: os.close(fd)
            p.require(files == expected and required_dirs <= dirs,
                      'storage.input_roster_missing')
        finally:
            for fd,_ in stack: os.close(fd)
            os.close(root)
        return dirs

    def write_staging_receipts(self, runtime, manifest, staged):
        self._active()
        p.require(self._copy == p.canonical(manifest), 'storage.staging_manifest_changed')
        self._write_new(self.evidence/'runtime-manifest.private.json',p.canonical(runtime),0o400)
        self._write_new(self.evidence/'input-manifest.private.json',self._copy,0o400)
        self._write_new(self.evidence/'staging.private.json',p.canonical(staged),0o400)
        self._runtime_rows = p.canonical(runtime)

    def recheck_runtime(self, runtime):
        self._active()
        self._owned_base()
        p.require(self._runtime_rows == p.canonical(runtime), 'storage.runtime_receipt_changed')
        for row in runtime['files']:
            target = self.root.joinpath(*_relative(row['path']))
            self._root_chain(target.parent,device=os.stat('/').st_dev)
            raw = self._read(target,row['bytes'],immutable=True)
            p.require(len(raw) == row['bytes'] and p.sha(raw) == row['sha256'] and
                      stat.S_IMODE(target.lstat().st_mode) == row['mode'],
                      'storage.staged_runtime_changed')

    def write_context(self, raw):
        self._active()
        self._owned_base()
        p.require(type(raw) is bytes and len(raw) <= CONTEXT_MAX and self._context_identity is None,
                  'storage.context_write_scope')
        target = self.root/'control/context.json'
        self._write_new(target,raw,0o444)
        self._context_identity = _identity(target.lstat())

    def recheck_context(self, raw):
        self._active()
        self._owned_base()
        target = self.root/'control/context.json'
        p.require(self._context_identity is not None and
                  _identity(target.lstat()) == self._context_identity and
                  self._read(target,CONTEXT_MAX,immutable=True) == raw,
                  'storage.context_changed')
        gate = self.root/'control/admission.json'
        p.require(self._gate_identity is not None and _identity(gate.lstat()) == self._gate_identity and
                  stat.S_IMODE(gate.stat().st_mode) == 0o600 and gate.stat().st_size == 0,
                  'storage.gate_placeholder_changed')

    def release_inputs_and_gate(self, raw):
        self._active()
        self._owned_base()
        p.require(type(raw) is bytes and 0 < len(raw) <= CONTEXT_MAX and self._copy is not None,
                  'storage.gate_publication_scope')
        gate = self.root/'control/admission.json'
        p.require(_identity(gate.lstat()) == self._gate_identity and
                  stat.S_IMODE(gate.stat().st_mode) == 0o600 and gate.stat().st_size == 0,
                  'storage.gate_publication_changed')
        manifest = p.decode(self._copy,262144)
        self.recheck_copied_inputs(manifest,expected_mode=0)
        os.chmod(self.root/'input',0o555,follow_symlinks=False)
        # Worker ignores mode0600 even if bytes exist. Publish complete bytes by
        # the final fchmod only after fsync; no partial JSON becomes readable.
        fd = os.open(gate,os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            p.require(_identity(os.fstat(fd)) == self._gate_identity, 'storage.gate_fd_changed')
            view=memoryview(raw)
            while view:
                count=os.write(fd,view);p.require(count>0,'storage.gate_short_write');view=view[count:]
            os.fsync(fd);os.lseek(fd,0,os.SEEK_SET)
            p.require(os.read(fd,CONTEXT_MAX+1)==raw,'storage.gate_readback')
            os.fchmod(fd,0o444);os.fsync(fd)
            p.require(_identity(os.fstat(fd))==_identity(gate.lstat()),'storage.gate_replaced')
        finally:os.close(fd)

    def read_copied_report(self):
        self._active(cleanup=True)
        self._owned_base()
        p.require(self._copy is not None, 'storage.report_not_copied')
        manifest=p.decode(self._copy,262144)
        row=next(r for r in manifest['entries'] if r['path']=='privacy.json')
        info=self._copied_stat('privacy.json')
        p.require((info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_size,
                   stat.S_IMODE(info.st_mode),info.st_nlink,info.st_mtime_ns,info.st_ctime_ns)==
                  tuple(row[k] for k in ('dev','ino','uid','gid','bytes','mode','nlink','mtimeNs','ctimeNs')),
                  'storage.report_copy_changed')
        raw=self._read(self.root/'input/privacy.json',p.REPORT_BYTES,immutable=True)
        p.require(len(raw)==p.REPORT_BYTES and p.sha(raw)==p.REPORT_SHA,'storage.report_copy_pin')
        return raw

    def remove_copied_inputs(self, manifest):
        self._active(cleanup=True)
        self._owned_base()
        p.require(self.test_is_unmounted() and self._copy==p.canonical(manifest),
                  'storage.cleanup_manifest_or_mount')
        root=self.root/'input'
        mode=stat.S_IMODE(root.lstat().st_mode)
        self.recheck_copied_inputs(manifest,expected_mode=mode)
        directories={tuple(_relative(name)) for name in self._check_input_roster(manifest)}
        fd=os.open(root,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for row in manifest['entries']:
                parts=_relative(row['path'])
                for i in range(1,len(parts)):directories.add(parts[:i])
                parent=copier.open_dir_at(fd,parts[:-1])
                try:os.unlink(parts[-1],dir_fd=parent)
                finally:os.close(parent)
            for parts in sorted(directories,key=lambda x:(-len(x),x)):
                parent=copier.open_dir_at(fd,parts[:-1])
                try:os.rmdir(parts[-1],dir_fd=parent)
                finally:os.close(parent)
            os.fsync(fd)
        finally:os.close(fd)
        os.rmdir(root)


if __name__ == '__main__':
    raise SystemExit('guest_storage_native_authority_unissued')

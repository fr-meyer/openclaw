"""CI-only grants derived from the actual authenticated Debian bootstrap.

JSON and test labels cannot construct these classes. Issuance requires the
genuine NativeCapability/Prepared/Plan/Compatibility seals, identical native
IO, current boot, source-pinned issuer code, authenticated tool/package rows,
and physical current-build runtime bytes. Private VM authority is excluded.
"""
from __future__ import annotations

import datetime as dt
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
from types import MappingProxyType

import integrated_fixture
import integrated_materials
import protocol as p

_KEY = object()
SOURCE_ROOT = '/opt/ocv/source'
CONTROL_ROOT = '/opt/ocv/control'
SOURCE_PREFIX = 'integrated/'
PIN_KEYS = frozenset(('contextSha256', 'guestSourceSha256', 'profileSha256',
    'workerSha256', 'entrySha256', 'runtimeManifestSha256', 'contextContractSha256',
    'transportReceiptSha256', 'macJournalRoot', 'sourceManifestSha256',
    'storageTools', 'unitTools', 'selinuxToolSha256', 'trustedCoreSources'))
OPERATIONAL_ROLES = frozenset(('storage', 'unit', 'mac'))


def _device_appearance_paths():
    return (integrated_fixture.BOOT_DEVICE_ALIAS, integrated_fixture.TEST_DEVICE_ALIAS,
            '/dev/disk/by-uuid/'+integrated_fixture.TEST_UUID)


def _poll_device_appearance(paths, *, check, now, lstat, stat_follow, pause, begin, deadline):
    """Readiness metadata only. This never validates a block device identity."""
    import guest_storage
    p.require(type(paths) is tuple and paths == _device_appearance_paths() and
              len(set(paths)) == 3, 'ci_authority.appearance_paths')
    p.require(type(begin) in (int, float) and type(deadline) in (int, float) and
              math.isfinite(begin) and math.isfinite(deadline) and
              begin < deadline <= begin+30, 'ci_authority.appearance_window')
    previous=begin
    for attempt in range(1, 302):
        check(); instant=now()
        p.require(type(instant) in (int, float) and math.isfinite(instant) and
                  previous <= instant < deadline, 'ci_authority.appearance_deadline')
        previous=instant;missing=False
        for path in paths:
            try:
                alias=lstat(path)
                p.require(stat.S_ISLNK(alias.st_mode) and
                          alias.st_uid == alias.st_gid == 0, 'ci_authority.appearance_alias_type_owner')
                target=stat_follow(path)
                p.require(stat.S_ISBLK(target.st_mode) and target.st_uid == 0 and
                          target.st_gid in guest_storage.DEVICE_GROUPS,
                          'ci_authority.appearance_target_type_owner')
            except FileNotFoundError:
                missing=True
        if not missing:
            check();finished=now()
            p.require(previous <= finished < deadline, 'ci_authority.appearance_deadline')
            return {'schema':'ocv.ci-device-appearance.v1','appearanceOnly':True,
                'identityValidated':False,'paths':list(paths),'attempts':attempt,
                'elapsedMilliseconds':int((finished-begin)*1000)}
        pause(min(.1,max(0,deadline-instant)))
    raise p.Refusal('ci_authority.appearance_attempt_bound')


def wait_for_device_appearance(parent, prepared):
    """One bounded native metadata poll before source/device admission."""
    _, io, _ = _parent(parent, prepared)
    begin=io.monotonic()
    p.require(parent.expires-begin > 1590, 'ci_authority.appearance_insufficient_reserve')
    deadline=min(parent.expires,begin+30)
    return _poll_device_appearance(_device_appearance_paths(),check=parent.check,
        now=io.monotonic,lstat=os.lstat,stat_follow=os.stat,pause=time.sleep,
        begin=begin,deadline=deadline)


def _sealed(instance):
    p.require(getattr(instance, '_key', None) is _KEY, 'ci_authority.unissued')


def _source_file(io, plan, relative, cap=262144):
    rows = [row for row in plan.source['files'] if row.get('path') == relative]
    p.require(len(rows) == 1, 'ci_authority.source_unlisted')
    row = rows[0]
    p.require(type(row) is dict and set(row) == {'path', 'bytes', 'sha256', 'mode'} and
              row['mode'] == 0o444 and type(row['bytes']) is int and
              0 < row['bytes'] <= cap, 'ci_authority.source_row')
    record = io.file(SOURCE_ROOT + '/' + relative, cap)
    p.require(type(record) is dict and record.get('regular') is True and
              record.get('uid') == record.get('gid') == 0 and record.get('mode') == 0o444 and
              record.get('canonicalPath') == SOURCE_ROOT + '/' + relative and
              type(record.get('raw')) is bytes and len(record['raw']) == row['bytes'] and
              p.sha(record['raw']) == row['sha256'], 'ci_authority.source_file_changed')
    return record['raw']


def _parent(parent, prepared):
    # Refuse on Mac before importing any native bootstrap entry or doing IO.
    p.require(sys.platform == 'linux' and os.geteuid() == os.getegid() == 0,
              'ci_authority.linux_root_required')
    try:
        import guard
        import issuer
        import native_io
    except ImportError:
        raise p.Refusal('ci_authority.bootstrap_unavailable') from None
    p.require(type(parent) is issuer.NativeCapability and parent.seal is issuer._SEAL and
              type(prepared) is issuer.Prepared and prepared._seal is issuer._PREPARED_SEAL and
              type(parent.io) is native_io.NativeEvidenceIO and prepared.io is parent.io and
              prepared.plan is parent.plan and type(parent.plan) is guard.Plan and
              parent.plan._seal is guard._PLAN_SEAL and parent.plan._verified_io is parent.io and
              parent.aliases is prepared.aliases and parent.tools is prepared.tools,
              'ci_authority.genuine_parent_required')
    compatibility = prepared.compatibility
    p.require(type(compatibility) is issuer.Compatibility and
              compatibility._seal is issuer._COMPATIBILITY_SEAL and
              compatibility.io is parent.io and compatibility.plan is parent.plan,
              'ci_authority.actual_compatibility_required')
    for name, module in (('issuer', issuer), ('guard', guard), ('native_io', native_io)):
        expected = SOURCE_ROOT + '/bootstrap/' + name + '.py'
        p.require(sys.modules.get(name) is module and str(Path(module.__file__).resolve()) == expected,
                  'ci_authority.bootstrap_module_path')
        source = _source_file(parent.io, parent.plan, 'bootstrap/' + name + '.py')
        # Do not let a sys.modules lookalike certify its own fictitious file IO.
        # The outer loader already established this tree; rejoin that physical
        # immutable file directly before accepting its class/seal universe.
        try:
            info = os.lstat(expected)
            p.require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
                      stat.S_IMODE(info.st_mode) == 0o444 and info.st_nlink == 1,
                      'ci_authority.bootstrap_source_identity')
            physical = p.read_regular(expected, 262144, expected_sha=p.sha(source))
        except OSError:
            raise p.Refusal('ci_authority.bootstrap_source_unavailable') from None
        p.require(physical == source, 'ci_authority.bootstrap_source_changed')
    parent.check()
    io, plan = parent.io, parent.plan
    for filename, expected_sha, expected_doc, cap in (
            (SOURCE_ROOT+'/PUBLIC-SOURCE-MANIFEST.json', plan.markers['ocv.source'], plan.source, 1048576),
            (CONTROL_ROOT+'/build.json', plan.markers['ocv.build'], plan.build, 1048576)):
        record = io.file(filename, cap); raw = record['raw']
        p.require(record.get('regular') is True and record.get('uid') == record.get('gid') == 0 and
                  record.get('mode') == 0o444 and type(raw) is bytes and
                  p.sha(raw) == expected_sha and guard.decode(raw, cap) == expected_doc,
                  'ci_authority.parent_source_or_build_marker')
    for name in ('runtime', 'tools', 'imports', 'apt'):
        record = io.file(CONTROL_ROOT+'/'+name+'.json', 8*1024*1024)
        raw = record['raw']
        p.require(record.get('regular') is True and record.get('uid') == record.get('gid') == 0 and
                  record.get('mode') == 0o444 and type(raw) is bytes and
                  p.sha(raw) == plan.control_hashes[name] and
                  guard.decode(raw, 8*1024*1024) == plan.controls[name],
                  'ci_authority.parent_control_changed')
    p.require(io.claimed is True and io.own is not None and io.own[2] == plan.boot_id and
              type(parent.expires) in (int, float) and io.monotonic() < parent.expires and
              parent.expires <= io.started + integrated_fixture.GUEST_WRAPPER_SECONDS,
              'ci_authority.parent_window')
    run = plan.build['runIdentity']
    p.require(type(run) is dict and set(run) ==
              {'repository', 'workflowRef', 'sourceCommit', 'runId', 'runAttempt'} and
              run['repository'] == 'fr-meyer/openclaw' and
              run['workflowRef'] == ('fr-meyer/openclaw/.github/workflows/'
              'authorized-beta-focused-validation.yml@refs/heads/retained-verifier-prerequisites') and
              re.fullmatch('[0-9a-f]{40}', run['sourceCommit']) and
              re.fullmatch('[1-9][0-9]{0,19}', run['runId']) and run['runAttempt'] == '1' and
              plan.build['fixtureOnly'] is True and plan.build['candidateImage'] is False and
              plan.build['sourceManifestSha256'] == plan.markers['ocv.source'],
              'ci_authority.source_origin')
    p.require(issuer.compatibility_result(guard.decode(compatibility.raw, 12288), plan) ==
              compatibility.raw and prepared.metadataProof.get('status') == 'classified',
              'ci_authority.prepared_proof_changed')
    expected_tools = {row['role']: row for row in plan.controls['tools']['tools']}
    p.require(prepared.tools == expected_tools and
              set(integrated_fixture.EXTRA_TOOL_SPECS) <= set(expected_tools),
              'ci_authority.authenticated_storage_tools_missing')
    package_rows = {row['name']: row for row in plan.controls['runtime']['packages']}
    for role, spec in integrated_fixture.EXTRA_TOOL_SPECS.items():
        row = expected_tools[role]; package = package_rows.get(spec['package'])
        p.require(row['path'] == spec['path'] and row['package'] == spec['package'] and
                  package is not None and row['version'] == package['version'] and
                  row['debSha256'] == package['debSha256'], 'ci_authority.tool_package_join')
    # These source-owned checks re-read the installed/status/index/hash chain.
    issuer.verify_signed_package_bindings(io, plan, prepared.tools)
    issuer.verify_packages(io, plan, prepared.tools)
    aliases, tools = guard.validate_runtime(io, plan)
    p.require(all(prepared.aliases.get(k) == row for k, row in aliases.items()) and
              tools == prepared.tools, 'ci_authority.prepared_alias_changed')
    return issuer, io, plan


def _parent_pin(parent, prepared):
    return p.sha(p.canonical({'source': parent.plan.source, 'build': parent.plan.build,
        'controls': parent.plan.controls, 'controlHashes': parent.plan.control_hashes,
        'markers': parent.plan.markers, 'bootId': parent.plan.boot_id,
        'aliases': prepared.aliases, 'tools': prepared.tools,
        'metadataProof': prepared.metadataProof,
        'compatibilitySha256': p.sha(prepared.compatibility.raw)}))


def _live_parent(parent, prepared, expected_pin):
    """Identity/boot/source joins; operation deadlines remain component-owned.

    Issuance already performed every actual APT/installed/runtime read. Repeating
    that whole build transaction on every D-Bus call would exceed snapshot age.
    Native effect ports still perform their fixed per-effect identity/tool reads.
    Cleanup is not suppressed merely because the work clock has elapsed.
    """
    import guard
    import issuer
    import native_io
    p.require(type(parent) is issuer.NativeCapability and parent.seal is issuer._SEAL and
              type(prepared) is issuer.Prepared and prepared._seal is issuer._PREPARED_SEAL and
              prepared.io is parent.io and prepared.plan is parent.plan and
              type(parent.io) is native_io.NativeEvidenceIO and type(parent.plan) is guard.Plan and
              parent.plan._seal is guard._PLAN_SEAL and parent.plan._verified_io is parent.io and
              parent.aliases is prepared.aliases and parent.tools is prepared.tools and
              _parent_pin(parent, prepared) == expected_pin,
              'ci_authority.live_parent_changed')
    parent.check(cleanup=True)
    return True


class CIRuntimeSource:
    __slots__ = ('_key', '_parent', '_prepared', '_parent_pin', '_storage',
                 '_materials', '_plan', '_sealed')
    def __init_subclass__(cls, **_kwargs): raise TypeError('ci_authority.sealed_class')
    def __setattr__(self, name, value):
        p.require(not getattr(self, '_sealed', False), 'ci_authority.immutable')
        object.__setattr__(self, name, value)
    def __delattr__(self, _name): raise p.Refusal('ci_authority.immutable')
    def __init__(self, key, parent, prepared, storage, materials, plan):
        p.require(key is _KEY, 'ci_authority.runtime_unissued')
        self._key, self._parent, self._prepared = key, parent, prepared
        self._parent_pin, self._storage = _parent_pin(parent, prepared), storage
        self._materials = MappingProxyType(dict(materials)); self._plan = p.canonical(plan)
        self._sealed = True
    @property
    def kind(self): _sealed(self); return 'ci-current-build'
    @property
    def materials(self): _sealed(self); return dict(self._materials)
    def require_parent(self, parent, prepared):
        _sealed(self)
        p.require(self._parent is parent and self._prepared is prepared,
                  'ci_authority.runtime_parent_changed')
        _live_parent(parent, prepared, self._parent_pin)
        return self
    def assert_for(self, cap_kind, io):
        import guest_storage
        self.require_parent(self._parent, self._prepared)
        p.require(cap_kind == 'ci-native-proof' and io is self._storage and
                  type(io) is guest_storage.NativeStorageIO,
                  'ci_authority.runtime_io_join')
        return self
    def inspect_materials(self, materials):
        import runtime_sources
        supplied = runtime_sources._materials(materials)
        self.require_parent(self._parent, self._prepared)
        p.require(all(supplied[k] == self._materials[k] for k in supplied),
                  'ci_authority.runtime_material_changed')
        return json.loads(self._plan)


def current_runtime_source(parent, prepared, storage_io):
    import guest_storage
    _, io, plan = _parent(parent, prepared)
    p.require(type(storage_io) is guest_storage.NativeStorageIO,
              'ci_authority.runtime_native_storage')
    rows, payloads = [], {}
    for seed, row in sorted(prepared.aliases.items()):
        name = row['path']
        if not (name == 'code/static-entry' or name.startswith(('usr/', 'lib/', 'lib64/'))):
            continue
        p.require(seed == '/seed/' + name and name not in payloads,
                  'ci_authority.runtime_alias')
        record = io.file(row['sourcePath'], 32*1024*1024)
        raw = record['raw']
        p.require(record.get('regular') is True and record.get('uid') == record.get('gid') == 0 and
                  not record.get('mode', 0o777) & 0o022 and
                  record.get('canonicalPath') == row['sourcePath'] and
                  type(raw) is bytes and len(raw) == row['bytes'] and p.sha(raw) == row['sha256'],
                  'ci_authority.runtime_alias_changed')
        rows.append({'path': name, 'archivePath': 'static-entry' if name == 'code/static-entry'
                     else 'runtime/' + name, 'bytes': len(raw), 'sha256': p.sha(raw), 'mode': row['mode']})
        payloads[name] = raw
    run = plan.build['runIdentity']
    receipt = {'schema': 'ocv.current-authenticated-bootstrap-origin.v1',
        'sourceCommit': run['sourceCommit'], 'runId': run['runId'],
        'sourceManifestSha256': plan.markers['ocv.source'], 'bootId': plan.boot_id,
        'runtimeControlSha256': plan.control_hashes['runtime'],
        'toolControlSha256': plan.control_hashes['tools'],
        'metadataProofSha256': p.sha(p.canonical(prepared.metadataProof)),
        'compatibilitySha256': p.sha(prepared.compatibility.raw),
        'qualificationProofComplete': False, 'nativeAuthorityFromReceipt': False}
    materials, rows = integrated_materials.current_runtime_materials(rows, payloads, receipt)
    import runtime_sources
    runtime_sources._materials(materials)
    result = {'files': rows, 'archiveSha256': p.sha(materials['archive']),
        'verificationSha256': p.sha(materials['verification']),
        'hostResultSha256': p.sha(materials['host']), 'exactResultSha256': p.sha(materials['exact']),
        'sourceCommit': run['sourceCommit'], 'runId': run['runId'],
        'authorityKind': 'ci-current-build', 'privateWorkerIncluded': False}
    return CIRuntimeSource(_KEY, parent, prepared, storage_io, materials, result)


class CIGrant:
    __slots__ = ('_key', '_parent', '_prepared', '_parent_pin', '_owner', '_context', '_pins',
                 '_ios', '_runtime', '_channel', '_issued_phases', '_graph', '_graph_rows', '_root', '_sealed')
    def __init_subclass__(cls, **_kwargs): raise TypeError('ci_authority.sealed_class')
    def __setattr__(self, name, value):
        p.require(not getattr(self, '_sealed', False), 'ci_authority.immutable')
        object.__setattr__(self, name, value)
    def __delattr__(self, _name): raise p.Refusal('ci_authority.immutable')
    def __init__(self, key, parent, prepared, owner, context, pins, ios, runtime):
        p.require(key is _KEY, 'ci_authority.grant_unissued')
        self._key, self._parent, self._prepared = key, parent, prepared
        self._parent_pin = _parent_pin(parent, prepared)
        self._owner, self._context, self._pins = p.canonical(owner), p.canonical(context), p.canonical(pins)
        self._ios, self._runtime = MappingProxyType(dict(ios)), runtime
        self._channel = ios['mac']; self._issued_phases = frozenset()
        self._graph = parent.io._integrated_module_graph
        self._root = Path('/var/lib/openclaw-retained-verifier-source')/owner['guestSourceSha256']
        self._graph_rows = MappingProxyType({row['path']: dict(row)
            for row in pins['trustedCoreSources'].values()})
        self._sealed = True

    @property
    def channel(self): _sealed(self); return self._channel

    def require_live(self):
        _sealed(self)
        _live_parent(self._parent, self._prepared, self._parent_pin)
        p.require(getattr(self._parent.io, '_integrated_module_graph', None) is self._graph,
                  'ci_authority.execution_graph_changed')
        self._graph.require_loaded_rows(self._root, dict(self._graph_rows))
        return True

    def require_for(self, phase, owner, context, pins, ios, runtime_source, bootstrap=None):
        _sealed(self)
        p.require(type(self) is CIGrant and phase in ('bootstrap', 'operational'),
                  'ci_authority.grant_phase')
        self.require_live()
        p.require(_parent_pin(self._parent, self._prepared) == self._parent_pin and
                  p.canonical(owner) == self._owner and p.canonical(context) == self._context and
                  p.canonical(pins) == self._pins and runtime_source is self._runtime,
                  'ci_authority.grant_binding_changed')
        expected = {'owner_guard'} if phase == 'bootstrap' else OPERATIONAL_ROLES
        p.require(type(ios) is dict and set(ios) == expected and
                  all(io is self._ios[role] for role, io in ios.items()),
                  'ci_authority.grant_io_changed')
        if phase == 'operational':
            import guest_bootstrap
            p.require(type(bootstrap) is guest_bootstrap.VerifiedBootstrap and
                      bootstrap.purpose == 'ci-native-proof' and bootstrap.owner == owner and
                      bootstrap.bundle_sha256 == owner['guestSourceSha256'] and
                      bootstrap.manifest_sha256 == pins['sourceManifestSha256'],
                      'ci_authority.verified_source_required')
            bootstrap.assert_source_path()
        self._runtime.require_parent(self._parent, self._prepared)
        p.require(phase not in self._issued_phases and
                  (phase != 'operational' or 'bootstrap' in self._issued_phases),
                  'ci_authority.phase_consumed_or_order')
        object.__setattr__(self, '_issued_phases', self._issued_phases | {phase})
        return True

    def require_channel(self, channel):
        _sealed(self)
        p.require(channel is self._channel, 'ci_authority.channel_changed')
        self.require_live()
        return True


def _physical_bundle(owner, pins):
    import guest_storage
    import native_authority
    root = Path(native_authority.SOURCE_BASE) / owner['guestSourceSha256']
    current = Path('/')
    for part in root.parts[1:]:
        current /= part; info = current.lstat()
        p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
                  not stat.S_IMODE(info.st_mode) & 0o022 and not current.is_symlink(),
                  'ci_authority.source_parent')
    raw = p.read_regular(root/'SOURCE-MANIFEST.private.json', 16384,
                         expected_sha=pins['sourceManifestSha256'])
    rows = guest_storage._source_manifest_rows(raw, pins['sourceManifestSha256'],
                                              owner['guestSourceSha256'])
    doc = p.decode(raw, 16384)
    p.require(doc['sourceClosureSha256'] == owner['guestSourceSha256'],
              'ci_authority.source_closure')
    values = {}
    for name, row in rows.items():
        path = root/name
        before = path.lstat()
        p.require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and
                  stat.S_IMODE(before.st_mode) == 0o444, 'ci_authority.source_identity')
        values[name] = p.read_regular(path, row['bytes'], expected_sha=row['sha256'],
                                      expected_size=row['bytes'])
    actual = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            path = Path(directory)/name; info = path.lstat()
            p.require(stat.S_ISDIR(info.st_mode) and not path.is_symlink() and
                      info.st_uid == info.st_gid == 0 and not stat.S_IMODE(info.st_mode) & 0o022,
                      'ci_authority.source_directory')
        for name in files:
            actual.add((Path(directory)/name).relative_to(root).as_posix())
            p.require(len(actual) <= 129, 'ci_authority.source_count')
    p.require(actual == set(rows) | {'SOURCE-MANIFEST.private.json'},
              'ci_authority.source_roster')
    return root, rows, values


def issue_ci_grant(parent, prepared, owner, context, pins, ios, runtime_source):
    import guest_storage
    import guest_unit
    import integrated_guest
    import native_authority
    import owner_guard
    import profile
    import worker
    _, io, plan = _parent(parent, prepared)
    native_authority.validate_owner(owner)
    p.require(type(pins) is dict and set(pins) == PIN_KEYS and type(ios) is dict and
              set(ios) == OPERATIONAL_ROLES | {'owner_guard'} and
              type(ios['storage']) is guest_storage.NativeStorageIO and
              type(ios['unit']) is guest_unit.NativeUnitIO and
              type(ios['mac']) is integrated_guest.LocalGuestTransport and
              type(ios['owner_guard']) is owner_guard.NativeOwnerGuardIO and
              type(runtime_source) is CIRuntimeSource and runtime_source._storage is ios['storage'],
              'ci_authority.exact_ports_required')
    runtime_source.require_parent(parent, prepared)
    session = p.sha(('integrated:' + plan.markers['ocv.session']).encode('ascii'))[:32]
    p.require(owner['vmId'] == integrated_fixture.VM_ID and owner['bootId'] == plan.boot_id and
              owner['sessionId'] == session and owner['unitName'] == 'ocv-'+session+'.service',
              'ci_authority.owner_origin')
    now = io.utc(); remaining = parent.expires-io.monotonic()
    p.require(type(now) is dt.datetime and now.tzinfo is not None and
              now+dt.timedelta(seconds=900) < p.utc(owner['providerStopAt']) and
              p.utc(owner['executionDeadlineUtc']) <= now+dt.timedelta(seconds=remaining),
              'ci_authority.real_cleanup_window')
    root, rows, values = _physical_bundle(owner, pins)
    public_name = 'guest/PUBLIC-INTEGRATED-SOURCE-MANIFEST.json'
    public_manifest = p.decode(values[public_name], 65536)
    p.require(type(public_manifest) is dict and public_manifest.get('schema') ==
              'ocv.integrated-public-sources.v1' and type(public_manifest.get('files')) is list,
              'ci_authority.public_source_manifest')
    expected_guest = {'guest/'+row['path'] for row in public_manifest['files']
                      if not row['path'].startswith('fixture/')} | {public_name}
    expected_roles = expected_guest | {'code/'+name for name in guest_storage.CODE_NAMES} | \
                     {name for name, _cap in integrated_materials.MATERIALS.values()}
    p.require(set(rows) == expected_roles, 'ci_authority.source_role_closure')
    for name, raw in values.items():
        if name.startswith('guest/'):
            relative = name[len('guest/'):]
            original = _source_file(io, plan, SOURCE_PREFIX + relative)
            p.require(raw == original, 'ci_authority.outer_source_changed')
    p.require(set(context) == set(worker.CONTEXT_KEYS) and
              context['inputManifestSha256'] is None and context['workerDeadlineUtc'] is None and
              all(context[k] == owner[k] for k in ('vmId', 'bootId', 'sessionId', 'unitName')) and
              context['privacyBytes'] == worker.REPORT_BYTES and
              context['privacySha256'] == worker.REPORT_SHA256 and
              context['sourceSha'] == worker.SOURCE and context['scannerSha'] == worker.SCANNER and
              context['indexDigest'] == worker.INDEX and context['consumerCode'] == worker.CONSUMER and
              context['maxJobSeconds'] == 300 and context['operation'] == 'retained-report-only' and
              context['mountPropagation'] == 'private' and
              context['identityName'] == 'ocv-'+session[:24] and
              context['contextNonce'] == p.sha((session+plan.boot_id).encode('ascii')),
              'ci_authority.context_origin')
    code = {name: values['code/'+name] for name in guest_storage.CODE_NAMES}
    p.require(all(raw == values['guest/'+name] for name, raw in code.items()) and
              all(values[name] == runtime_source.materials[role] for role, (name, _cap) in
                  integrated_materials.MATERIALS.items()), 'ci_authority.bundle_roles_changed')
    public_plan = runtime_source.inspect_materials(runtime_source.materials)
    runtime_manifest = guest_storage.runtime_manifest(public_plan, guest_storage._code_rows(code),
        owner['guestSourceSha256'], profile.DESIGN_PROFILE_SHA)
    helper = next(row['sha256'] for row in public_plan['files'] if row['path'] == 'code/static-entry')
    hashes = {'contextSha256': p.sha(p.canonical(context)),
        'guestSourceSha256': owner['guestSourceSha256'], 'profileSha256': profile.DESIGN_PROFILE_SHA,
        'workerSha256': p.sha(code['worker.py']), 'entrySha256': helper,
        'runtimeManifestSha256': p.sha(p.canonical(runtime_manifest)),
        'contextContractSha256': p.sha(p.canonical(sorted(worker.CONTEXT_KEYS)))}
    p.require(all(pins[k] == value for k, value in hashes.items()) and
              all(context[k] == hashes[k] for k in
                  ('profileSha256', 'workerSha256', 'entrySha256', 'runtimeManifestSha256')),
              'ci_authority.context_pin_join')
    tools = prepared.tools
    storage_tools = {spec['path']: tools[role]['sha256']
                     for role, spec in integrated_fixture.STORAGE_TOOL_SPECS.items() if role != 'findmnt'}
    unit_tools = {tools[role]['path']: tools[role]['sha256'] for role in
                  ('systemd-run', 'systemctl', 'busctl', 'selinuxenabled')}
    p.require(pins['storageTools'] == storage_tools and pins['unitTools'] == unit_tools and
              pins['selinuxToolSha256'] == tools['selinuxenabled']['sha256'] and
              pins['macJournalRoot'] == str(Path(owner_guard.CONTROL_ROOT)/session/'mac-journal'),
              'ci_authority.actual_tool_pins')
    channel_record = {'schema': 'ocv.ci-local-channel.v1', 'owner': owner,
        'outerSourceManifestSha256': plan.markers['ocv.source'],
        'sourceManifestSha256': pins['sourceManifestSha256'],
        'transportSourceSha256': rows['guest/integrated_guest.py']['sha256']}
    p.require(pins['transportReceiptSha256'] == p.sha(p.canonical(channel_record)),
              'ci_authority.channel_source_pin')
    graph = getattr(io, '_integrated_module_graph', None)
    p.require(graph is not None and callable(getattr(graph, 'require_loaded_rows', None)),
              'ci_authority.source_execution_graph_unissued')
    executed_core = graph.require_loaded_rows(root, rows)
    p.require(pins['trustedCoreSources'] == executed_core,
              'ci_authority.complete_source_execution_core')
    return CIGrant(_KEY, parent, prepared, owner, context, pins, ios, runtime_source)


def session_descriptor(parent, prepared, source_binding, runtime_source):
    """Derive the request representation; only issue_ci_grant can authenticate it."""
    import guest_storage
    import native_authority
    import owner_guard
    import profile
    import worker
    _, io, plan = _parent(parent, prepared)
    p.require(type(source_binding) is dict and set(source_binding) ==
              {'sourceClosureSha256', 'sourceManifestSha256'} and
              all(type(value) is str and re.fullmatch('[0-9a-f]{64}', value)
                  for value in source_binding.values()) and type(runtime_source) is CIRuntimeSource,
              'ci_authority.descriptor_source')
    runtime_source.require_parent(parent, prepared)
    session = p.sha(('integrated:'+plan.markers['ocv.session']).encode('ascii'))[:32]
    now = io.utc(); remaining = math.floor(parent.expires-io.monotonic())-2
    p.require(remaining > 1501, 'ci_authority.insufficient_whole_window')
    end = now+dt.timedelta(seconds=remaining)
    owner = {'vmId': integrated_fixture.VM_ID, 'bootId': plan.boot_id, 'sessionId': session,
        'unitName': 'ocv-'+session+'.service',
        'guestSourceSha256': source_binding['sourceClosureSha256'],
        'providerStopAt': p.stamp(end-dt.timedelta(seconds=600)),
        'executionDeadlineUtc': p.stamp(end)}
    root, rows, values = _physical_bundle(owner,
        {'sourceManifestSha256': source_binding['sourceManifestSha256']})
    code = {name: values['code/'+name] for name in guest_storage.CODE_NAMES}
    public = runtime_source.inspect_materials(runtime_source.materials)
    runtime = guest_storage.runtime_manifest(public, guest_storage._code_rows(code),
        owner['guestSourceSha256'], profile.DESIGN_PROFILE_SHA)
    entry_sha = next(row['sha256'] for row in public['files'] if row['path'] == 'code/static-entry')
    context = {'schema': worker.CONTEXT_SCHEMA, 'sessionId': session, 'unitName': owner['unitName'],
        'bootId': plan.boot_id, 'vmId': integrated_fixture.VM_ID, 'identityName': 'ocv-'+session[:24],
        'contextNonce': p.sha((session+plan.boot_id).encode('ascii')),
        'workerDeadlineUtc': None, 'maxJobSeconds': 300, 'operation': 'retained-report-only',
        'mountPropagation': 'private', 'sourceSha': worker.SOURCE, 'scannerSha': worker.SCANNER,
        'indexDigest': worker.INDEX, 'privacySha256': worker.REPORT_SHA256,
        'privacyBytes': worker.REPORT_BYTES, 'consumerCode': worker.CONSUMER,
        'profileSha256': profile.DESIGN_PROFILE_SHA, 'entrySha256': entry_sha,
        'workerSha256': p.sha(code['worker.py']), 'runtimeManifestSha256': p.sha(p.canonical(runtime)),
        'inputManifestSha256': None}
    graph = getattr(io, '_integrated_module_graph', None)
    p.require(graph is not None and callable(getattr(graph, 'require_loaded_rows', None)),
              'ci_authority.source_execution_graph_unissued')
    core = graph.require_loaded_rows(root, rows)
    tools = prepared.tools
    channel_record = {'schema': 'ocv.ci-local-channel.v1', 'owner': owner,
        'outerSourceManifestSha256': plan.markers['ocv.source'],
        'sourceManifestSha256': source_binding['sourceManifestSha256'],
        'transportSourceSha256': rows['guest/integrated_guest.py']['sha256']}
    pins = {'contextSha256': p.sha(p.canonical(context)),
        'guestSourceSha256': owner['guestSourceSha256'], 'profileSha256': profile.DESIGN_PROFILE_SHA,
        'workerSha256': context['workerSha256'], 'entrySha256': entry_sha,
        'runtimeManifestSha256': context['runtimeManifestSha256'],
        'contextContractSha256': p.sha(p.canonical(sorted(worker.CONTEXT_KEYS))),
        'transportReceiptSha256': p.sha(p.canonical(channel_record)),
        'macJournalRoot': str(Path(owner_guard.CONTROL_ROOT)/session/'mac-journal'),
        'sourceManifestSha256': source_binding['sourceManifestSha256'],
        'storageTools': {spec['path']: tools[role]['sha256'] for role, spec in
                         integrated_fixture.STORAGE_TOOL_SPECS.items() if role != 'findmnt'},
        'unitTools': {tools[role]['path']: tools[role]['sha256'] for role in
                      ('systemd-run', 'systemctl', 'busctl', 'selinuxenabled')},
        'selinuxToolSha256': tools['selinuxenabled']['sha256'], 'trustedCoreSources': core}
    return owner, context, pins


def issue_session(parent, prepared, owner, context, pins, ios, runtime_source):
    """Actual CI-only owner lease/source bootstrap, after complete grant checks."""
    import guest_bootstrap
    import native_authority
    import owner_guard
    grant = issue_ci_grant(parent, prepared, owner, context, pins, ios, runtime_source)
    bootstrap_issuer = getattr(native_authority, '_issue_bootstrap_from_verified_grant', None)
    operational_issuer = getattr(native_authority, '_issue_operational_from_verified_grant', None)
    p.require(callable(bootstrap_issuer) and callable(operational_issuer),
              'ci_authority.narrow_native_constructors_unavailable')
    bootstrap_cap = bootstrap_issuer(grant, owner, context, pins,
        {'owner_guard': ios['owner_guard']}, runtime_source=runtime_source, channel=grant.channel)
    guard = owner_guard.acquire(bootstrap_cap, ios['owner_guard'])
    root = bootstrap_cap.source_root
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        source_grant = guest_bootstrap.issue_from_outer(bootstrap_cap, fd,
            pins['sourceManifestSha256'], guard, 'ci-native-proof', grant.channel,
            trusted_core={name: sys.modules[name] for name in pins['trustedCoreSources']})
    finally: os.close(fd)
    bootstrap = guest_bootstrap.VerifiedBootstrap(source_grant)
    peer = guest_bootstrap.issue_peer_from_outer(bootstrap, grant.channel)
    cap = operational_issuer(grant, owner, context, pins,
        {role: ios[role] for role in OPERATIONAL_ROLES}, runtime_source,
        bootstrap, guard, channel=grant.channel)
    return cap, bootstrap, peer


if __name__ == '__main__': raise SystemExit('ci_authority_no_native_cli')

"""Source-pinned CI staging entry, before any integrated module is imported.

The genuine bootstrap owns this disposable Linux guest. This entry checks that
capability, reads only source/build rows it authenticated, stages one immutable
source tree with no overwrite or retry, then imports the actual native chain
from that physical tree. Ordinary import and CLI perform no operation.
"""
from __future__ import annotations

import hashlib
import builtins
import importlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types
from types import MappingProxyType

SOURCE = '/opt/ocv/source'
CONTROL = '/opt/ocv/control'
SOURCE_PREFIX = 'integrated/'
SOURCE_BASE = '/var/lib/openclaw-retained-verifier-source'
PUBLIC_MANIFEST = 'PUBLIC-INTEGRATED-SOURCE-MANIFEST.json'
_GRAPH_KEY = object()
_STDLIB = frozenset(getattr(sys, 'stdlib_module_names', ()))


class Refusal(RuntimeError):
    pass


def need(ok, code):
    if not ok: raise Refusal(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def guest_module_names(files):
    need(type(files) is dict, 'integrated_entry.module_mapping')
    return frozenset(name[:-3] for name in files if '/' not in name and
                     re.fullmatch('[a-z][a-z0-9_]*[.]py', name))


def reject_ambient_guest_modules(files):
    # A forged __file__ is not an execution receipt. Every initially occupied
    # guest name is refused, including pure fixture/helper/consumer modules.
    need(all(name not in sys.modules for name in guest_module_names(files)),
         'integrated_entry.ambient_guest_module')


class CheckedGuestModules:
    """One closed, checked-byte execution graph owned by the genuine outer IO."""
    __slots__ = ('_key', '_root', '_sources', '_modules', '_executed', '_outer', '_sealed')
    def __init_subclass__(cls, **_kwargs): raise TypeError('integrated_entry.graph_sealed')
    def __setattr__(self, name, value):
        need(not getattr(self, '_sealed', False), 'integrated_entry.graph_immutable')
        object.__setattr__(self, name, value)
    def __delattr__(self, _name): raise Refusal('integrated_entry.graph_immutable')
    def __init__(self, key, root, files, outer):
        need(key is _GRAPH_KEY and isinstance(root, Path) and type(outer) is dict and
             set(outer) == {'guard', 'issuer', 'native_io'}, 'integrated_entry.graph_unissued')
        reject_ambient_guest_modules(files)
        self._key, self._root = key, root
        self._sources = MappingProxyType({name: files[name+'.py'] for name in guest_module_names(files)})
        self._outer = MappingProxyType(dict(outer)); self._modules, self._executed = {}, {}
        self._sealed = True

    def load(self, name):
        need(self._key is _GRAPH_KEY and name in self._sources, 'integrated_entry.module_unlisted')
        if name in self._modules: return self._modules[name]
        need(name not in sys.modules, 'integrated_entry.module_became_ambient')
        raw = self._sources[name]
        need(type(raw) is bytes and 0 < len(raw) <= 262144, 'integrated_entry.module_cap')
        module = types.ModuleType(name); module.__file__ = str(self._root/'guest'/(name+'.py'))
        module.__package__ = ''; module.__loader__ = self
        self._modules[name] = module; sys.modules[name] = module
        original_import = builtins.__import__
        def checked_import(import_name, globals=None, locals=None, fromlist=(), level=0):
            need(level == 0, 'integrated_entry.relative_import')
            first = import_name.split('.', 1)[0]
            if first in self._sources:
                need(first == import_name, 'integrated_entry.guest_submodule')
                return self.load(first)
            if first in self._outer:
                need(sys.modules.get(first) is self._outer[first], 'integrated_entry.outer_module_changed')
                return self._outer[first]
            need(first in _STDLIB, 'integrated_entry.import_unlisted')
            return original_import(import_name, globals, locals, fromlist, level)
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=checked_import)
        try:
            code = compile(raw, module.__file__, 'exec', dont_inherit=True)
            exec(code, module.__dict__)
            self._executed[name] = (module, sha(raw), len(raw))
        except BaseException:
            self._modules.pop(name, None); self._executed.pop(name, None)
            if sys.modules.get(name) is module: sys.modules.pop(name)
            raise
        return module

    def load_all(self):
        for name in sorted(self._sources): self.load(name)
        need(set(self._executed) == set(self._sources), 'integrated_entry.module_execution_incomplete')
        return MappingProxyType(dict(self._modules))

    def require_loaded_rows(self, root, rows):
        need(self._key is _GRAPH_KEY and root == self._root and type(rows) is dict,
             'integrated_entry.graph_source_changed')
        names = {Path(name).stem for name in rows if name.startswith('guest/') and
                 len(Path(name).parts) == 2 and name.endswith('.py')}
        need(names == set(self._sources) == set(self._executed) == set(self._modules),
             'integrated_entry.graph_roster_changed')
        result = {}
        for name in sorted(names):
            module, digest, size = self._executed[name]; relative = 'guest/'+name+'.py'
            row = rows[relative]
            need(module is self._modules[name] is sys.modules.get(name) and
                 module.__loader__ is self and module.__file__ == str(root/relative) and
                 sha(self._sources[name]) == digest == row['sha256'] and size == row['bytes'],
                 'integrated_entry.module_execution_changed')
            result[name] = {key: row[key] for key in ('path', 'bytes', 'sha256')}
        return result


def _parent(parent, prepared):
    need(sys.platform == 'linux' and os.geteuid() == os.getegid() == 0,
         'integrated_entry.linux_root_required')
    import guard
    import issuer
    import native_io
    need(type(parent) is issuer.NativeCapability and parent.seal is issuer._SEAL and
         type(prepared) is issuer.Prepared and prepared._seal is issuer._PREPARED_SEAL and
         prepared.io is parent.io and prepared.plan is parent.plan and
         type(parent.io) is native_io.NativeEvidenceIO and type(parent.plan) is guard.Plan and
         parent.plan._seal is guard._PLAN_SEAL and parent.plan._verified_io is parent.io and
         prepared.compatibility is not None and type(prepared.compatibility) is issuer.Compatibility and
         prepared.compatibility._seal is issuer._COMPATIBILITY_SEAL and
         prepared.compatibility.io is parent.io and prepared.compatibility.plan is parent.plan,
         'integrated_entry.genuine_bootstrap_required')
    parent.check()
    for filename, digest, expected in ((SOURCE+'/PUBLIC-SOURCE-MANIFEST.json',
            parent.plan.markers['ocv.source'], parent.plan.source),
            (CONTROL+'/build.json', parent.plan.markers['ocv.build'], parent.plan.build)):
        record = parent.io.file(filename, 1048576)
        need(record.get('regular') is True and record.get('uid') == record.get('gid') == 0 and
             record.get('mode') == 0o444 and sha(record['raw']) == digest and
             guard.decode(record['raw'], 1048576) == expected, 'integrated_entry.parent_pin')
    need(parent.plan.build['fixtureOnly'] is True and parent.plan.build['candidateImage'] is False,
         'integrated_entry.synthetic_only')
    return guard


def _source(parent, relative, cap=262144):
    matches = [row for row in parent.plan.source['files'] if row['path'] == relative]
    need(len(matches) == 1, 'integrated_entry.source_unlisted')
    row = matches[0]
    record = parent.io.file(SOURCE+'/'+relative, cap)
    need(record.get('regular') is True and record.get('uid') == record.get('gid') == 0 and
         record.get('mode') == 0o444 and record.get('canonicalPath') == SOURCE+'/'+relative and
         type(record.get('raw')) is bytes and len(record['raw']) == row['bytes'] <= cap and
         sha(record['raw']) == row['sha256'], 'integrated_entry.source_changed')
    return record['raw']


def _materials(parent, prepared, helper, guard):
    aliases, tools = guard.validate_runtime(parent.io, parent.plan)
    need(all(prepared.aliases.get(seed) == row for seed, row in aliases.items()) and
         prepared.tools == tools, 'integrated_entry.prepared_alias_changed')
    rows, payloads = [], {}
    for seed, row in sorted(aliases.items()):
        name = row['path']; record = parent.io.file(row['sourcePath'], 32*1024*1024)
        raw = record['raw']
        need(seed == '/seed/'+name and name not in payloads and type(raw) is bytes and
             len(raw) == row['bytes'] and sha(raw) == row['sha256'],
             'integrated_entry.runtime_changed')
        payloads[name] = raw
        rows.append({'path': name, 'archivePath': 'static-entry' if name == 'code/static-entry'
            else 'runtime/'+name, 'bytes': len(raw), 'sha256': sha(raw), 'mode': row['mode']})
    plan = parent.plan; run = plan.build['runIdentity']
    origin = {'schema': 'ocv.current-authenticated-bootstrap-origin.v1',
        'sourceCommit': run['sourceCommit'], 'runId': run['runId'],
        'sourceManifestSha256': plan.markers['ocv.source'], 'bootId': plan.boot_id,
        'runtimeControlSha256': plan.control_hashes['runtime'],
        'toolControlSha256': plan.control_hashes['tools'],
        'metadataProofSha256': sha(canonical(prepared.metadataProof)),
        'compatibilitySha256': sha(prepared.compatibility.raw),
        'qualificationProofComplete': False, 'nativeAuthorityFromReceipt': False}
    return helper.current_runtime_materials(rows, payloads, origin)[0]


def _directory(path, *, create=False):
    need(path.is_absolute() and path.resolve() == path, 'integrated_entry.directory_path')
    if create: os.mkdir(path, 0o700)
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
         stat.S_IMODE(info.st_mode) == 0o700 and info.st_dev == os.stat('/').st_dev,
         'integrated_entry.directory_identity')


def _stage(files, binding, helper):
    need(type(binding) is dict and re.fullmatch('[0-9a-f]{64}', binding['sourceClosureSha256']) and
         type(files) is dict, 'integrated_entry.stage_binding')
    base = Path(SOURCE_BASE)
    parent = base.parent; info = parent.lstat()
    need(parent == Path('/var/lib') and stat.S_ISDIR(info.st_mode) and
         info.st_uid == info.st_gid == 0 and not stat.S_IMODE(info.st_mode) & 0o022 and
         parent.resolve() == parent, 'integrated_entry.stage_parent')
    try: _directory(base, create=True)
    except FileExistsError: _directory(base)
    root = base/binding['sourceClosureSha256']
    _directory(root, create=True)  # Existing or partial publication never overwritten.
    for name, raw in sorted(files.items()):
        helper.path(name)
        path = root/name
        current = root
        for part in Path(name).parts[:-1]:
            current /= part
            try: _directory(current, create=True)
            except FileExistsError: _directory(current)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            view = memoryview(raw)
            while view:
                count = os.write(fd, view); need(count > 0, 'integrated_entry.short_write')
                view = view[count:]
            os.fchmod(fd, 0o444); os.fsync(fd)
            observed = os.fstat(fd)
            need(stat.S_ISREG(observed.st_mode) and observed.st_uid == observed.st_gid == 0 and
                 observed.st_nlink == 1 and observed.st_size == len(raw),
                 'integrated_entry.leaf_identity')
        finally: os.close(fd)
        parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(parent_fd)
        finally: os.close(parent_fd)
    return root


def run(parent, prepared):
    guard = _parent(parent, prepared)
    need(not hasattr(parent.io, '_integrated_entry_intent'), 'integrated_entry.attempt_consumed')
    parent.io._integrated_entry_intent = True
    raw = _source(parent, SOURCE_PREFIX+'integrated_materials.py')
    helper = types.ModuleType('_ocv_integrated_material_builder')
    helper.__file__ = SOURCE+'/'+SOURCE_PREFIX+'integrated_materials.py'
    exec(compile(raw, helper.__file__, 'exec'), helper.__dict__)
    manifest_raw = _source(parent, SOURCE_PREFIX+PUBLIC_MANIFEST, 65536)
    manifest = guard.decode(manifest_raw, 65536)
    need(type(manifest) is dict and manifest.get('schema') == 'ocv.integrated-public-sources.v1' and
         manifest.get('fixtureOnly') is True and manifest.get('candidateImage') is False and
         manifest.get('privateVmAdmission') is False and type(manifest.get('files')) is list,
         'integrated_entry.manifest_schema')
    exported = {PUBLIC_MANIFEST: manifest_raw}
    for row in manifest['files']:
        name = helper.path(row['path'])
        need(name not in exported and row['mode'] == 0o444, 'integrated_entry.source_roster')
        value = _source(parent, SOURCE_PREFIX+name)
        need(len(value) == row['bytes'] and sha(value) == row['sha256'],
             'integrated_entry.exported_source_pin')
        exported[name] = value
    materials = _materials(parent, prepared, helper, guard)
    files, binding = helper.bundle_payloads(exported, materials)
    root = _stage(files, binding, helper)
    guest = root/'guest'
    # The controlled graph compiles the checked cached bytes, not whatever an
    # ambient import finder happens to supply or an object's __file__ claims.
    graph = CheckedGuestModules(_GRAPH_KEY, root, exported,
        {name: sys.modules[name] for name in ('guard', 'issuer', 'native_io')})
    parent.io._integrated_module_graph = graph
    loaded = graph.load_all()
    ci, native, storage, unit, owner, integrated = (loaded[name] for name in
        ('ci_authority', 'native_authority', 'guest_storage', 'guest_unit', 'owner_guard', 'integrated_guest'))
    storage_io, unit_io = storage.NativeStorageIO(), unit.NativeUnitIO()
    transport, owner_io = integrated.LocalGuestTransport(), owner.NativeOwnerGuardIO()
    runtime = ci.current_runtime_source(parent, prepared, storage_io)
    need(runtime.materials == materials, 'integrated_entry.rebuilt_material_binding')
    parent.io._integrated_device_appearance = ci.wait_for_device_appearance(parent, prepared)
    owner_record, context, pins = ci.session_descriptor(parent, prepared, binding, runtime)
    ports = {'storage': storage_io, 'unit': unit_io, 'mac': transport, 'owner_guard': owner_io}
    cap, bootstrap, peer = native.issue_ci_native(parent, prepared, owner_record, context, pins, ports, runtime)
    run_identity = parent.plan.build['runIdentity']
    identity = {'sessionId': cap.owner['sessionId'], 'bootId': parent.plan.boot_id,
        'sourceManifestSha256': parent.plan.markers['ocv.source'],
        'sourceCommit': run_identity['sourceCommit'], 'runId': run_identity['runId'],
        'runAttempt': run_identity['runAttempt']}
    return integrated.run_bound(parent, prepared, cap, bootstrap, peer,
        storage_io, unit_io, transport, identity=identity)


if __name__ == '__main__': raise SystemExit('integrated_entry_requires_genuine_bootstrap')

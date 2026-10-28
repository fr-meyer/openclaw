"""Read-once guest source bootstrap. No source or peer authority on import.

The outer, independently verified owner must issue the grant from an already
opened source-directory descriptor and a reviewed manifest digest. A guest
cannot certify its own complete source bundle by hashing itself after import.
"""
from __future__ import annotations

import builtins
import json
import os
import re
import stat
import sys
import types
from types import MappingProxyType
from pathlib import Path

import native_authority
from protocol import Refusal, canonical, decode, require, sha

_KEY = object()
MAX_FILES = 128
MAX_TOTAL = 64 * 1024 * 1024
MAX_LEAF = 32 * 1024 * 1024
MAX_MANIFEST = 16384
MANIFEST_NAME = 'SOURCE-MANIFEST.private.json'
MODULE_PREFIX = 'guest/'
PURPOSES = frozenset(('private-owned-ssh', 'ci-native-proof', 'synthetic-contract'))
_HEX = re.compile(r'[0-9a-f]{64}\Z')
_PART = re.compile(r'[A-Za-z0-9_+.-]{1,96}\Z')
_STDLIB = getattr(sys, 'stdlib_module_names', frozenset((
    '__future__','base64','binascii','builtins','copy','datetime','errno','fcntl','hashlib',
    'io','json','math','os','pathlib','re','selectors','signal','stat',
    'struct','subprocess','sys','tarfile','time','types','uuid')))


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            info.st_gid, info.st_nlink, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns)


def _part(name):
    require(type(name) is str and _PART.fullmatch(name) is not None and
            name not in ('.', '..'), 'bootstrap.path')


def _path(name):
    require(type(name) is str and 0 < len(name) <= 512 and
            not name.startswith('/') and '\\' not in name, 'bootstrap.path')
    parts = name.split('/')
    require(len(parts) <= 8, 'bootstrap.path_depth')
    for part in parts: _part(part)
    return parts


def _read_at(root_fd, path, limit, uid, mode=0o444):
    parts = _path(path)
    parent = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent)
            os.close(parent); parent = child
            info = os.fstat(parent)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and
                    stat.S_IMODE(info.st_mode) == 0o700,
                    'bootstrap.directory_identity')
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=parent)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == uid and
                    before.st_nlink == 1 and before.st_size <= limit and
                    stat.S_IMODE(before.st_mode) == mode,
                    'bootstrap.file_identity')
            chunks, count = [], 0
            while True:
                raw = os.read(fd, min(65536, limit + 1 - count))
                if not raw: break
                chunks.append(raw); count += len(raw)
                require(count <= limit, 'bootstrap.file_cap')
            after = os.fstat(fd)
            require(_identity(before) == _identity(after) and count == before.st_size,
                    'bootstrap.file_changed')
            return b''.join(chunks)
        finally: os.close(fd)
    except OSError:
        raise Refusal('bootstrap.file_unavailable') from None
    finally: os.close(parent)


def _roster(root_fd, uid):
    """Enumerate the pinned tree, including directories, without following links."""
    files, directories = set(), set()
    def walk(fd, prefix, depth):
        require(depth <= 8 and len(directories) <= MAX_FILES,
                'bootstrap.roster_cap')
        try: names = os.listdir(fd)
        except OSError: raise Refusal('bootstrap.roster_unavailable') from None
        require(len(names) <= MAX_FILES + 16, 'bootstrap.roster_cap')
        for name in names:
            _part(name)
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            relative = prefix + name
            require(info.st_uid == uid, 'bootstrap.roster_owner')
            if stat.S_ISDIR(info.st_mode):
                require(stat.S_IMODE(info.st_mode) == 0o700,
                        'bootstrap.roster_directory')
                directories.add(relative)
                require(len(directories) <= MAX_FILES, 'bootstrap.roster_cap')
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=fd)
                try: walk(child, relative + '/', depth+1)
                finally: os.close(child)
            else:
                require(stat.S_ISREG(info.st_mode), 'bootstrap.roster_special')
                files.add(relative)
                require(len(files) <= MAX_FILES + 1, 'bootstrap.roster_cap')
    walk(root_fd, '', 0)
    return files, directories


class GuestSourceGrant:
    __slots__ = ('_key', '_cap', '_owner_raw', '_purpose', '_fd', '_manifest_sha',
                 '_uid', '_channel_receipt', '_used', '_source_path', '_core',
                 '_owner_guard')
    def __setattr__(self, name, value):
        require(not hasattr(self,name) or (name == '_used' and value is True and
                getattr(self,'_used',None) is False), 'bootstrap.grant_immutable')
        object.__setattr__(self,name,value)
    def __delattr__(self, _name):
        raise Refusal('bootstrap.grant_immutable')
    def __init__(self, key, cap, purpose, fd, manifest_sha, uid,
                 channel_receipt, source_path, core, owner_guard):
        require(key is _KEY, 'bootstrap.grant_unissued')
        require(type(purpose) is str and purpose in PURPOSES and
                type(fd) is int and fd >= 0 and type(uid) is int and uid >= 0 and
                type(manifest_sha) is str and _HEX.fullmatch(manifest_sha) is not None,
                'bootstrap.grant_schema')
        self._key, self._cap = key, cap
        self._owner_raw = canonical(cap.owner)
        self._purpose, self._fd = purpose, os.dup(fd)
        self._manifest_sha, self._uid = manifest_sha, uid
        self._channel_receipt, self._used = channel_receipt, False
        self._source_path = Path(source_path)
        require(self._source_path.is_absolute() and
                self._source_path.resolve() == self._source_path,
                'bootstrap.source_path')
        try:
            path_fd = os.open(self._source_path,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try: require(os.fstat(path_fd).st_dev == os.fstat(self._fd).st_dev and
                         os.fstat(path_fd).st_ino == os.fstat(self._fd).st_ino,
                         'bootstrap.source_fd_path_join')
            finally: os.close(path_fd)
        except OSError:
            raise Refusal('bootstrap.source_path_unavailable') from None
        require(type(core) is dict and all(type(k) is str and
                type(v) is types.ModuleType for k,v in core.items()),
                'bootstrap.core_schema')
        self._core = MappingProxyType(dict(core))
        self._owner_guard = owner_guard


def issue_from_outer(cap, source_dir_fd, manifest_sha256, owner_guard,
                     purpose, channel_receipt, *, trusted_core):
    """Native factory: requires the separately issued actual VM-owner guard."""
    require(purpose in ('private-owned-ssh', 'ci-native-proof') and
            cap.kind == {'private-owned-ssh': 'private-bootstrap',
                         'ci-native-proof': 'ci-bootstrap'}[purpose],
            'bootstrap.native_purpose')
    guard = getattr(native_authority, 'require_owner_guard', None)
    require(callable(guard), 'bootstrap.owner_guard_unissued')
    guard(cap, owner_guard)
    require(type(cap.pins.get('sourceManifestSha256')) is str and
            manifest_sha256 == cap.pins['sourceManifestSha256'],
            'bootstrap.manifest_capability_pin')
    require(type(channel_receipt) is not dict and channel_receipt is not None,
            'bootstrap.channel_unissued')
    core_check = getattr(native_authority,'require_verified_core',None)
    require(callable(core_check), 'bootstrap.core_issuer_unissued')
    core_check(cap,trusted_core)
    return GuestSourceGrant(_KEY, cap, purpose, source_dir_fd,
                            manifest_sha256, 0, channel_receipt,
                            cap.source_root, trusted_core, owner_guard)


def synthetic_grant_for_test(cap, source_dir_fd, manifest_sha256,
                             source_path, trusted_core=None):
    """Explicitly synthetic; cannot be upgraded to native or issue a peer."""
    require(cap.kind == 'synthetic-contract', 'bootstrap.synthetic_only')
    return GuestSourceGrant(_KEY, cap, 'synthetic-contract', source_dir_fd,
                            manifest_sha256, os.getuid(), None,
                            source_path, trusted_core or {}, None)


def require_verified_guest_source(grant, owner, purpose):
    require(type(grant) is GuestSourceGrant and grant._key is _KEY and
            grant._owner_raw == canonical(owner) and grant._purpose == purpose and
            not grant._used, 'bootstrap.source_unissued')
    return grant


class VerifiedBootstrap:
    __slots__ = ('_key', '_grant', '_source', '_modules', '_manifest_sha',
                 '_bundle_sha', '_sealed', '_source_fd', '_source_identity')
    def __setattr__(self, name, value):
        require(not getattr(self, '_sealed', False), 'bootstrap.immutable')
        object.__setattr__(self, name, value)
    def __delattr__(self, _name):
        raise Refusal('bootstrap.immutable')
    def __init__(self, grant):
        require_verified_guest_source(grant, grant._cap.owner, grant._purpose)
        root = os.fstat(grant._fd)
        require(stat.S_ISDIR(root.st_mode) and root.st_uid == grant._uid and
                stat.S_IMODE(root.st_mode) == 0o700,
                'bootstrap.root_identity')
        manifest_raw = _read_at(grant._fd, MANIFEST_NAME, MAX_MANIFEST, grant._uid)
        require(sha(manifest_raw) == grant._manifest_sha,
                'bootstrap.manifest_pin')
        manifest = decode(manifest_raw, MAX_MANIFEST)
        require(canonical(manifest) == manifest_raw,
                'bootstrap.manifest_canonical')
        require(type(manifest) is dict and set(manifest) ==
                {'schema', 'files', 'sourceClosureSha256'} and
                manifest['schema'] == 'openclaw.native-guest-source-bundle.v1' and
                type(manifest['files']) is list and 1 <= len(manifest['files']) <= MAX_FILES and
                type(manifest['sourceClosureSha256']) is str and
                _HEX.fullmatch(manifest['sourceClosureSha256']) is not None,
                'bootstrap.manifest_schema')
        rows, source, total = [], {}, 0
        for row in manifest['files']:
            require(type(row) is dict and set(row) ==
                    {'path', 'bytes', 'sha256', 'mode'} and
                    type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_LEAF and
                    type(row['mode']) is int and row['mode'] == 0o444 and
                    type(row['sha256']) is str and _HEX.fullmatch(row['sha256']) is not None,
                    'bootstrap.row_schema')
            path = row['path']; _path(path)
            require(path not in source and path != MANIFEST_NAME,
                    'bootstrap.duplicate_leaf')
            total += row['bytes']
            require(total <= MAX_TOTAL, 'bootstrap.total_cap')
            raw = _read_at(grant._fd, path, row['bytes'], grant._uid,row['mode'])
            require(len(raw) == row['bytes'] and sha(raw) == row['sha256'],
                    'bootstrap.leaf_pin')
            source[path] = raw
            rows.append(dict(row))
        expected_dirs = {'/'.join(path.split('/')[:index])
                         for path in source
                         for index in range(1,len(path.split('/')))}
        files, dirs = _roster(grant._fd, grant._uid)
        require([r['path'] for r in rows] == sorted(source) and
                sha(canonical(rows)) == manifest['sourceClosureSha256'] and
                files == set(source) | {MANIFEST_NAME} and
                dirs == expected_dirs,
                'bootstrap.closed_roster')
        require(grant._cap.owner['guestSourceSha256'] ==
                manifest['sourceClosureSha256'], 'bootstrap.owner_source_join')
        self._source_fd = os.dup(grant._fd)
        self._source_identity = (root.st_dev,root.st_ino)
        object.__setattr__(grant, '_used', True)
        os.close(grant._fd)
        self._key, self._grant = _KEY, grant
        self._source = MappingProxyType(source)
        self._modules = dict(grant._core)
        self._manifest_sha = sha(manifest_raw)
        self._bundle_sha = manifest['sourceClosureSha256']
        self._sealed = True

    @property
    def purpose(self): return self._grant._purpose
    @property
    def owner(self): return json.loads(self._grant._owner_raw)
    @property
    def manifest_sha256(self): return self._manifest_sha
    @property
    def bundle_sha256(self): return self._bundle_sha
    @property
    def owner_guard(self): return self._grant._owner_guard
    def bytes_for(self, path):
        _path(path)
        require(path in self._source, 'bootstrap.unlisted_leaf')
        return self._source[path]

    def assert_source_path(self):
        try:
            fd = os.open(self._grant._source_path,
                         os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:
                live=os.fstat(fd)
                held=os.fstat(self._source_fd)
                require((live.st_dev,live.st_ino)==self._source_identity==
                        (held.st_dev,held.st_ino),
                        'bootstrap.source_path_changed')
            finally:os.close(fd)
        except OSError:
            raise Refusal('bootstrap.source_path_unavailable') from None

    def module(self, name):
        """Execute only cached, verified Python bytes, with local imports pinned."""
        self.assert_source_path()
        require(type(name) is str and re.fullmatch('[a-z][a-z0-9_]*', name),
                'bootstrap.module_name')
        path = MODULE_PREFIX + name + '.py'
        require(path in self._source, 'bootstrap.module_unlisted')
        if name in self._modules: return self._modules[name]
        module = types.ModuleType(name)
        module.__file__ = str(self._grant._source_path / path)
        module.__package__ = ''
        self._modules[name] = module
        original_import = builtins.__import__
        def pinned_import(import_name, globals=None, locals=None, fromlist=(), level=0):
            require(level == 0, 'bootstrap.relative_import')
            root_name = import_name.split('.', 1)[0]
            if MODULE_PREFIX + root_name + '.py' in self._source:
                return self.module(root_name)
            require(root_name in _STDLIB,
                    'bootstrap.import_unlisted')
            return original_import(import_name, globals, locals, fromlist, level)
        builtins_map = dict(vars(builtins), __import__=pinned_import)
        module.__dict__['__builtins__'] = builtins_map
        try:
            code = compile(self._source[path], module.__file__, 'exec', dont_inherit=True)
            exec(code, module.__dict__)
        except BaseException:
            self._modules.pop(name, None)
            raise
        return module


class PeerAuthority:
    __slots__ = ('_key', '_bootstrap', '_channel', '_purpose')
    def __setattr__(self, name, value):
        require(not hasattr(self,name), 'bootstrap.peer_immutable')
        object.__setattr__(self,name,value)
    def __delattr__(self, _name):
        raise Refusal('bootstrap.peer_immutable')
    def __init__(self, key, bootstrap, channel):
        require(key is _KEY and type(bootstrap) is VerifiedBootstrap,
                'bootstrap.peer_unissued')
        self._key, self._bootstrap, self._channel = key, bootstrap, channel
        self._purpose = bootstrap.purpose

    def require_for(self, bootstrap, purpose, channel):
        require(self._key is _KEY and self._bootstrap is bootstrap and
                self._purpose == purpose and self._channel is channel,
                'bootstrap.peer_changed')
        return True


def issue_peer_from_outer(bootstrap, channel):
    require(type(bootstrap) is VerifiedBootstrap and
            bootstrap.purpose != 'synthetic-contract',
            'bootstrap.peer_unissued')
    from framed_channel import NativeFramedChannel
    if (bootstrap.purpose == 'private-owned-ssh' or
            type(channel) is NativeFramedChannel):
        require(type(channel) is NativeFramedChannel,
                'bootstrap.private_channel_type')
        receipt = channel.assert_for_bootstrap(bootstrap)
    else:
        # CI's separately reviewed issuer binds its truthful encoded local
        # channel; the native SSH pipe class is never relabelled as CI.
        receipt = channel
    require(receipt is bootstrap._grant._channel_receipt,
            'bootstrap.channel_changed')
    checker = getattr(native_authority, 'require_authenticated_peer_channel', None)
    require(callable(checker), 'bootstrap.peer_issuer_unissued')
    checker(bootstrap._grant._cap, receipt, bootstrap.purpose)
    return PeerAuthority(_KEY, bootstrap, channel)


def synthetic_peer_for_test(bootstrap, channel=None):
    """Only usable with synthetic IO; cannot certify native SSH or CI provenance."""
    require(type(bootstrap) is VerifiedBootstrap and
            bootstrap.purpose == 'synthetic-contract',
            'bootstrap.synthetic_peer_only')
    return PeerAuthority(_KEY, bootstrap, channel)


if __name__ == '__main__':
    raise SystemExit('guest_bootstrap_no_cli')

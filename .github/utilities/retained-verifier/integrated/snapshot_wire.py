"""Ordered, bounded factual snapshot for one private host admission.

The guest collector records every actual read, including repeated reads and
errors. The Mac replays the exact sequence through the pinned probe. This is
an evidence transport, never a worker verdict or an allowlist source.
"""
from __future__ import annotations

import base64
import errno
import os
from pathlib import PurePosixPath
import re
import stat
from types import SimpleNamespace

from protocol import Refusal, canonical, closed, require, sha

MAX_CALLS = 4500
MAX_READ_BYTES = 20 * 1024 * 1024
# Keep the admission transfer below the mission's 4 MiB aggregate private
# diagnostic allowance, leaving room for stdout, stderr and closeout records.
MAX_WIRE_BYTES = 2 * 1024 * 1024
STAT_FIELDS = ('st_mode', 'st_ino', 'st_dev', 'st_nlink', 'st_uid', 'st_gid',
               'st_size', 'st_rdev', 'st_mtime_ns', 'st_ctime_ns')


def _path(value):
    require(type(value) is str and 0 < len(value) <= 1024 and
            value.startswith('/') and '\x00' not in value and '..' not in value.split('/')
            and str(PurePosixPath(value)) == value,
            'snapshot.path')


def _cap(value):
    require(type(value) is int and 0 <= value <= MAX_READ_BYTES, 'snapshot.cap')


class RecordingReader:
    """No OS authority: wraps one separately admitted live reader."""
    def __init__(self, live):
        require(live is not None and all(callable(getattr(live, method, None)) for method in
                                        ('read', 'readlink', 'stat', 'listdir')),
                'snapshot.live_reader')
        self.live = live
        self.calls = []
        self.read_bytes = 0

    def _call(self, method, path, cap=None):
        _path(path)
        if cap is not None: _cap(cap)
        require(len(self.calls) < MAX_CALLS, 'snapshot.call_cap')
        item = {'method': method, 'path': path, 'cap': cap}
        try:
            result = getattr(self.live, method)(path) if cap is None else getattr(self.live, method)(path, cap)
            if method == 'read':
                require(type(result) is bytes and len(result) <= cap, 'snapshot.read_shape')
                self.read_bytes += len(result)
                require(self.read_bytes <= MAX_READ_BYTES, 'snapshot.read_cap')
                item['value'] = base64.b64encode(result).decode('ascii')
            elif method == 'readlink':
                require(type(result) is str and len(result) <= 4096 and '\x00' not in result,
                        'snapshot.link_shape')
                item['value'] = result
            elif method == 'stat':
                row = {name: getattr(result, name) for name in STAT_FIELDS}
                require(all(type(value) is int and value >= 0 for value in row.values()),
                        'snapshot.stat_shape')
                item['value'] = row
            else:
                require(type(result) is list and len(result) <= cap and
                        all(type(name) is str and 0 < len(name) <= 255 and '\x00' not in name
                            for name in result), 'snapshot.list_shape')
                item['value'] = result
            return result
        except OSError as error:
            require(type(error.errno) is int and 0 < error.errno < 4096, 'snapshot.os_error_shape')
            item['error'] = {'errno': error.errno}
            raise
        finally:
            self.calls.append(item)

    def read(self, path, cap): return self._call('read', path, cap)
    def readlink(self, path): return self._call('readlink', path)
    def stat(self, path): return self._call('stat', path)
    def listdir(self, path, cap): return self._call('listdir', path, cap)

    def packet(self, binding):
        require(type(binding) is dict and set(binding) ==
                {'bootId', 'sessionId', 'unitName', 'pid', 'startTimeTicks', 'invocationId',
                 'profileSha256', 'sourceAnchorSha256', 'startedAtUtc', 'finishedAtUtc'},
                'snapshot.binding_schema')
        value = {'schema': 'openclaw.private-host-snapshot.v1', 'binding': binding,
                 'calls': self.calls, 'readBytes': self.read_bytes}
        raw = canonical(value)
        require(len(raw) <= MAX_WIRE_BYTES, 'snapshot.wire_cap')
        return raw


class LiveReader:
    """Fixed Linux host-side fact paths for one already identified worker.

    Construction performs no read or effect. The sole owner must check VM,
    boot, unit and collector namespace before constructing this reader.
    """
    def __init__(self, pid, cgroup_path):
        require(type(pid) is int and 1 < pid <= 4194304 and
                type(cgroup_path) is str and re.fullmatch('/system.slice/ocv-[0-9a-f]{32}\\.service', cgroup_path),
                'snapshot.reader_identity')
        self.pid = pid
        self.cgroup = '/sys/fs/cgroup' + cgroup_path

    def _allowed(self, method, path):
        """Only the exact paths used by the pinned source probe may be read."""
        _path(path)
        base = '/proc/' + str(self.pid)
        suffix = path[len(base)+1:] if path.startswith(base + '/') else None
        if method == 'read':
            if path == '/proc/sys/kernel/random/boot_id' or re.fullmatch(
                    '/proc/[1-9][0-9]*/status', path): return True
            if path in {self.cgroup+'/'+v for v in ('memory.max','memory.swap.max',
                     'pids.max','cpu.max','pids.current')}: return True
            return suffix in {'stat','cgroup','environ','mountinfo','net/dev',
                              'net/route','net/ipv6_route',
                              'task/'+str(self.pid)+'/children',
                              'fdinfo/0','fdinfo/1','fdinfo/2'}
        if method == 'readlink':
            return suffix in {'exe','root','cwd'} | {'ns/'+v for v in
                   ('mnt','net','ipc','pid','user','uts','cgroup')}
        if method == 'stat':
            allowed = {'exe','root','fd/0','fd/1','fd/2'}
            allowed |= {'root'+v for v in ('/','/tmp','/var/tmp','/input','/control',
                       '/run/systemd/incoming','/run','/dev','/dev/mqueue',
                       '/proc','/sys','/code')}
            return suffix in allowed
        if method == 'listdir':
            return path == '/proc' or suffix in {'task','fd','root/tmp',
                   'root/var/tmp','root/run/systemd/incoming'}
        return False

    def _admit(self, method, path):
        require(self._allowed(method, path), 'snapshot.reader_path')

    def read(self, path, cap):
        self._admit('read', path); _cap(cap)
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            chunks, total = [], 0
            while total <= cap:
                block = os.read(fd, min(65536, cap + 1 - total))
                if not block: break
                chunks.append(block); total += len(block)
            require(total <= cap, 'snapshot.live_read_cap')
            return b''.join(chunks)
        finally:
            os.close(fd)

    def readlink(self, path):
        self._admit('readlink', path)
        return os.readlink(path)

    def stat(self, path):
        self._admit('stat', path)
        return os.stat(path)

    def listdir(self, path, cap):
        self._admit('listdir', path); _cap(cap)
        result = []
        with os.scandir(path) as entries:
            for item in entries:
                require(len(result) < cap, 'snapshot.live_list_cap')
                result.append(item.name)
        return result


class ReplayReader:
    def __init__(self, raw, expected_binding):
        require(type(raw) is bytes and len(raw) <= MAX_WIRE_BYTES, 'snapshot.wire_cap')
        from protocol import decode
        value = decode(raw, MAX_WIRE_BYTES)
        require(canonical(value) == raw, 'snapshot.not_canonical')
        closed(value, {'schema', 'binding', 'calls', 'readBytes'}, 'snapshot.schema')
        require(value['schema'] == 'openclaw.private-host-snapshot.v1' and
                value['binding'] == expected_binding and type(value['calls']) is list and
                len(value['calls']) <= MAX_CALLS and type(value['readBytes']) is int and
                0 <= value['readBytes'] <= MAX_READ_BYTES, 'snapshot.binding')
        self.calls = value['calls']
        self.index = 0
        self.read_bytes = 0
        self.raw = raw

    def _call(self, method, path, cap=None):
        _path(path)
        if cap is not None: _cap(cap)
        require(self.index < len(self.calls), 'snapshot.missing_call')
        item = self.calls[self.index]
        self.index += 1
        closed(item, {'method', 'path', 'cap', 'value'} if 'value' in item else
               {'method', 'path', 'cap', 'error'}, 'snapshot.call_schema')
        require(item['method'] == method and item['path'] == path and item['cap'] == cap,
                'snapshot.call_order')
        if 'error' in item:
            closed(item['error'], {'errno'}, 'snapshot.error_schema')
            number = item['error']['errno']
            require(type(number) is int and 0 < number < 4096, 'snapshot.error_shape')
            raise OSError(number, os.strerror(number))
        result = item['value']
        if method == 'read':
            require(type(result) is str and re.fullmatch('[A-Za-z0-9+/]*={0,2}', result),
                    'snapshot.base64_shape')
            try: result = base64.b64decode(result, validate=True)
            except ValueError: raise Refusal('snapshot.base64_shape') from None
            require(len(result) <= cap, 'snapshot.read_shape')
            self.read_bytes += len(result)
            require(self.read_bytes <= MAX_READ_BYTES, 'snapshot.read_cap')
        elif method == 'readlink':
            require(type(result) is str and len(result) <= 4096 and '\x00' not in result,
                    'snapshot.link_shape')
        elif method == 'stat':
            closed(result, STAT_FIELDS, 'snapshot.stat_shape')
            require(all(type(v) is int and v >= 0 for v in result.values()), 'snapshot.stat_shape')
            result = SimpleNamespace(**result)
        else:
            require(type(result) is list and len(result) <= cap and
                    all(type(name) is str and 0 < len(name) <= 255 and '\x00' not in name
                        for name in result), 'snapshot.list_shape')
        return result

    def read(self, path, cap): return self._call('read', path, cap)
    def readlink(self, path): return self._call('readlink', path)
    def stat(self, path): return self._call('stat', path)
    def listdir(self, path, cap): return self._call('listdir', path, cap)

    def finish(self):
        require(self.index == len(self.calls) and self.read_bytes <= MAX_READ_BYTES,
                'snapshot.unused_or_truncated_calls')
        from protocol import decode
        value = decode(self.raw, MAX_WIRE_BYTES)
        require(self.read_bytes == value['readBytes'], 'snapshot.read_bytes_changed')
        return {'calls': self.index, 'readBytes': self.read_bytes, 'snapshotSha256': sha(self.raw)}

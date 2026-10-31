"""Read-only, source-pinned Linux host observation for one owned verifier.

This module cannot start a unit, mount a disk, release inputs or issue a gate.
An outer, reviewed guest owner must call ``before`` prior to unit submission,
keep this object in the same root/manager namespace, and call ``capture`` after
the exact unit is observed. No CLI or JSON value issues that owner capability.
"""
from __future__ import annotations

import datetime as dt
import builtins
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import selectors
import subprocess
import time
import types

from protocol import Refusal, canonical, read_regular, require, sha, stamp
from snapshot_wire import LiveReader, RecordingReader
import probe
import profile

GENERIC_PINS = {
    'ci_anchors.py': '8658db838fb8ded8550b6c8eae4f74062e0e5cb7e9b0b5b358d08dec0e047689',
    'ci_probe.py': '766472d5d5e724f742ccdb9a76dd689f46aa20771057ed764f43fce0daddf3a3',
    'ci_protocol.py': '03c29e4b17dea1114b7dd4af5fbb91eefd1e9e07bf67c9971f86b70f59c02339',
    'ci_native_port.py': '7fc345b51fa6ecea3dc2c1a46229554c3291b0c5b26ecdb33ff273fb3c72d4b5',
    'ci_profile.py': '9d9b9b90f54ba6fad05c8621329bd0f6c9aae6e0797a3d88ba99f2cfc9f5c804',
    'ci_fixture.py': '7ae1f7e08470235dfe735c4d7ca2633758f65e5842989d635c8446e52cde7818',
}
ROOT_PREFIX = '/var/lib/openclaw-retained-verifier/'
MAX_PATH = 1024
# The existing VM's executable has not been measured through the authorized
# route. A caller-provided digest must never turn an unknown tool into authority.
# Authenticated expected bytes from signed run57 selinux-utils 3.4-1+b6.
# The source-issued observer/catalog join must still prove the actual VM match.
SELINUX_TOOL_SHA256 = '2d3c6a10650d380fde19ed7e5b0d80d6a8a99a3d950c1d7f424237a17d609148'
GENERIC_STDLIB = frozenset(('__future__','datetime','copy','hashlib','json','os',
    'pathlib','selectors','stat','subprocess','time','math','errno','re'))


def _absolute(value):
    require(type(value) is str and 0 < len(value) <= MAX_PATH and
            value.startswith('/') and '\x00' not in value and
            str(PurePosixPath(value)) == value and '..' not in value.split('/'),
            'host.path')
    return value


def source_pins(directory=None):
    """Exact files from the authenticated run41 public-tooling archive."""
    directory = Path(directory) if directory is not None else Path(__file__).resolve().parent / 'attested_generic'
    require(directory.is_dir() and not directory.is_symlink() and directory.resolve() == directory,
            'host.generic_directory')
    for name, digest in GENERIC_PINS.items():
        path = directory / name
        require(path.is_file() and not path.is_symlink() and path.resolve() == path,
                'host.generic_source_pin')
        read_regular(path,131072,expected_sha=digest)
    return directory


def _root_owned_sources(directory):
    """Guest execution requires an immutable root-owned source path chain."""
    current = Path('/')
    for component in Path(directory).parts[1:]:
        current = current / component
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
                not stat.S_IMODE(info.st_mode) & 0o022 and not current.is_symlink(),
                'host.generic_parent_identity')
    for name in GENERIC_PINS:
        info = (Path(directory) / name).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
                info.st_nlink == 1 and not stat.S_IMODE(info.st_mode) & 0o222,
                'host.generic_file_identity')


def load_generic(directory=None):
    """One checked-byte graph, isolated from any ambient same-name CI modules."""
    directory = source_pins(directory)
    names = tuple(name[:-3] for name in GENERIC_PINS)
    sources = {name: read_regular(directory/(name+'.py'),131072,
                    expected_sha=GENERIC_PINS[name+'.py']) for name in names}
    modules = {}
    original_import=builtins.__import__
    def pinned_import(import_name,globals=None,locals=None,fromlist=(),level=0):
        require(level==0,'host.generic_relative_import')
        root_name=import_name.split('.')[0]
        if root_name in sources:return load(root_name)
        require(root_name in GENERIC_STDLIB,'host.generic_import_unlisted')
        return original_import(import_name,globals,locals,fromlist,level)
    def load(name):
        if name in modules:return modules[name]
        require(name in sources,'host.generic_module_unlisted')
        module=types.ModuleType(name)
        module.__file__=str(directory/(name+'.py'));module.__package__=''
        module.__dict__['__builtins__']=dict(vars(builtins),__import__=pinned_import)
        modules[name]=module
        try:exec(compile(sources[name],module.__file__,'exec'),module.__dict__)
        except BaseException:
            modules.pop(name,None);raise
        return module
    for name in names:load(name)
    return modules


PROVIDED_SELINUX_FILES = {
    'usr/sbin/selinuxenabled':(14576,SELINUX_TOOL_SHA256),
    'lib64/ld-linux-x86-64.so.2':(215000,'02bcda52c1a5dfc236f94d9e5255b4a0e26347d8a372a5223b650e31f291ce3c'),
    'lib/x86_64-linux-gnu/libc.so.6':(1926232,'6b4a45352fd0c540a9c7c718f35ce8c8e46a4e482f9d3885a910c32d1a0e1421'),
    'lib/x86_64-linux-gnu/libselinux.so.1':(174312,'0207e4908ea384e186c75925b0e56996a3eccecd48c99252aeb757d0d3451c93'),
    'lib/x86_64-linux-gnu/libpcre2-8.so.0':(629384,'092bc945140e65c691c7c717d71083111f46813f31a76dd848bf82e91450778b')}
PROVIDED_SELINUX_NEEDED = {
    'usr/sbin/selinuxenabled':('libselinux.so.1','libc.so.6'),
    'lib/x86_64-linux-gnu/libselinux.so.1':('libpcre2-8.so.0','libc.so.6','ld-linux-x86-64.so.2'),
    'lib/x86_64-linux-gnu/libpcre2-8.so.0':('libc.so.6',),
    'lib/x86_64-linux-gnu/libc.so.6':('ld-linux-x86-64.so.2',),
    'lib64/ld-linux-x86-64.so.2':()}
PROVIDED_ENV = {'PATH':'/usr/bin','LANG':'C','LC_ALL':'C'}
PROVIDED_SELINUX_MODES = {p:(0o555 if p in ('usr/sbin/selinuxenabled','lib64/ld-linux-x86-64.so.2')else 0o444)for p in PROVIDED_SELINUX_FILES}


def _provided_elf(raw):
    """Passive closed ELF64 graph; no loader execution or interpretation grant."""
    import struct
    require(type(raw)is bytes and len(raw)>=64 and raw[:6]==b'\x7fELF\x02\x01' and
        struct.unpack_from('<H',raw,18)[0]==62,'host.provided_elf')
    start=struct.unpack_from('<Q',raw,32)[0];size,count=struct.unpack_from('<HH',raw,54)
    require(size==56 and count<=256 and start+size*count<=len(raw),'host.provided_elf_headers')
    loads=[];dynamic=None;interpreter=''
    for index in range(count):
        kind,flags,offset,address,physical,files,mem,align=struct.unpack_from('<IIQQQQQQ',raw,start+index*size)
        require(offset+files<=len(raw),'host.provided_elf_segment')
        if kind==1:loads.append((address,files,offset))
        elif kind==2:require(dynamic is None,'host.provided_dynamic_duplicate');dynamic=(offset,files)
        elif kind==3:interpreter=raw[offset:offset+files].rstrip(b'\0').decode('ascii')
    require(dynamic is not None,'host.provided_dynamic_missing')
    offset,size=dynamic;require(size<=65536 and size%16==0,'host.provided_dynamic_cap');tags=[]
    for position in range(offset,offset+size,16):
        tag,value=struct.unpack_from('<qQ',raw,position)
        if tag==0:break
        require(tag not in (15,29,0x7ffffffd,0x7fffffff,0x6ffffefb,0x6ffffefc),
            'host.provided_unreviewed_dynamic_path');tags.append((tag,value))
    strings=[v for t,v in tags if t==5];lengths=[v for t,v in tags if t==10]
    require(len(strings)==len(lengths)==1 and lengths[0]<=1024*1024,'host.provided_strings')
    matches=[o+strings[0]-a for a,n,o in loads if a<=strings[0] and strings[0]+lengths[0]<=a+n]
    require(len(matches)==1,'host.provided_strings_mapping');table=raw[matches[0]:matches[0]+lengths[0]]
    needed=[]
    for tag,index in tags:
        if tag!=1:continue
        require(index<len(table),'host.provided_needed_offset');end=table.find(b'\0',index)
        require(end>=index,'host.provided_needed_termination');name=table[index:end].decode('ascii')
        require(re.fullmatch('[A-Za-z0-9_.+-]{1,64}',name) and name not in needed,'host.provided_needed')
        needed.append(name)
    return tuple(needed),interpreter


class ProvidedSelinuxProbe:
    """Read-only evidence/physical command description, NOT native authority.

    Private callers must additionally hold the source-issued runtime/owner role.
    Linux fixtures may exercise this evidence class without minting that role.
    """
    __slots__=('root','binary','loader','library','_selected','_validation_count','_view','_files','_loader_result','_probe_result')
    def __init__(self,root):
        require(type(root)is str and re.fullmatch('/var/lib/openclaw-retained-bootstrap/[0-9a-f]{64}/[0-9a-f]{32}/root',root),
            'host.provided_root')
        self.root=root;self.binary=root+'/usr/sbin/selinuxenabled'
        self.loader=root+'/lib64/ld-linux-x86-64.so.2';self.library=root+'/lib/x86_64-linux-gnu'
        self._selected=(self.root,self.binary,self.loader,self.library)
        self._validation_count=0
        self._view=self.host_view();self._files=None;self._loader_result=None;self._probe_result=None
        self.validate()
    def argv(self,listing=False):
        require(type(listing)is bool,'host.provided_listing')
        return (self.loader,'--inhibit-cache','--library-path',self.library)+ (('--list',)if listing else ())+(self.binary,)
    @property
    def commands(self):return (self.argv(True),self.argv(False))
    @staticmethod
    def host_view():
        require(sys.platform=='linux' and os.geteuid()==0,'host.provided_host_required')
        names=('mnt','net','ipc','pid','user','uts','cgroup')
        own={n:os.readlink('/proc/self/ns/'+n)for n in names}
        manager={n:os.readlink('/proc/1/ns/'+n)for n in names}
        identity=lambda s:(s.st_dev,s.st_ino)
        require(own==manager and identity(os.stat('/'))==identity(os.stat('/proc/1/root')),
            'host.provided_host_view')
        return {'namespaces':own,'root':identity(os.stat('/'))}
    def read(self,relative):
        require(relative in PROVIDED_SELINUX_FILES,'host.provided_file_scope')
        path=Path(self.root)/relative
        _root_owned_sources_parent(path.parent)
        before=path.lstat();size,digest=PROVIDED_SELINUX_FILES[relative]
        require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and
            before.st_nlink==1 and stat.S_IMODE(before.st_mode)==PROVIDED_SELINUX_MODES[relative] and
            before.st_size==size and before.st_dev==os.stat('/').st_dev and
            (relative not in ('usr/sbin/selinuxenabled','lib64/ld-linux-x86-64.so.2')or
             stat.S_IMODE(before.st_mode)&0o111),'host.provided_file_identity')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            opened=os.fstat(fd);raw=b''
            while len(raw)<=size:
                block=os.read(fd,min(65536,size+1-len(raw)))
                if not block:break
                raw+=block
            after=os.fstat(fd)
        finally:os.close(fd)
        key=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        require(key(before)==key(opened)==key(after)==key(path.lstat())and len(raw)==size and sha(raw)==digest,
            'host.provided_file_changed')
        return raw,{k:int(getattr(before,k))for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
    def validate(self):
        require((self.root,self.binary,self.loader,self.library)==self._selected,'host.provided_path_changed')
        require(self._validation_count<32,'host.provided_validation_budget');self._validation_count+=1
        require(self.host_view()==self._view,'host.provided_view_changed')
        require(not os.path.lexists('/etc/ld.so.preload') and
            not any(k.startswith('LD_')or k in ('GLIBC_TUNABLES','SELINUX_PATH','SELINUX_DEBUG')for k in os.environ),
            'host.provided_loader_environment')
        require(not os.path.lexists(self.library+'/glibc-hwcaps')and
            not os.path.lexists(self.root+'/lib64/glibc-hwcaps'),'host.provided_hwcaps')
        rows={}
        for name in PROVIDED_SELINUX_FILES:
            raw,identity=self.read(name);needed,interpreter=_provided_elf(raw)
            require(needed==PROVIDED_SELINUX_NEEDED[name] and
                interpreter==('/lib64/ld-linux-x86-64.so.2'if name in ('usr/sbin/selinuxenabled','lib/x86_64-linux-gnu/libc.so.6')else ''),
                'host.provided_elf_closure');rows[name]=identity
        if self._files is not None:require(rows==self._files,'host.provided_identity_changed')
        self._files=rows;return True
    def loader_result(self,result):
        require(self._loader_result is None,'host.provided_loader_replayed');self.validate()
        require(_capture_ok(result)and type(result['exitCode'])is int and result['exitCode']==0 and result['stderr']==b'',
            'host.provided_loader_capture')
        text=result['stdout'].decode('ascii');rows={};vdso=0
        for line in text.splitlines():
            line=line.strip()
            if re.fullmatch(r'linux-vdso\.so\.1 \(0x[0-9a-f]+\)',line):vdso+=1;continue
            match=re.fullmatch(r'([A-Za-z0-9_.+-]+) => (/[^\s]+) \(0x[0-9a-f]+\)',line)
            if match:name,path=match.groups()
            elif line.startswith('/lib64/ld-linux-x86-64.so.2 => '):
                match=re.fullmatch(r'/lib64/ld-linux-x86-64.so.2 => (/[^\s]+) \(0x[0-9a-f]+\)',line)
                require(match is not None,'host.provided_loader_alias');name,path='@loader',match.group(1)
            else:
                match=re.fullmatch(r'(/[^\s]+) \(0x[0-9a-f]+\)',line)
                require(match is not None,'host.provided_loader_row');name,path='@loader',match.group(1)
            if name=='ld-linux-x86-64.so.2':name='@loader'
            require(name not in rows,'host.provided_loader_duplicate');rows[name]=path
        require(vdso==1 and rows=={'libselinux.so.1':self.library+'/libselinux.so.1',
            'libpcre2-8.so.0':self.library+'/libpcre2-8.so.0','libc.so.6':self.library+'/libc.so.6',
            '@loader':self.loader},'host.provided_loader_resolution')
        self._loader_result=result;return True
    def probe_result(self,result):
        require(self._loader_result is not None and self._probe_result is None,'host.provided_probe_order');self.validate()
        require(_capture_ok(result)and type(result['exitCode'])is int and result['exitCode']in(0,1)and
            result['stdout']==result['stderr']==b'',
            'host.provided_probe_capture');self._probe_result=result;return True


def _root_owned_sources_parent(path):
    require(path.is_absolute()and path.resolve()==path,'host.provided_parent')
    for item in (*reversed(path.parents),path):
        info=item.lstat();require(stat.S_ISDIR(info.st_mode)and info.st_uid==info.st_gid==0 and
            not stat.S_IMODE(info.st_mode)&0o022,'host.provided_parent')


def _capture_ok(result):
    return (type(result)is dict and result.get('captureComplete')is True and
        result.get('streamsEOF')is True and result.get('streamsClosed')is True and
        result.get('ownedChildExited')is True and result.get('ownershipRetained')is False and
        result.get('refusalCode')is None and result.get('timedOut')is False and
        type(result.get('stdout'))is bytes and type(result.get('stderr'))is bytes and
        all(type(result.get(k+'Facts'))is dict and result[k+'Facts'].get('truncated')is False and
            result[k+'Facts'].get('complete')is True and result[k+'Facts'].get('bytes')==len(result[k])and
            result[k+'Facts'].get('sha256')==sha(result[k])for k in('stdout','stderr')))


class HostOps:
    """Actual Linux reads constrained to the one root and anchor paths."""
    def __init__(self, session_root, unit, *, provided_selinux=None):
        require(type(session_root) is str and re.fullmatch(ROOT_PREFIX + '[0-9a-f]{32}', session_root)
                and type(unit) is str and unit == 'ocv-' + session_root[-32:] + '.service',
                'host.session_root')
        self.root, self.unit = session_root, unit
        self.incoming = '/run/systemd/propagate/' + unit
        self.command_port = None
        self.provided_selinux=provided_selinux
        if provided_selinux is not None:
            require(type(provided_selinux)is ProvidedSelinuxProbe,'host.provided_evidence_type')
            provided_selinux.validate()

    def _within(self, path):
        _absolute(path)
        return path == self.root or path.startswith(self.root + '/')

    def _anchor(self, path):
        _absolute(path)
        return (path in ('/', '/tmp', '/var', '/var/tmp', '/var/lib',
                         '/var/lib/openclaw-retained-verifier', '/run', '/run/systemd',
                         '/run/systemd/propagate', '/dev', '/dev/null') or
                path == self.incoming or path.startswith('/tmp/systemd-private-') or
                path.startswith('/var/tmp/systemd-private-') or self._within(path))

    def lstat(self, path):
        require(self._anchor(path), 'host.anchor_path')
        return os.lstat(path)

    def listdir(self, path, cap):
        require(path in ('/tmp', '/var/tmp', self.incoming) and
                type(cap) is int and 0 <= cap <= 4096, 'host.listdir_path')
        rows = []
        with os.scandir(path) as entries:
            for entry in entries:
                require(len(rows) < cap, 'host.listdir_cap')
                rows.append(entry.name)
        return rows

    def readlink(self, path):
        require(path in ('/proc/1/ns/mnt', '/proc/1/ns/user') or
                re.fullmatch('/proc/self/ns/(?:mnt|net|ipc|pid|user|uts|cgroup)', path),
                'host.namespace_path')
        return os.readlink(path)

    def read(self, path, cap):
        require(not(self.provided_selinux is not None and path=='/usr/sbin/selinuxenabled'),'host.provided_no_legacy_fallback')
        if self.provided_selinux is not None and path==self.provided_selinux.binary:
            self.provided_selinux.validate()
            value,_=self.provided_selinux.read('usr/sbin/selinuxenabled')
            require(len(value)<=cap,'host.provided_read_cap');return value
        require(path in ('/proc/self/mountinfo', '/proc/sys/kernel/random/boot_id',
                         '/usr/sbin/selinuxenabled') or
                re.fullmatch('/proc/[1-9][0-9]*/(?:status|stat)', path) or
                path in ('/etc/passwd', '/etc/group'), 'host.read_path')
        require(type(cap) is int and 0 <= cap <= 1048576, 'host.read_cap')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            chunks, total = [], 0
            while total <= cap:
                block = os.read(fd, min(65536, cap + 1 - total))
                if not block: break
                chunks.append(block); total += len(block)
            require(total <= cap, 'host.read_oversize')
            return b''.join(chunks)
        finally:
            os.close(fd)

    def command(self, argv, timeout):
        require(not(self.provided_selinux is not None and argv==('/usr/sbin/selinuxenabled',)),'host.provided_no_legacy_fallback')
        if self.provided_selinux is not None and argv in self.provided_selinux.commands:
            require(timeout==5,'host.provided_command_time');self.provided_selinux.validate()
            require(self.command_port is not None,'host.command_unissued')
            result=self.command_port.command(argv,timeout)
            if argv==self.provided_selinux.argv(True):self.provided_selinux.loader_result(result)
            else:self.provided_selinux.probe_result(result)
            return result
        require(type(argv) is tuple and type(timeout) is int and timeout == 5 and
                (argv == ('/usr/sbin/selinuxenabled',) or
                 (len(argv) == 8 and argv[:4] ==
                  ('/usr/bin/busctl', '--system', '--json=short', 'get-property') and
                  argv[4] == 'org.freedesktop.systemd1' and
                  argv[5] == '/org/freedesktop/systemd1/unit/' +
                  ''.join(c if c.isascii() and c.isalnum() else '_'+format(ord(c),'02x')
                          for c in self.unit) and
                  argv[6] in ('org.freedesktop.systemd1.Service',
                              'org.freedesktop.systemd1.Unit') and
                  argv[7] in {'DynamicUser', 'User', 'Group', 'MainPID', 'NoNewPrivileges',
                              'PrivateNetwork', 'PrivateIPC', 'CapabilityBoundingSet',
                              'AmbientCapabilities', 'MountFlags', 'InvocationID',
                              'ControlGroup'})), 'host.command_unissued')
        require(self.command_port is not None, 'host.command_unissued')
        return self.command_port.command(argv, timeout)


def _typed(ops, generic, unit, interface, name, kind):
    escaped = ''.join(c if c.isascii() and c.isalnum() else '_'+format(ord(c),'02x')
                      for c in unit)
    argv = ('/usr/bin/busctl', '--system', '--json=short', 'get-property',
            'org.freedesktop.systemd1', '/org/freedesktop/systemd1/unit/'+escaped,
            interface, name)
    outcome = ops.command(argv, 5)
    require(generic['ci_native_port'].command_capture_ok(outcome) and
            outcome.get('exitCode') == 0 and
            all(outcome.get(k, {}).get('truncated') is False for k in
                ('stdoutFacts', 'stderrFacts')), 'host.typed_capture')
    value = generic['ci_protocol'].decode(outcome['stdout'], 16384)
    require(type(value) is dict and set(value) == {'type', 'data'} and
            value['type'] == kind, 'host.typed_schema')
    data = value['data']
    if kind == 'b': require(type(data) is bool, 'host.typed_shape')
    elif kind == 's': require(type(data) is str, 'host.typed_shape')
    elif kind == 'u': require(type(data) is int and 0 <= data < 2**32, 'host.typed_shape')
    elif kind == 't': require(type(data) is int and 0 <= data < 2**64, 'host.typed_shape')
    elif kind == 'ay':
        require(type(data) is list and len(data) == 16 and
                all(type(x) is int and 0 <= x <= 255 for x in data), 'host.typed_shape')
    else: raise Refusal('host.typed_kind')
    return data


class _GuestCommandIO:
    """Exact-child capture primitives for the two read-only command families."""
    def now(self): return time.monotonic()
    def spawn(self, argv):
        return subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env={'PATH': '/usr/bin', 'LANG': 'C', 'LC_ALL': 'C'},
                                close_fds=True)
    def selector(self): return selectors.DefaultSelector()
    def nonblocking(self, stream): os.set_blocking(stream.fileno(), False)
    def register(self, selector, stream, label): selector.register(stream, selectors.EVENT_READ, label)
    def events(self, selector, seconds): return selector.select(seconds)
    def mapped(self, selector): return bool(selector.get_map())
    def read(self, stream): return os.read(stream.fileno(), 65536)
    def unregister(self, selector, stream): selector.unregister(stream)
    def close_selector(self, selector): selector.close()
    def close_stream(self, stream): stream.close()
    def poll(self, child): return child.poll()
    def terminate(self, child): child.terminate()
    def kill(self, child): child.kill()
    def wait(self, child, seconds): return child.wait(timeout=seconds)


class Collector:
    """Keeps the source-anchor object alive across start and capture."""
    def __init__(self, ops, boot_id):
        require(type(ops) is HostOps and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',
                                                     boot_id or ''), 'host.collector_identity')
        require(os.geteuid() == 0, 'host.root_collector_required')
        require(type(SELINUX_TOOL_SHA256) is str and re.fullmatch('[0-9a-f]{64}', SELINUX_TOOL_SHA256),
                'host.selinux_pin_unbound')
        self.ops, self.boot = ops, boot_id
        _root_owned_sources(Path(__file__).resolve().parent / 'attested_generic')
        self.generic = load_generic()
        require(ops.command_port is None, 'host.command_port_already_issued')
        commands=ops.provided_selinux.commands if ops.provided_selinux is not None else ()
        ops.command_port = self.generic['ci_native_port'].CommandCapture(_GuestCommandIO(),readonly_selinux_commands=commands)
        self.sources = self.generic['ci_anchors'].Sources(ops, ops.root, ops.unit, boot_id,
                                                          SELINUX_TOOL_SHA256,
                                                          propagation_policy='private',
                                                          provided_selinux=ops.provided_selinux if ops.provided_selinux is not None else None)
        self.prepared = False
        self.captured = False

    def before(self):
        require(not self.prepared, 'host.before_once')
        self.sources.before()
        self.prepared = True
        return {'managerNamespaces': dict(self.sources.manager),
                'selinuxExitCode': self.sources.selinux_evidence['exitCode'],
                'root': self.ops.root, 'unit': self.ops.unit, 'bootId': self.boot}

    def _unit(self, context, properties_sha):
        service = 'org.freedesktop.systemd1.Service'
        unit_interface = 'org.freedesktop.systemd1.Unit'
        values = {name: _typed(self.ops, self.generic, self.ops.unit, service, name, kind)
                  for name, kind in
                  (('DynamicUser', 'b'), ('User', 's'), ('Group', 's'),
                   ('MainPID', 'u'), ('NoNewPrivileges', 'b'),
                   ('PrivateNetwork', 'b'), ('PrivateIPC', 'b'),
                   ('CapabilityBoundingSet', 't'), ('AmbientCapabilities', 't'),
                   ('MountFlags', 't'))}
        require(values['DynamicUser'] is True and values['NoNewPrivileges'] is True and
                values['PrivateNetwork'] is True and values['PrivateIPC'] is True and
                values['CapabilityBoundingSet'] == values['AmbientCapabilities'] == 0 and
                values['MountFlags'] == 262144 and values['User'] == values['Group'] ==
                context['identityName'], 'host.unit_security_readback')
        pid = values['MainPID']
        require(type(pid) is int and 1 < pid <= 4194304, 'host.unit_pid')
        invocation = _typed(self.ops, self.generic, self.ops.unit,
                            unit_interface, 'InvocationID', 'ay')
        group = _typed(self.ops, self.generic, self.ops.unit,
                       service, 'ControlGroup', 's')
        require(group == '/system.slice/' + self.ops.unit, 'host.unit_cgroup')
        for path in ('/etc/passwd', '/etc/group'):
            require(not any(line.split(':', 1)[0] == context['identityName']
                            for line in self.ops.read(path, 65536).decode('utf-8').splitlines()),
                    'host.static_identity_present')
        status = probe.status(self.ops.read('/proc/' + str(pid) + '/status', 16384).decode(), full=True)
        uid, gid = int(status['Uid'][0]), int(status['Gid'][0])
        generation = probe.proc_stat(self.ops.read('/proc/' + str(pid) + '/stat', 8192).decode(), pid)
        record = {'unitName': self.ops.unit, 'DynamicUser': values['DynamicUser'],
                  'User': values['User'], 'Group': values['Group'],
                  'MainPID': pid, 'UID': uid, 'GID': gid,
                  'InvocationID': bytes(invocation).hex(), 'ControlGroup': group,
                  'propertiesSha256': properties_sha, 'staticNameAbsent': True,
                  'MountFlags': values['MountFlags']}
        return record, generation['startTimeTicks']

    def capture(self, context):
        """Return exact ordered host facts for independent Mac replay.

        Neither a caller-provided unit verdict nor child mount observations
        build the expected roster. Manager D-Bus and source anchors do that.
        """
        require(self.prepared and not self.captured, 'host.capture_sequence')
        self.captured = True
        require(type(context) is dict and context.get('bootId') == self.boot and
                context.get('unitName') == self.ops.unit and
                context.get('sessionId') == self.ops.root[-32:] and
                context.get('identityName') == 'ocv-' + self.ops.root[-32:-8] and
                context.get('mountPropagation') == 'private' and
                context.get('profileSha256') == profile.DESIGN_PROFILE_SHA,
                'host.capture_join')
        require(self.ops.read('/proc/sys/kernel/random/boot_id', 128).strip().decode() == self.boot,
                'host.boot_changed')
        start = dt.datetime.now(dt.timezone.utc)
        template = Path(__file__).resolve().parent / 'PROFILE.template.private.json'
        properties = profile.properties(template.read_bytes(), context['sessionId'], self.ops.root)
        properties_sha = sha(canonical(properties))
        unit, ticks = self._unit(context, properties_sha)
        anchor = self.sources.collect(context)
        self.sources.recheck()
        expected = dict(anchor, schema=probe.EXPECTED_SCHEMA,
                        sessionId=context['sessionId'], bootId=self.boot,
                        pid=unit['MainPID'], startTimeTicks=ticks,
                        unitName=self.ops.unit, identityName=context['identityName'],
                        invocationId=unit['InvocationID'], uid=unit['UID'], gid=unit['GID'],
                        dynamicIdRange=[61184, 65519], cgroupPath=unit['ControlGroup'],
                        hostNamespaces={name: int(self.ops.readlink('/proc/self/ns/'+name).split('[')[1][:-1])
                                        for name in probe.NAMESPACE_NAMES},
                        limits={'memoryMaxBytes': 2147483648, 'memorySwapMaxBytes': 0,
                                'cpuQuota': 100000, 'cpuPeriod': 100000, 'pidsMax': 64},
                        environmentSha256=sha(canonical(probe.ENVIRONMENT)),
                        profileSha256=profile.DESIGN_PROFILE_SHA)
        probe.validate_expected(expected)
        facts = RecordingReader(LiveReader(expected['pid'], expected['cgroupPath']))
        proof = probe.collect_and_validate(facts, expected)
        self.sources.recheck()
        require(self._unit(context, properties_sha) == (unit, ticks) and
                self.ops.read('/proc/sys/kernel/random/boot_id', 128).strip().decode() == self.boot,
                'host.generation_changed')
        finish = dt.datetime.now(dt.timezone.utc)
        require(dt.timedelta(0) <= finish - start <= dt.timedelta(seconds=20),
                'host.capture_time')
        binding = {'bootId': self.boot, 'sessionId': context['sessionId'],
                   'unitName': self.ops.unit, 'pid': expected['pid'],
                   'startTimeTicks': ticks, 'invocationId': unit['InvocationID'],
                   'profileSha256': profile.DESIGN_PROFILE_SHA,
                   'sourceAnchorSha256': sha(canonical(anchor)),
                   'startedAtUtc': stamp(start), 'finishedAtUtc': stamp(finish)}
        packet = facts.packet(binding)
        return {'schema': 'openclaw.private-host-capture.v1',
                'expected': expected, 'unit': unit, 'binding': binding,
                'snapshot': packet, 'guestProofSha256': sha(canonical(proof))}


if __name__ == '__main__':
    raise SystemExit('host_admission_no_cli')

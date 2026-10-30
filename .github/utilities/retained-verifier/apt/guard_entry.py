"""Fixed future mkosi hook entry. Default CLI/import performs no native work.

Only a generated, hash-pinned CI source launcher calls native_main/export.
Tests use the injected capture core; they never instantiate NativeIO.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import pwd
import grp
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import types
import uuid

ROOT = Path('/etc/apt/ocv')
RECEIPTS = Path('/var/lib/apt/ocv-guard')
SHA = re.compile('[0-9a-f]{64}\\Z')
CONTEXT_CAP = 16384
MAX_RECORDS = 128


class EntryRefusal(RuntimeError):
    def __init__(self,code,facts=None):super().__init__(code);self.facts={} if facts is None else facts


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def _identity(info):
    return tuple(getattr(info, key) for key in ('st_dev','st_ino','st_mode','st_uid','st_gid',
                  'st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def _safe_read(path, cap, *, immutable=False):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, 'apt.native_path')
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and
            before.st_nlink == 1 and before.st_mode & 0o022 == 0 and
            (not immutable or before.st_mode & 0o222 == 0) and 0 <= before.st_size <= cap,
            'apt.native_identity')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd); chunks = []; total = 0
        while True:
            block = os.read(fd, min(65536, cap + 1 - total))
            if not block:
                break
            chunks.append(block); total += len(block)
            require(total <= cap, 'apt.native_read_cap')
        after = os.fstat(fd)
    finally:
        os.close(fd)
    raw = b''.join(chunks)
    require(len(raw) == before.st_size and _identity(before) == _identity(opened) ==
            _identity(after) == _identity(path.lstat()), 'apt.native_read_changed')
    return raw


def capture_command(io, argv, *, timeout, stdout_cap, stderr_cap):
    """One spawned metadata child, bounded streams and independent closeout."""
    require(type(argv) is tuple and 0 < timeout <= 30 and
            0 < stdout_cap <= 64*1024*1024 and 0 < stderr_cap <= 16384, 'apt.capture_contract')
    child = None; selector = None; reason = None; timed = False; code = None
    data = {'stdout': bytearray(), 'stderr': bytearray()}; eof = set(); errors = []
    caps = {'stdout': stdout_cap, 'stderr': stderr_cap}; phase = 'spawn'
    start = io.now()
    try:
        # The port must retain its returned handle immediately inside spawn.
        child = io.spawn(argv)
        phase = 'selector'; selector = io.selector(child)
        phase = 'setup'; io.setup(child, selector)
        while eof != {'stdout','stderr'} or code is None:
            if io.now() - start >= timeout:
                timed = True; reason = 'timeout'; break
            phase = 'read'
            for channel, block in io.drain(child, selector, min(0.1, timeout-(io.now()-start))):
                require(channel in caps and type(block) is bytes, 'apt.capture_stream')
                if block == b'':
                    eof.add(channel); continue
                room = caps[channel] - len(data[channel])
                data[channel].extend(block[:room])
                if len(block) > room:
                    reason = 'output_limit'; break
            if reason:
                break
            phase = 'poll'; code = io.poll(child)
            require(code is None or type(code) is int, 'apt.capture_exit')
        if io.now() - start >= timeout:
            timed = True; reason = 'timeout'
    except BaseException as error:
        reason = 'boundary'
        errors.append({'phase': phase, 'type': type(error).__name__, 'errno': getattr(error,'errno',None)})
    finally:
        if child is not None:
            # A failed selector/read/TERM cannot skip exact-child wait/KILL.
            for stage, call in (
                ('terminate', lambda: io.terminate_if_running(child)),
                ('wait', lambda: io.wait(child, 1)),
                ('kill', lambda: io.kill_if_running(child)),
                ('wait_final', lambda: io.wait(child, 1)),
            ):
                try:
                    value = call()
                    if stage.startswith('wait') and type(value) is int:
                        code = value
                except BaseException as error:
                    errors.append({'phase': stage, 'type': type(error).__name__, 'errno': getattr(error,'errno',None)})
            for stage, call in (
                ('close_selector', lambda: io.close_selector(selector)),
                ('close_stdout', lambda: io.close_stream(child,'stdout')),
                ('close_stderr', lambda: io.close_stream(child,'stderr')),
            ):
                try:
                    call()
                except BaseException as error:
                    errors.append({'phase': stage, 'type': type(error).__name__, 'errno': getattr(error,'errno',None)})
            try:
                settled = io.settled(child)
            except BaseException:
                settled = False
            try:io.retire(child, settled is True and not errors and eof == {'stdout','stderr'})
            except BaseException as error:
                errors.append({'phase':'retire','type':type(error).__name__,'errno':getattr(error,'errno',None)})
        else:
            settled = False
    complete = eof == {'stdout','stderr'} and reason is None and not errors
    return {'exitCode': code, 'timedOut': timed, 'captureComplete': complete,
            'ownedChildExited': settled is True, 'ownershipRetained': child is not None and
            (not settled or bool(errors) or eof != {'stdout','stderr'}),
            'stdout': bytes(data['stdout']), 'stderr': bytes(data['stderr']),
            'captureReason': reason, 'errors': errors[:16]}


class _CommandIO:
    def __init__(self):
        self.pending = None
    def now(self): return time.monotonic()
    def spawn(self, argv):
        require(self.pending is None,'apt.owned_command_uncertain')
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
             stderr=subprocess.PIPE, close_fds=True, start_new_session=True,
             env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','HOME':'/'})
        self.pending = child
        return child
    def selector(self, child): return selectors.DefaultSelector()
    def setup(self, child, selector):
        for name in ('stdout','stderr'):
            stream = getattr(child,name); os.set_blocking(stream.fileno(),False)
            selector.register(stream, selectors.EVENT_READ, name)
    def drain(self, child, selector, delay):
        result = []
        for key, _ in selector.select(max(0,delay)):
            try: raw = os.read(key.fileobj.fileno(),65536)
            except BlockingIOError: continue
            result.append((key.data,raw))
            if not raw: selector.unregister(key.fileobj)
        return result
    def poll(self, child): return child.poll()
    def terminate_if_running(self, child):
        try: os.killpg(child.pid,signal.SIGTERM)
        except ProcessLookupError: pass
    def kill_if_running(self, child):
        try: os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError: pass
    def wait(self, child, seconds): return child.wait(timeout=seconds)
    def close_selector(self, selector):
        if selector is not None: selector.close()
    def close_stream(self, child, name): getattr(child,name).close()
    def settled(self, child):
        if type(child.poll()) is not int:return False
        try:os.killpg(child.pid,0);return False
        except ProcessLookupError:return True
    def retire(self, child, settled):
        require(self.pending is child,'apt.owned_command_identity')
        if settled:self.pending=None


class NativeIO:
    """Fixed read/metadata-command port created only by checked native entry."""
    def __init__(self, context, guard):
        self.context = context; self.guard = guard; self.events = []; self.verified = None
        self.command_io = _CommandIO()
    def now(self): return datetime.now(timezone.utc)
    def apt_sandbox_identity(self):
        # Matches APT's getpwnam(SandboxUser)/getgrnam(ROOT_GROUP) source.
        user=pwd.getpwnam('_apt');root=grp.getgrnam('root')
        require(user.pw_name=='_apt' and type(user.pw_uid) is int and user.pw_uid>0 and
                root.gr_name=='root' and root.gr_gid==0,'apt.native_sandbox_account')
        return {'name':'_apt','uid':user.pw_uid,'rootGroupName':'root','rootGroupGid':root.gr_gid}
    def read_regular(self, path, cap):
        permitted = {self.guard.ETC+'/sources.list', self.guard.ETC+'/apt.conf.d/'+self.guard.GUARD_FILE,
                     self.guard.KEYRING, '/usr/bin/gpgv','/usr/lib/apt/apt-helper',
                     self.guard.LISTS+'/'+self.guard.RELEASE,
                     self.guard.LISTS+'/'+self.guard.SECURITY_RELEASE}
        permitted |= {self.guard.LISTS+'/'+name+s for name in
                      (self.guard.PACKAGES,self.guard.SECURITY_PACKAGES)
                      for s in self.guard.PACKAGE_SUFFIXES}
        require(path in permitted, 'apt.native_read_role')
        return _safe_read(path,cap)
    def entries(self, path, cap):
        directory_role(path)
        p = Path(path); require(p.resolve()==p, 'apt.native_directory_alias')
        info = p.lstat(); require(stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and
                                  info.st_mode&0o022==0, 'apt.native_directory_identity')
        rows = []
        with os.scandir(p) as stream:
            for item in stream:
                require(len(rows)<cap,'apt.native_directory_cap'); s=item.stat(follow_symlinks=False)
                kind='file' if stat.S_ISREG(s.st_mode) else 'directory' if stat.S_ISDIR(s.st_mode) else 'other'
                rows.append({'name':item.name,'kind':kind,'uid':s.st_uid,'gid':s.st_gid,
                             'mode':stat.S_IMODE(s.st_mode),'bytes':s.st_size,
                             'identity':[s.st_dev,s.st_ino,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink]})
        return sorted(rows,key=lambda x:x['name'])
    def run(self, argv, *, timeout, stdout_cap, stderr_cap):
        g=self.guard
        valid_gpg=argv in tuple(('/usr/bin/gpgv','--status-fd=1','--keyring',g.KEYRING,g.LISTS+'/'+name)
                               for name in (g.RELEASE,g.SECURITY_RELEASE))
        valid_cat=(len(argv)==3 and argv[:2]==('/usr/lib/apt/apt-helper','cat-file') and
                   argv[2] in {g.LISTS+'/'+name+s for name in (g.PACKAGES,g.SECURITY_PACKAGES)
                               for s in g.PACKAGE_SUFFIXES})
        require(valid_gpg or valid_cat,'apt.native_command_role')
        return capture_command(self.command_io,argv,timeout=timeout,stdout_cap=stdout_cap,stderr_cap=stderr_cap)
    def evidence(self, role, value):
        require(role in ('gpgv','packages') and len(self.events)<8,'apt.native_evidence_role')
        event={'role':role}
        for key in ('exitCode','timedOut','captureComplete','ownedChildExited','ownershipRetained',
                    'captureReason','errors','boundaryFailure','errno'):
            if key in value: event[key]=value[key]
        for key in ('stdout','stderr'):
            if key in value:
                raw=value[key]
                event[key]={'bytes':len(raw),'sha256':sha(raw)}
                if key=='stderr':event[key]['view']=(raw[:1024]+raw[-1024:] if len(raw)>2048 else raw).decode('ascii','backslashreplace')
        self.events.append(event)


def _load(expected_context_sha, expected_guard_sha, expected_policy_sha):
    require(sys.platform=='linux' and os.geteuid()==os.getegid()==0,'apt.native_role')
    for h in (expected_context_sha,expected_guard_sha,expected_policy_sha):
        require(type(h) is str and SHA.fullmatch(h),'apt.native_pin')
    raws={}
    for name,cap in (('guard-context.json',CONTEXT_CAP),('archive_guard.py',131072),('archive_policy.py',65536)):
        try:raws[name]=_safe_read(ROOT/name,cap,immutable=True)
        except BaseException as error:
            raise EntryRefusal('apt.native_source_read',{'role':name,'exceptionType':type(error).__name__,
                               'errno':getattr(error,'errno',None)}) from None
    for name,h in (('guard-context.json',expected_context_sha),('archive_guard.py',expected_guard_sha),
                   ('archive_policy.py',expected_policy_sha)):
        if sha(raws[name])!=h:raise EntryRefusal('apt.native_source_pin',{'role':name,'actualSha256':sha(raws[name])})
    for name in ('archive_policy','archive_guard'):
        module=types.ModuleType(name);module.__file__=str(ROOT/(name+'.py'));sys.modules[name]=module
        exec(compile(raws[name+'.py'],module.__file__,'exec'),module.__dict__)
    guard=sys.modules['archive_guard'];context=guard.parse_json(raws['guard-context.json'])
    guard.context_checked(context)
    return guard,context,NativeIO(context,guard)


def _receipt_paths():
    result=[]
    with os.scandir(RECEIPTS) as entries:
        for item in entries:
            require(len(result)<MAX_RECORDS,'apt.receipt_count')
            result.append(Path(item.path))
    return sorted(result)


def directory_role(path):
    require(path in {'/etc/apt','/etc/apt/apt.conf.d','/etc/apt/sources.list.d',
            '/etc/apt/preferences.d','/var/lib/apt/lists'}, 'apt.native_directory_role')
    return path


def context_binding(io):
    """Identity of checked native context; metadata only, never a pass grant."""
    if io is None:return {}
    context=getattr(io,'context',None)
    if not(type(context) is dict and context.get('schema')=='ocv-apt-guard-context-v1' and
           type(context.get('buildId')) is str and re.fullmatch('[0-9a-f]{32}',context['buildId']) and
           type(context.get('sourceManifestSha256')) is str and SHA.fullmatch(context['sourceManifestSha256'])):
        return {}
    return {'buildId':context['buildId'],'sourceManifestSha256':context['sourceManifestSha256'],
            'contextSha256':sha(canonical(context))}


def _record(guard, io, proof=None, *, phase, failure=None, failure_facts=None):
    if not RECEIPTS.exists(): RECEIPTS.mkdir(mode=0o700)
    s=RECEIPTS.lstat();require(RECEIPTS.resolve()==RECEIPTS and stat.S_ISDIR(s.st_mode) and
      s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700,'apt.receipt_directory')
    require(len(_receipt_paths())<MAX_RECORDS,'apt.receipt_count')
    value=guard.hook_record(proof,io.events) if proof else {
      'schema':'ocv-apt-hook-record-v1','outcome':'refused','phase':phase,
      'reason':failure,'facts':{} if failure_facts is None else failure_facts,'events':io.events}
    if proof is None:value.update(context_binding(io))
    raw=canonical(value);require(len(raw)<=16384,'apt.receipt_size')
    prefix='proof-' if proof else 'failure-'
    target=RECEIPTS/(prefix+phase+'-'+uuid.uuid4().hex+'.json')
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    return value


def failure_payload(phase,error,guard=None,io=None):
    controlled=(isinstance(error,RuntimeError) or (guard is not None and isinstance(error,guard.Refusal)))
    reason=str(error) if controlled and re.fullmatch('[a-zA-Z0-9_.:-]{1,128}',str(error)) else 'apt.native_boundary'
    value={'schema':'ocv-apt-refused-v1','phase':phase,'reason':reason,
           'exceptionType':type(error).__name__,'errno':getattr(error,'errno',None),
           'events':io.events if io else [],'facts':getattr(error,'facts',{})}
    value.update(context_binding(io))
    return value


def _failure(phase, error, guard=None, io=None, record_failure=None):
    value=failure_payload(phase,error,guard,io)
    reason=value['reason']
    if guard is not None and io is not None:
        recorder=_record if record_failure is None else record_failure
        try:recorder(guard,io,phase=phase,failure=reason,failure_facts=getattr(error,'facts',{}))
        except BaseException as receipt_error:
            value['receiptFailure']={'type':type(receipt_error).__name__,'errno':getattr(receipt_error,'errno',None)}
    raw=canonical(value)
    if len(raw)>16384:
        value['events']=value['events'][:1];value['eventViewTruncated']=True;raw=canonical(value)
    sys.stderr.write(raw.decode()+'\n')
    return 100


def native_main(expected_context_sha, expected_guard_sha, expected_policy_sha, phase):
    guard=io=None
    try:
        guard,context,io=_load(expected_context_sha,expected_guard_sha,expected_policy_sha)
        require(phase in ('update','install'),'apt.native_phase')
        # mkosi20 sets this exact file to relocate Dir::Etc before fragments.
        config=os.environ.get('APT_CONFIG',''); require(config.startswith('/'),'apt.native_config_path')
        try:config_raw=_safe_read(config,4096)
        except BaseException as error:
            raise EntryRefusal('apt.native_config_read',{'role':'mkosi-apt-config','exceptionType':type(error).__name__,
                               'errno':getattr(error,'errno',None)}) from None
        require(config_raw.strip()==b'Dir::Etc "etc/apt";','apt.native_config')
        proof=guard.run_guard(io,context,phase)
        _record(guard,io,proof,phase=phase)
        return 0
    except BaseException as error:
        return _failure(phase,error,guard,io)


def _write_once(path, raw):
    require(type(raw) is bytes,'apt.export_bytes')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o444)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())


def native_export(expected_context_sha, expected_guard_sha, expected_policy_sha):
    guard=io=None
    try:
        guard,context,io=_load(expected_context_sha,expected_guard_sha,expected_policy_sha)
        proof,contents=guard._run_dual_guard(io,context,'postinstall',guard.policy.BOOKWORM)
        _record(guard,io,proof,phase='postinstall')
        records=[]
        for path in _receipt_paths():
            require(re.fullmatch(r'proof-(update|install|postinstall)-[0-9a-f]{32}\.json',path.name),
                    'apt.failed_or_unknown_hook_receipt')
            records.append(guard.parse_json(_safe_read(path,16384)))
        ledger=canonical({'schema':'ocv-apt-first-stage-ledger-v1','records':records})
        guard.validate_ledger(ledger,context,proof)
        contents.update({'guard-proof.json':canonical(proof),'first-stage-ledger.json':ledger})
        descriptor=guard.export_descriptor(contents,proof,context)
        buildroot=Path(os.environ.get('BUILDROOT',''))
        require(buildroot.is_absolute() and buildroot!=Path('/') and buildroot.resolve()==buildroot,
                'apt.export_buildroot')
        source_manifest=_safe_read(buildroot/'opt/ocv/source/PUBLIC-SOURCE-MANIFEST.json',1048576,immutable=True)
        require(sha(source_manifest)==context['sourceManifestSha256'],'apt.export_target_source')
        destinations=(buildroot/'opt/ocv/control/apt-data',Path('/work/out/apt-data'))
        for destination in destinations:
            require(not destination.exists() and destination.parent.resolve()==destination.parent,
                    'apt.export_destination')
            destination.mkdir(mode=0o755,parents=False)
            for name,raw in contents.items():_write_once(destination/name,raw)
        _write_once(buildroot/'opt/ocv/control/apt-export.json',canonical(descriptor))
        _write_once(Path('/work/out/apt-export.json'),canonical(descriptor))
        return 0
    except BaseException as error:
        return _failure('postinstall',error,guard,io)


if __name__=='__main__':
    raise SystemExit('disarmed_requires_pinned_ci_source_launcher')

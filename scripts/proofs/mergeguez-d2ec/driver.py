#!/usr/bin/env python3
"""Task-only hosted build supervisor. No provider, production, deployment or retry route."""
import hashlib
import json
import os
import re
from pathlib import Path
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import tarfile
import time

PROOF = Path(__file__).resolve().parent
LOADED_HASH = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
GIB = 1024 ** 3

class Refusal(RuntimeError):
    pass

class UnsettledCommand(Refusal):
    """The original issued host process group may still access task storage."""
    pass

def need(ok, message):
    if not ok:
        raise Refusal(message)

def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def atomic(path, value, mode=0o600):
    temp = path.with_name(path.name + '.new')
    with open(temp, 'x', encoding='utf8') as stream:
        os.fchmod(stream.fileno(), mode)
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)

def uptime():
    return float(Path('/proc/uptime').read_text().split()[0])

def memory_available(path=Path('/proc/meminfo')):
    fields = dict(line.split(':', 1) for line in path.read_text().splitlines())
    return int(fields['MemAvailable'].split()[0]) * 1024

def validate_event(env, event, contract):
    need(env.get('GITHUB_REPOSITORY') == contract['repository'], 'wrong repository')
    need(env.get('GITHUB_REF') == contract['branch'], 'wrong branch')
    need(env.get('GITHUB_EVENT_NAME') == 'push' and env.get('GITHUB_RUN_ATTEMPT') == '1', 'not first push attempt')
    need(env.get('GITHUB_ACTOR') == contract['actor'], 'wrong actor')
    need(type(event.get('created')) is bool and event.get('forced') is False and event.get('deleted') is False, 'not non-force branch publication')
    need(event.get('repository', {}).get('id') == contract['repository_id'] and event['repository'].get('private') is False, 'wrong public repository identity')
    need(event.get('sender', {}).get('login') == contract['actor'], 'wrong event sender')
    head = env.get('GITHUB_SHA', '')
    need(re.fullmatch('[0-9a-f]{40}', head) is not None and head != '0' * 40 and event.get('after') == head, 'wrong tooling commit')
    need(event.get('ref') == contract['branch'], 'wrong event ref')
    before = event.get('before', '')
    need(type(before) is str and re.fullmatch('[0-9a-f]{40}', before) is not None and before != head, 'wrong prior branch identity')
    need((before == '0' * 40) == event['created'], 'creation/update identity mismatch')
    run_id = env.get('GITHUB_RUN_ID', '')
    need(re.fullmatch('[1-9][0-9]*', run_id) is not None, 'wrong run identity')
    # GitHub provides execution identity. Approval remains with the trusted
    # publisher, which verifies the approved old/new SHA and prior settlement.
    return {'repository_id': contract['repository_id'], 'branch': contract['branch'], 'actor': contract['actor'], 'before': before, 'tooling_commit': head, 'created': event['created'], 'run_id': run_id, 'attempt': 1, 'source_commit': contract['source_commit'], 'source_tree': contract['source_tree'], 'tooling_manifest_sha256': env.get('QUALIFICATION_MANIFEST_SHA256', '')}

def bind_admission(state, admission):
    prior = state.get('admission')
    if prior is None:
        need(state['phase'] == 'init' and not state['containers'], 'missing admission for existing job')
        state['admission'] = dict(admission)
    else:
        need(prior == admission, 'job admission identity changed')

def contained_walk(root, expected_device=None):
    """No follow; reject escaping links, specials, hard-link aliases and submounts."""
    root = Path(root)
    need(not root.is_symlink(), 'aliased task root')
    device = root.lstat().st_dev if expected_device is None else expected_device
    stack = [root]
    while stack:
        p = stack.pop()
        st = p.lstat()
        need(st.st_dev == device, 'task device crossing')
        if stat.S_ISLNK(st.st_mode):
            resolved = p.resolve(strict=True)
            need(resolved == root or root in resolved.parents, 'escaping task symlink')
        elif stat.S_ISDIR(st.st_mode):
            stack.extend(sorted(p.iterdir(), reverse=True))
        else:
            need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, 'special or hard-linked task input')
        yield p, st

def phase_mounts(mount, proof, gates, phase):
    mount, proof, gates = Path(mount), Path(proof), Path(gates)
    if phase == 'offline-native':
        # No overlapping RW ancestor, source checkout, store, or source patch mount.
        return {'/artifact': (str(mount / 'runnable'), False), '/qualification/native-state': (str(mount / 'native-state'), True), '/qualification/native-output': (str(mount / 'native-output'), True), '/tmp': (str(mount / 'native-tmp'), True), '/control': (str(gates), False), **{'/proof/' + name: (str(proof / name), False) for name in ['runtime.mjs', 'materialize.mjs', 'contract.json']}}
    result = {'/qualification': (str(mount), True), '/proof': (str(proof), False), '/control': (str(gates), False), '/tmp': (str(mount / 'tmp'), True)}
    if phase == 'offline-compile': result['/qualification/toolchain'] = (str(mount / 'toolchain'), False)
    return result

def cgroup_values(path):
    path = Path(path)
    return {n: (path / n).read_text().strip() for n in ['memory.max', 'memory.swap.max', 'pids.max', 'cpu.max']}

def validate_cgroup(values, c):
    need(values['memory.max'] == str(c['memory_bytes']) and values['memory.swap.max'] == '0', 'charged memory/swap containment mismatch')
    need(values['pids.max'] == str(c['pids']), 'PID containment mismatch')
    q, period = map(int, values['cpu.max'].split())
    need(q == period * c['cpus'], 'CPU containment mismatch')

def host_cgroup(pid, container_id, proc=Path('/proc'), cgroup=Path('/sys/fs/cgroup')):
    need(type(pid) is int and pid > 0 and re.fullmatch('[0-9a-f]{64}', container_id) is not None, 'invalid native worker identity')
    line = (proc / str(pid) / 'cgroup').read_text().strip()
    need(line.startswith('0::/') and '\n' not in line, 'not unified native cgroup')
    relative = line[3:].lstrip('/')
    p = cgroup / relative
    need(p.name in [container_id, 'docker-' + container_id + '.scope'] and p.resolve() == p, 'cgroup not bound to exact container')
    return p

def native_custody(pid, container_id, proc=Path('/proc'), cgroup=Path('/sys/fs/cgroup')):
    need(type(pid) is int and pid > 0 and re.fullmatch('[0-9a-f]{64}', container_id) is not None, 'invalid native worker identity')
    def started():
        text = (proc / str(pid) / 'stat').read_text()
        prefix, sep, rest = text.rpartition(')')
        need(sep and prefix.split(' ', 1)[0] == str(pid), 'invalid native process stat')
        fields = rest.split()
        need(len(fields) >= 20 and fields[19].isdigit() and int(fields[19]) > 0, 'missing native process start identity')
        return fields[19]
    before = started()
    path = host_cgroup(pid, container_id, proc, cgroup)
    need(started() == before, 'native process changed during custody observation')
    return {'pid': pid, 'container_id': container_id, 'start_ticks': before, 'cgroup': str(path)}

def namespace_observer(args):
    # Read-only, fixed /proc and cgroup roots. Never attach, setns, signal,
    # change a credential/policy, read an environment or launch a worker.
    need(os.geteuid() == 0, 'namespace observer requires ephemeral host root')
    need(len(args) == 5, 'wrong namespace observer arguments')
    pid, container_id, start_ticks, path, deadline = args
    need(pid.isdigit() and str(int(pid)) == pid and start_ticks.isdigit(), 'invalid namespace observer identity')
    need(uptime() < float(deadline), 'namespace observation deadline exhausted')
    expected = {'pid': int(pid), 'container_id': container_id, 'start_ticks': start_ticks, 'cgroup': path}
    need(native_custody(int(pid), container_id) == expected, 'native custody changed before namespace observation')
    observed = {}
    for name in ['pid', 'mnt', 'net', 'ipc', 'cgroup']:
        need(uptime() < float(deadline), 'namespace observation deadline exhausted')
        worker = os.readlink(Path('/proc') / pid / 'ns' / name)
        host = os.readlink(Path('/proc/self/ns') / name)
        need(re.fullmatch(name + r':\[[0-9]+\]', worker) is not None and re.fullmatch(name + r':\[[0-9]+\]', host) is not None, 'invalid ' + name + ' namespace observation')
        need(worker != host, 'shared ' + name + ' namespace')
        observed[name] = {'worker': worker, 'host': host}
    need(native_custody(int(pid), container_id) == expected, 'native custody changed during namespace observation')
    return {'custody': expected, 'observer_euid': 0, 'namespaces': observed}

def peek_exit(process):
    # Do not poll()/wait() here: retaining the unreaped leader reserves its PID
    # and process-group identity until the last group signal has been issued.
    need(hasattr(os, 'waitid'), 'host lacks non-reaping child observation')
    return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)

def close_owned_group(process):
    need(process.returncode is None, 'process group leader was reaped before custody cleanup')
    for sig in [signal.SIGTERM, signal.SIGKILL]:
        try: os.killpg(process.pid, sig)
        except ProcessLookupError: pass
    process.wait(timeout=2)
    # Observation only after reaping. Never signal this numeric group again.
    until = time.monotonic() + 2
    while True:
        try: os.killpg(process.pid, 0)
        except ProcessLookupError: return
        need(time.monotonic() < until, 'owned host process group extinction unresolved')
        time.sleep(0.02)

class Driver:
    def __init__(self):
        self.c = json.loads((PROOF / 'contract.json').read_text())
        self.workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve()
        self.control = Path(os.environ['QUALIFICATION_CONTROL'])
        need(self.control.resolve() == self.control and self.control.parent == Path(os.environ['RUNNER_TEMP']).resolve(), 'wrong control custody')
        need(self.control.lstat().st_uid == os.getuid() and not self.control.is_symlink(), 'wrong control owner')
        self.state_path = self.control / 'state.json'
        self.state = json.loads(self.state_path.read_text())
        self.mount = self.workspace / 'qualification'
        self.backing = self.control.parent / ('mergeguez-backing-' + self.state['job'])
        self.work_deadline = self.state['start_uptime'] + self.c['work_seconds']
        self.cleanup_deadline = self.state['start_uptime'] + self.c['total_seconds'] - 60
        self.log_bytes = sum(p.stat().st_size for p in self.control.glob('*.log'))
        self.env = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': str(self.control / 'client-home'), 'DOCKER_CONFIG': str(self.control / 'docker-config'), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null'}
        for p in ['client-home', 'docker-config']:
            (self.control / p).mkdir(mode=0o700, exist_ok=True)
        self.gates = self.control / 'gates'
        self.gates.mkdir(mode=0o755, exist_ok=True)
        self.gates.chmod(0o755)
        self.verify_tooling()

    def save(self):
        atomic(self.state_path, self.state)

    def verify_tooling(self):
        m = PROOF / 'manifest.json'
        need(digest(m) == os.environ['QUALIFICATION_MANIFEST_SHA256'], 'tooling manifest mismatch')
        for x in json.loads(m.read_text())['files']:
            p = PROOF / x['path']
            need(p.resolve().parent == PROOF and p.is_file() and not p.is_symlink(), 'tooling path alias')
            need(p.stat().st_size == x['bytes'] and digest(p) == x['sha256'], 'tooling bytes changed')
            if x['path'] == 'driver.py':
                need(x['sha256'] == LOADED_HASH, 'loaded driver differs from sealed driver')
        admission = validate_event(os.environ, json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text()), self.c)
        need(self.state['job'] == os.environ['GITHUB_RUN_ID'] + '-1', 'job receipt mismatch')
        bind_admission(self.state, admission)
        self.admission = admission
        self.save()

    def budget(self, cleanup=False):
        need(self.state.get('admission') == self.admission, 'job admission identity changed')
        need(uptime() < (self.cleanup_deadline if cleanup else min(self.work_deadline, getattr(self, 'active_deadline', self.work_deadline))), 'shared deadline exhausted')
        if not cleanup:
            need(os.statvfs(self.workspace).f_bavail * os.statvfs(self.workspace).f_frsize >= self.c['outside_free_reserve_bytes'], 'outside disk reserve exhausted')

    def command(self, argv, name='host', cleanup=False, maximum=120, retain_log=True):
        self.budget(cleanup)
        limit = min(maximum, (self.cleanup_deadline if cleanup else min(self.work_deadline, getattr(self, 'active_deadline', self.work_deadline))) - uptime())
        p = None; selector = None
        try:
            p = subprocess.Popen(argv, env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
            selector = selectors.DefaultSelector(); selector.register(p.stdout, selectors.EVENT_READ)
            out = bytearray(); deadline = uptime() + limit
            while selector.get_map():
                self.budget(cleanup)
                need(uptime() < deadline, 'host command timeout')
                for key, _ in selector.select(0.1):
                    block = os.read(key.fd, 65536)
                    if not block: selector.unregister(key.fileobj); continue
                    capture_limit = self.c['evidence_cap_bytes'] - 4 * 1024**2 if cleanup else self.c['log_cap_bytes']
                    need(len(out) + len(block) <= 2 * 1024**2 and (not retain_log or self.log_bytes + len(block) <= capture_limit), 'diagnostic capture bound exceeded')
                    out.extend(block)
                    if retain_log:
                        self.log_bytes += len(block)
                        with open(self.control / (name + '.log'), 'ab') as log: log.write(block)
            result = peek_exit(p)
            while result is None:
                self.budget(cleanup); need(uptime() < deadline, 'host command timeout')
                time.sleep(0.02); result = peek_exit(p)
            need(result.si_code == os.CLD_EXITED and result.si_status == 0, 'host command failed: ' + argv[0] + ' (' + str(result.si_status) + ')')
            return bytes(out).decode('utf8')
        finally:
            try:
                if p is not None: self.join_host_group(p, name)
            finally:
                try:
                    if selector is not None: selector.close()
                finally:
                    if p is not None: p.stdout.close()

    def join_host_group(self, process, purpose):
        # The original unreaped Popen handle owns signalling and joins. This
        # persisted diagnostic never grants authority to act on a later PID.
        operation_error = sys.exc_info()[1]
        try: close_owned_group(process)
        except Exception as error:
            self.state['host_command_custody_unknown'] = True
            self.state.setdefault('unknown_host_group_custody', []).append({'purpose': purpose, 'issued_pid': process.pid, 'start_new_session': True, 'operation_error': None if operation_error is None else (type(operation_error).__name__ + ': ' + str(operation_error))[:2048], 'join_error': (type(error).__name__ + ': ' + str(error))[:2048], 'identity_policy': 'original unreaped Popen owner only; no persisted PID release authority'})
            self.state['host_command_custody_error'] = (type(error).__name__ + ': ' + str(error))[:2048]
            try: self.save()
            finally: raise UnsettledCommand('owned host command group not settled') from error

    def docker(self, *args, **kwargs):
        return self.command(['docker', *args], **kwargs)

    def inspect(self, name, cleanup=False):
        return json.loads(self.docker('inspect', name, cleanup=cleanup, maximum=10, retain_log=False))[0]

    def verify_owned(self, record, cleanup=False):
        value = self.inspect(record['name'], cleanup)
        labels = value['Config']['Labels']
        need(labels.get('mergeguez.qualification.job') == self.state['job'] and labels.get('mergeguez.qualification.driver') == LOADED_HASH, 'container ownership changed')
        need(value['Name'] == '/' + record['name'], 'container name changed')
        if record.get('id'): need(value['Id'] == record['id'], 'container identity changed')
        return value

    def capture_native_custody(self, record, spec):
        need(spec['State']['Running'], 'native worker is not running')
        custody = native_custody(spec['State']['Pid'], record['id'])
        if record.get('native_custody') is not None:
            need(record['native_custody'] == custody, 'issued native custody changed')
        else:
            # Custody is not admission. Save before namespace/limit guards can
            # fail, so cleanup retains the exact issued native cgroup.
            record['native_custody'] = custody
            record['cgroup'] = custody['cgroup']
            self.save()
        return custody

    def admit_worker(self, record, spec):
        custody = self.capture_native_custody(record, spec)
        result = json.loads(self.command(['sudo', '-n', sys.executable, str(PROOF / 'driver.py'), '_namespaces', str(custody['pid']), record['id'], custody['start_ticks'], custody['cgroup'], str(self.work_deadline)], name='namespace-observation', maximum=10, retain_log=False))
        need(result.get('custody') == custody and result.get('observer_euid') == 0, 'namespace observer custody mismatch')
        spaces = result.get('namespaces', {})
        need(set(spaces) == {'pid', 'mnt', 'net', 'ipc', 'cgroup'}, 'incomplete namespace observation')
        for name, values in spaces.items():
            need(all(type(values.get(k)) is str and re.fullmatch(name + r':\[[0-9]+\]', values[k]) is not None for k in ['worker', 'host']) and values['worker'] != values['host'], 'invalid or shared ' + name + ' namespace')
        current = self.verify_owned(record)
        need(current['State']['Running'] and current['State']['Pid'] == custody['pid'], 'Docker worker changed during namespace observation')
        need(native_custody(custody['pid'], record['id']) == custody, 'native worker changed during namespace observation')
        path = Path(custody['cgroup'])
        validate_cgroup(cgroup_values(path), self.c)
        record['namespace_observation'] = result
        record['initial_memory_events'] = (path / 'memory.events').read_text()
        self.save()

    def prepare(self):
        self.active_deadline = min(self.work_deadline, uptime() + self.c['phase_max_seconds']['prepare'])
        need(self.state['phase'] == 'init', 'preparation already attempted')
        self.state['phase'] = 'preparing'; self.save()
        need(sys.platform == 'linux' and Path('/sys/fs/cgroup/cgroup.controllers').is_file(), 'wrong host/cgroup backend')
        need(memory_available() >= self.c['available_memory_min_bytes'], 'insufficient fresh available memory')
        need(self.docker('ps', '-q').strip() == '', 'fresh host has other running containers')
        self.state['docker_info'] = json.loads(self.docker('info', '--format', '{{json .}}'))
        need(self.state['docker_info']['CgroupVersion'] == '2', 'wrong Docker cgroup version')
        for image in [self.c['node_image'], self.c['bun_image']]:
            self.docker('pull', '--platform', 'linux/amd64', image, name='image-pull', maximum=1200)
            info = json.loads(self.docker('image', 'inspect', image))[0]
            need(info['Os'] == 'linux' and info['Architecture'] == 'amd64' and any(x.split('@')[-1] == image.split('@')[-1] for x in info['RepoDigests']), 'image platform/digest mismatch')
            self.state.setdefault('images', {})[image] = info['Id']; self.save()
        free = os.statvfs(self.workspace).f_bavail * os.statvfs(self.workspace).f_frsize
        need(free >= self.c['free_after_images_min_bytes'] and memory_available() >= self.c['available_memory_min_bytes'], 'post-image headroom insufficient')
        need(not self.mount.exists() and not self.mount.is_symlink() and not self.backing.exists() and not self.backing.is_symlink(), 'pre-existing task storage')
        # Journal before the first storage effect. Allocation/mkfs can fail
        # before mount is issued; those files still need qualified retirement.
        self.state['storage_intent'] = True; self.save()
        self.mount.mkdir(mode=0o700)
        fd = os.open(self.backing, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            st = os.fstat(fd)
            self.state['backing_identity'] = {'device': st.st_dev, 'inode': st.st_ino}
            self.save()
        finally: os.close(fd)
        self.check_backing()
        self.command(['fallocate', '-l', str(self.c['filesystem_bytes']), str(self.backing)])
        self.check_backing()
        self.command(['mkfs.ext4', '-q', '-F', '-m', '0', str(self.backing)])
        self.check_backing()
        self.state['mount_intent'] = True; self.save()
        self.command(['sudo', '-n', 'mount', '-o', 'loop,nodev,nosuid', str(self.backing), str(self.mount)])
        self.check_mount()
        self.command(['sudo', '-n', 'chown', str(os.getuid()) + ':' + str(os.getgid()), str(self.mount)])
        self.state['phase'] = 'prepared'; self.save()

    def check_backing(self):
        st = self.backing.lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o600, 'backing custody changed')
        need(self.state.get('backing_identity') == {'device': st.st_dev, 'inode': st.st_ino}, 'backing identity unknown or changed')
        return st

    def loop_devices(self, selector, cleanup=False):
        # --json applies to --list; a selected device alone prints classic text.
        rows = json.loads(self.command(['sudo', '-n', 'losetup', '--list', '--json', '--output', 'NAME,BACK-FILE', *selector], cleanup=cleanup, maximum=10))['loopdevices']
        need(isinstance(rows, list), 'invalid loop observation')
        for row in rows:
            need(re.fullmatch('/dev/loop[0-9]+', row.get('name', '')) is not None and Path(row['back-file']).resolve() == self.backing, 'loop association changed')
        return rows

    def check_mount(self, cleanup=False, allow_absent=False):
        need(not self.mount.is_symlink(), 'mount path aliased')
        rows = json.loads(self.command(['findmnt', '-J', '-T', str(self.mount), '-o', 'TARGET,SOURCE,FSTYPE,OPTIONS'], cleanup=cleanup, maximum=10))['filesystems']
        need(len(rows) == 1, 'ambiguous mount observation')
        info = rows[0]
        if allow_absent and info['target'] != str(self.mount): return False
        need(info['target'] == str(self.mount) and info['fstype'] == 'ext4' and {'nodev', 'nosuid', 'rw'}.issubset(set(info['options'].split(','))), 'wrong mounted filesystem')
        need(self.state.get('mount_intent') is True, 'mount was not issued by this job')
        loop = info['source']; need(loop.startswith('/dev/loop') and loop[9:].isdigit(), 'not owned loop filesystem')
        values = self.loop_devices([loop], cleanup)
        need(len(values) == 1 and values[0]['name'] == loop and self.check_backing().st_size == self.c['filesystem_bytes'], 'wrong loop backing')
        device = self.mount.stat().st_dev
        need(self.state.get('loop', loop) == loop and self.state.get('device', device) == device, 'mounted identity changed')
        self.state['loop'] = loop; self.state['device'] = device; self.save()
        return True

    def reconcile_storage(self):
        need(not self.state.get('host_command_custody_unknown'), 'unresolved host command ownership; hold task storage')
        if not self.state.get('storage_intent'):
            need(not self.state.get('mount_intent') and not self.state.get('loop') and not self.backing.exists() and not self.backing.is_symlink() and not self.mount.is_mount(), 'storage creation custody missing')
            self.state['storage_retired'] = True; self.save(); return False
        if not self.backing.exists() and not self.backing.is_symlink():
            need(not self.state.get('backing_identity') and not self.state.get('mount_intent') and not self.state.get('loop') and not self.mount.is_mount(), 'intended backing disappeared')
            self.state['storage_retired'] = True; self.save(); return False
        self.check_backing()
        return self.check_mount(cleanup=True, allow_absent=True)

    def retire_storage(self, mounted):
        need(not self.state.get('host_command_custody_unknown'), 'unresolved host command ownership; hold task storage')
        if self.state.get('storage_retired'): return
        self.check_backing()
        if mounted:
            self.check_mount(cleanup=True)
            self.command(['sudo', '-n', 'umount', str(self.mount)], cleanup=True, maximum=20)
            self.state['unmount_completed'] = True; self.save()
        # mount -o loop uses autoclear. Observe its bounded retirement; never
        # detach a global loop or repeatedly issue an uncertain unmount.
        until = min(uptime() + 20, self.cleanup_deadline)
        while True:
            rows = self.loop_devices(['--associated', str(self.backing)], cleanup=True)
            need(all(row['name'] == self.state.get('loop') for row in rows), 'unreconciled loop association')
            if not rows: break
            need(uptime() < until, 'loop backing still attached'); time.sleep(0.1)
        need(not self.check_mount(cleanup=True, allow_absent=True), 'task mount still present')
        need(not self.state.get('host_command_custody_unknown'), 'unresolved host command ownership; hold backing')
        self.check_backing(); self.backing.unlink()
        self.state['storage_retired'] = True; self.save()

    def source(self):
        self.active_deadline = min(self.work_deadline, uptime() + self.c['phase_max_seconds']['source'])
        need(self.state['phase'] == 'prepared', 'source reconstruction not admitted')
        self.check_mount(); source = self.mount / 'source'
        need(source.resolve().parent == self.mount and source.stat().st_dev == self.state['device'], 'checkout outside bound')
        def git(*args): return self.command(['git', '-C', str(source), *args], name='source').strip()
        need(git('rev-parse', 'HEAD') == self.c['baseline'] and git('rev-parse', 'HEAD^{tree}') == self.c['baseline_tree'], 'wrong baseline')
        need(git('status', '--porcelain=v1') == '', 'dirty baseline')
        need(git('remote', 'get-url', 'origin') in ['https://github.com/fr-meyer/openclaw', 'https://github.com/fr-meyer/openclaw.git'], 'wrong public origin')
        for step in self.c['source_chain']:
            need(git('rev-parse', 'HEAD') == step['parent'], 'source chain parent absent')
            patch, raw = PROOF / step['patch'], PROOF / step['raw_commit']
            need(digest(patch) == step['patch_sha256'] and digest(raw) == step['raw_commit_sha256'], 'source delta mismatch')
            raw_text = raw.read_text()
            need(raw_text.startswith('tree ' + step['tree'] + '\nparent ' + step['parent'] + '\n'), 'raw source ancestry mismatch')
            git('apply', '--check', '--index', str(patch)); git('apply', '--index', str(patch))
            need(git('write-tree') == step['tree'], 'source result tree mismatch')
            need(git('hash-object', '-t', 'commit', '-w', str(raw)) == step['commit'], 'source raw identity mismatch')
            git('-c', 'core.hooksPath=/dev/null', 'checkout', '--detach', step['commit'])
            need(git('status', '--porcelain=v1') == '', 'reconstructed source dirty')
        need(git('rev-parse', 'HEAD') == self.c['source_commit'] and git('rev-parse', 'HEAD^{tree}') == self.c['source_tree'], 'final coherent source mismatch')
        for name in ['toolchain', 'toolchain/bin', 'home', 'tmp', 'reports', 'pnpm-store', 'native-state', 'native-output', 'native-tmp']:
            (self.mount / name).mkdir(mode=0o700, exist_ok=True)
        export = {'name': 'mergeguez-bun-' + self.state['job'], 'kind': 'export', 'started': False}
        self.state['containers'].append(export); self.save()
        export['id'] = self.docker('create', '--name', export['name'], '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--label', 'mergeguez.qualification.job=' + self.state['job'], '--label', 'mergeguez.qualification.driver=' + LOADED_HASH, '--entrypoint', '/bin/true', self.state['images'][self.c['bun_image']]).strip(); self.save()
        self.verify_owned(export)
        self.docker('cp', export['id'] + ':/usr/local/bin/bun', str(self.mount / 'toolchain/bun'))
        (self.mount / 'toolchain/bun').chmod(0o555)
        self.state['bun_binary_sha256'] = digest(self.mount / 'toolchain/bun'); self.save()
        self.command(['sudo', '-n', sys.executable, str(PROOF / 'driver.py'), '_handoff', str(self.mount), str(self.state['device']), str(self.c['compiler_uid']), str(self.c['compiler_gid']), str(self.work_deadline)])
        self.state['phase'] = 'source-owned'; self.save()

    def phase(self, phase):
        self.active_deadline = min(self.work_deadline, uptime() + self.c['phase_max_seconds'][phase])
        self.budget(); need(memory_available() >= self.c['available_memory_min_bytes'], 'fresh phase memory admission failed')
        gate = self.gates / 'gate.json'; gate.unlink(missing_ok=True)
        nonce = secrets.token_hex(32)
        record = {'name': 'mergeguez-' + phase + '-' + self.state['job'], 'kind': 'worker', 'phase': phase, 'started': False}
        self.state['containers'].append(record); self.save()
        mounts = phase_mounts(self.mount, PROOF, self.gates, phase)
        argv = ['create', '--name', record['name'], '--platform', 'linux/amd64', '--user', '1000:1000', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--cgroupns', 'private', '--ipc', 'private', '--network', 'bridge' if phase == 'warm-fetch' else 'none', '--memory', str(self.c['memory_bytes']), '--memory-swap', str(self.c['memory_bytes']), '--cpus', '4', '--pids-limit', '512', '--log-driver', 'none', '--label', 'mergeguez.qualification.job=' + self.state['job'], '--label', 'mergeguez.qualification.driver=' + LOADED_HASH]
        for destination, (origin, writable) in mounts.items():
            argv += ['--mount', 'type=bind,src=' + origin + ',dst=' + destination + ('' if writable else ',readonly')]
        argv += ['--workdir', '/artifact' if phase == 'offline-native' else '/qualification/source', '--env', 'QUALIFICATION_JOB=' + self.state['job'], '--env', 'QUALIFICATION_NONCE=' + nonce, '--env', 'QUALIFICATION_UPTIME_DEADLINE=' + str(self.active_deadline), '--entrypoint', 'node', self.state['images'][self.c['node_image']], '/proof/runtime.mjs', phase]
        record['id'] = self.docker(*argv).strip(); self.save()
        spec = self.verify_owned(record); hc = spec['HostConfig']
        need(hc['Memory'] == self.c['memory_bytes'] and hc['MemorySwap'] == self.c['memory_bytes'] and hc['ReadonlyRootfs'] and not hc['Privileged'] and hc['NetworkMode'] == ('bridge' if phase == 'warm-fetch' else 'none'), 'Docker containment spec mismatch')
        expected = mounts
        observed = {x['Destination']: (x['Source'], x['RW']) for x in spec['Mounts']}
        need(observed == expected and all(x['Type'] == 'bind' for x in spec['Mounts']), 'unexpected or writable control mount')
        need(hc['LogConfig']['Type'] == 'none' and spec['Config']['User'] == '1000:1000', 'unbounded daemon log or wrong compiler UID')
        need({x.split('=', 1)[0] for x in spec['Config']['Env']}.issubset({'PATH', 'NODE_VERSION', 'YARN_VERSION', 'QUALIFICATION_JOB', 'QUALIFICATION_NONCE', 'QUALIFICATION_UPTIME_DEADLINE'}), 'compiler environment override')
        record['admitted_docker_spec'] = {'host_config': hc, 'mounts': spec['Mounts'], 'image': spec['Image'], 'user': spec['Config']['User'], 'environment_names': [x.split('=', 1)[0] for x in spec['Config']['Env']]}; self.save()
        record['started'] = True; self.save()
        attach = None; sel = None
        try:
            attach = subprocess.Popen(['docker', 'start', '--attach', record['id']], env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
            sel = selectors.DefaultSelector(); sel.register(attach.stdout, selectors.EVENT_READ)
            admitted = False; start = uptime(); eof = False
            while True:
                self.budget()
                for key, _ in sel.select(0.1):
                    block = os.read(key.fd, 65536)
                    if not block: sel.unregister(key.fileobj); eof = True; continue
                    need(self.log_bytes + len(block) <= self.c['log_cap_bytes'], 'captured model-free build log exceeded bound')
                    self.log_bytes += len(block)
                    with open(self.control / (phase + '.log'), 'ab') as log: log.write(block)
                spec = self.verify_owned(record)
                if spec['State']['Running'] and not admitted:
                    self.admit_worker(record, spec)
                    atomic(gate, {'job': self.state['job'], 'phase': phase, 'nonce': nonce, 'admitted': True}, mode=0o644)
                    admitted = True
                if admitted and spec['State']['Running']:
                    cg = Path(record['cgroup'])
                    try:
                        validate_cgroup(cgroup_values(cg), self.c)
                        record['last_observed_metrics'] = {x: (cg / x).read_text().strip() for x in ['memory.current', 'memory.peak', 'memory.events', 'memory.pressure', 'cpu.stat', 'pids.current']}
                        self.save()
                    except FileNotFoundError:
                        # A terminal transition may remove the native cgroup;
                        # final Docker state/extinction remains mandatory.
                        record['metrics_unavailable_at_transition'] = True
                if not spec['State']['Running'] and spec['State']['Status'] == 'exited':
                    record['exit_code'] = spec['State']['ExitCode']; record['oom_killed'] = spec['State']['OOMKilled']; self.save()
                    need(admitted and not record['oom_killed'] and record['exit_code'] == 0, 'worker did not complete after native admission')
                    if eof: break
                need(not eof or spec['State']['Status'] == 'exited', 'attach disconnected before worker terminal')
                need(admitted or uptime() - start < 30, 'worker admission unresolved')
                time.sleep(0.5)
            until = min(uptime() + 5, self.work_deadline)
            result = peek_exit(attach)
            while result is None:
                need(uptime() < until, 'attach CLI terminal unresolved')
                time.sleep(0.02); result = peek_exit(attach)
            need(result.si_code == os.CLD_EXITED and result.si_status == 0, 'attach CLI failed')
            self.settle(record)
            receipt = json.loads(self.command(['sudo', '-n', 'cat', str(self.mount / ('native-output' if phase == 'offline-native' else 'reports') / (phase + '-receipt.json'))], name='receipts'))
            need(receipt['phase'] == phase and receipt['job'] == self.state['job'] and receipt['complete'] is True, 'incomplete worker result')
            self.state.setdefault('receipts', {})[phase] = receipt; self.save()
        finally:
            try: gate.unlink(missing_ok=True)
            finally:
                try:
                    if attach is not None: self.join_host_group(attach, 'docker-attach-' + phase)
                finally:
                    try:
                        if sel is not None: sel.close()
                    finally:
                        if attach is not None: attach.stdout.close()

    def settle(self, record):
        if record.get('settled'): return
        spec = self.verify_owned(record, cleanup=True)
        if record['started'] and not record.get('cgroup') and spec['State']['Running']:
            # Also reconcile a launch/attach failure before the first admission
            # observation. Never invent custody for an already terminal worker.
            try: self.capture_native_custody(record, spec)
            except Exception as error:
                record['custody_error'] = str(error); self.save()
        if spec['State']['Running']:
            try: self.docker('stop', '--time', '10', record['id'], cleanup=True, maximum=20)
            except Exception as e: record['stop_error'] = str(e); self.save()
            spec = self.verify_owned(record, cleanup=True)
            if spec['State']['Running']:
                self.docker('kill', record['id'], cleanup=True, maximum=10)
                spec = self.verify_owned(record, cleanup=True)
        need(not spec['State']['Running'] and spec['State']['Pid'] == 0, 'worker terminal unresolved')
        if record['started']:
            need(record.get('cgroup'), 'issued cgroup identity was never observed; retain unknown')
            cg = Path(record['cgroup']); until = min(uptime() + 20, self.cleanup_deadline)
            while cg.exists() and uptime() < until: time.sleep(0.1)
            need(not cg.exists(), 'worker cgroup extinction unresolved')
        self.docker('rm', record['id'], cleanup=True, maximum=10)
        record['settled'] = True; self.save()

    def execute(self):
        self.source(); self.phase('warm-fetch')
        self.state['compilation_attempted'] = True; self.save()
        self.phase('offline-compile')
        self.state['phase'] = 'compiled'; self.state['compiled_complete'] = True; self.save()
        self.state['native_started'] = True; self.save()
        self.phase('offline-native')
        self.state['phase'] = 'qualified'; self.save()

    def cleanup(self):
        issues = []
        if self.state.get('host_command_custody_unknown'): issues.append('unresolved host command ownership; hold task storage')
        for record in self.state['containers']:
            if not record.get('id'):
                # An uncertain create cannot be inferred absent from a failed CLI.
                issues.append('unreconciled container create: ' + record['name']); continue
            try: self.settle(record)
            except Exception as e: issues.append(str(e))
        mounted = False
        if not issues:
            try: mounted = self.reconcile_storage()
            except Exception as e: issues.append(str(e))
        if not issues and mounted and (self.state.get('compiled_complete') or self.state.get('native_started') or self.state.get('compilation_attempted')):
            try:
                self.command(['sudo', '-n', sys.executable, str(PROOF / 'driver.py'), '_retain', str(self.mount), str(self.control), str(self.state['device']), str(os.getuid()), str(os.getgid()), str(self.cleanup_deadline), self.state['job'], '1' if self.state.get('native_started') else '0'], cleanup=True, maximum=self.c['archive_max_seconds'], name='retain-runnable-native')
                if (self.control / 'runnable.tar.gz').exists():
                    self.state['runnable_archive_sha256'] = digest(self.control / 'runnable.tar.gz')
                    self.state['native_state_retained'] = True
            except Exception as e: issues.append('retention unresolved; hold task storage: ' + str(e))
        if not issues and mounted:
            try:
                self.command(['sudo', '-n', sys.executable, str(PROOF / 'driver.py'), '_reports', str(self.mount), str(self.control), str(self.state['device']), str(os.getuid()), str(os.getgid())], cleanup=True, name='reports')
            except Exception as e: issues.append(str(e))
        candidate = self.state['phase'] == 'qualified' and not issues and self.state.get('native_state_retained') is True
        self.state['cleanup_issues'] = issues; self.state['complete'] = False
        self.save()
        upload = self.control / 'upload'; stage = self.control / 'upload.stage'
        need(not upload.exists() and not stage.exists(), 'retention publication already attempted')
        stage.mkdir(mode=0o700)
        try:
            total = self.state_path.stat().st_size
            for p in [*self.control.glob('*.log'), *(p for p in self.control.glob('*.json') if p != self.state_path)]:
                total += p.stat().st_size
                need(total <= self.c['evidence_cap_bytes'], 'evidence retention exceeded')
                (stage / p.name).write_bytes(p.read_bytes())
            atomic(stage / 'state.json', self.state)
            if self.state.get('native_state_retained'):
                os.rename(self.control / 'runnable.tar.gz', stage / 'runnable.tar.gz')
            # Publish a false receipt first. Success is the final atomic write,
            # after all archive, copy and directory publication steps succeed.
            os.rename(stage, upload)
            # Durable archive/evidence publication precedes task storage retirement.
            if not issues:
                try: self.retire_storage(mounted)
                except Exception as error: issues.append(str(error))
            self.state['cleanup_issues'] = issues
            self.state['complete'] = candidate and not issues and self.state.get('storage_retired') is True; self.save()
            atomic(upload / 'state.json', self.state)
        except Exception as error:
            self.state['complete'] = False
            self.state['retention_error'] = str(error)
            self.save()
            upload.mkdir(mode=0o700, exist_ok=True)
            atomic(upload / 'state.json', self.state)
            raise
        need(self.state['complete'], 'qualification failed/unknown; retained diagnostic evidence only')

def handoff(args):
    root, device, uid, gid, deadline = args
    root = Path(root); need(root.is_mount(), 'handoff root not mounted')
    for p, st in contained_walk(root, int(device)):
        need(uptime() < float(deadline), 'handoff deadline exhausted')
        os.chown(p, int(uid), int(gid), follow_symlinks=False)


def compiled_walk(source, names, device):
    # Retain original runtime symlinks as metadata, never follow or copy targets.
    # Both lexical and physical targets must stay inside selected compiled roots.
    source = Path(source)
    need(source.resolve() == source and not source.is_symlink(), 'aliased compiled source')
    need(isinstance(names, list) and names and len(names) == len(set(names)), 'invalid compiled roots')
    need(all(isinstance(n, str) and re.fullmatch(r'(dist|dist-runtime|packages/[a-z-]+/dist)', n) for n in names), 'unsafe compiled root name')
    roots = [source / n for n in names]
    def retained(p): return any(p == r or r in p.parents for r in roots)
    for root in roots:
        need(root.is_dir() and root.resolve() == root and not root.is_symlink(), 'compiled root missing or aliased')
        regular = 0; stack = [root]
        while stack:
            p = stack.pop(); st = p.lstat()
            need(st.st_dev == device, 'compiled device crossing')
            if stat.S_ISLNK(st.st_mode):
                target = os.readlink(p)
                need(not os.path.isabs(target), 'absolute compiled link')
                lexical = Path(os.path.abspath(p.parent / target))
                need(retained(lexical) and retained(p.resolve(strict=True)), 'escaping compiled link')
            elif stat.S_ISDIR(st.st_mode): stack.extend(sorted(p.iterdir(), reverse=True))
            else:
                need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, 'special or hard-linked compiled output')
                regular += 1
            yield p, st
        need(regular > 0, 'empty compiled root')

def archive(args):
    mount, control, device, cap, uid, gid, deadline = args
    mount, control = Path(mount), Path(control); need(mount.is_mount(), 'archive mount absent')
    need(control.resolve() == control and control.lstat().st_uid == int(uid), 'archive output custody changed')
    contract = json.loads((PROOF / 'contract.json').read_text())
    files = []; total = 0
    for p, st in compiled_walk(mount / 'source', contract['compiled_roots'], int(device)):
        need(uptime() < float(deadline), 'archive deadline exhausted')
        if stat.S_ISREG(st.st_mode): total += st.st_size
        need(total <= int(cap), 'compiled output cap exceeded')
        files.append(p)
    target = mount / 'compiled.tar.gz'; need(not target.exists(), 'archive target pre-exists')
    with tarfile.open(target, 'w:gz') as tar:
        for p in files:
            need(uptime() < float(deadline), 'archive deadline exhausted')
            tar.add(p, arcname=str(p.relative_to(mount / 'source')), recursive=False)
    need(target.stat().st_size <= int(cap), 'compiled archive cap exceeded')
    output = control / 'compiled.tar.gz'; need(not output.exists(), 'retention target pre-exists')
    with open(target, 'rb') as src, open(output, 'xb') as dst:
        for block in iter(lambda: src.read(1024 * 1024), b''):
            need(uptime() < float(deadline), 'retention deadline exhausted'); dst.write(block)
    os.chown(output, int(uid), int(gid)); output.chmod(0o600)

class CappedArchiveWriter:
    def __init__(self, stream, cap, deadline): self.stream, self.cap, self.deadline, self.bytes = stream, cap, deadline, 0
    def write(self, data):
        need(uptime() < self.deadline, 'retention deadline exhausted')
        need(self.bytes + len(data) <= self.cap, 'combined compressed retention cap exceeded')
        written = self.stream.write(data); self.bytes += written; return written
    def flush(self): self.stream.flush()


def retain(args):
    mount, control, device, uid, gid, deadline, job, native_required = args
    need(native_required in ['0', '1'] and re.fullmatch('[0-9]+-1', job), 'retention execution identity absent')
    mount, control, device, deadline = Path(mount), Path(control), int(device), float(deadline)
    need(mount.is_mount() and control.resolve() == control and control.lstat().st_uid == int(uid), 'retention custody changed')
    contract = json.loads((PROOF / 'contract.json').read_text())
    build_file = mount / 'reports/offline-compile-build.json'
    if not build_file.exists():
        need(native_required == '0', 'native state has no successful build owner receipt'); return
    st = build_file.lstat(); need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_dev == device and st.st_size <= 65536, 'unsafe successful build receipt')
    build = json.loads(build_file.read_text())
    need(build.get('complete') is True and build.get('job') == job and build.get('source_commit') == contract['source_commit'] and build.get('source_tree') == contract['source_tree'] and build.get('compile_argv') == contract['compile_argv'] and build.get('environment') == contract['compile_environment'], 'retention build/source/job mismatch')
    commands = build.get('commands', [])
    need([command.get('argv') for command in commands] == [['corepack', contract['packageManager'], *contract['install_argv']], *contract['compile_argv']] and all(command.get('code') == 0 and command.get('signal') is None for command in commands), 'retention original compile receipts absent')
    # Source emissions are bounded by the compiler phase; retention owns only the actual portable/native roots.
    files = []
    caps = {'package': contract['retention_cap_bytes'], 'runnable': contract['portable_runnable_unpacked_cap_bytes'], 'native-state': contract['native_state_cap_bytes'], 'native-output': contract['native_state_cap_bytes']}
    for name in contract['retention_roots']:
        root = mount / name
        if not root.exists():
            need(native_required == '0', 'required native retention root absent'); continue
        need(root.is_dir() and root.resolve() == root, 'required retention root absent')
        total = 0
        for p, st in contained_walk(root, device):
            need(uptime() < deadline, 'retention inventory deadline exhausted')
            if stat.S_ISREG(st.st_mode): total += st.st_size
            need(total <= caps[name], 'retention root cap exceeded: ' + name)
            files.append(p)
    output = control / 'runnable.tar.gz'; need(not output.exists(), 'retention target pre-exists')
    try:
        with open(output, 'xb') as raw:
            os.fchmod(raw.fileno(), 0o600); os.fchown(raw.fileno(), int(uid), int(gid))
            stream = CappedArchiveWriter(raw, contract['retention_cap_bytes'], deadline)
            with tarfile.open(fileobj=stream, mode='w|gz') as tar:
                for p in files:
                    need(uptime() < deadline, 'retention archive deadline exhausted')
                    tar.add(p, arcname=str(p.relative_to(mount)), recursive=False)
            raw.flush(); os.fsync(raw.fileno())
    except Exception:
        # Partial retained bytes confer no approval; source/native state remains on held volume.
        raise


def reports(args):
    mount, control, device, uid, gid = args
    mount, control = Path(mount), Path(control)
    need(mount.is_mount() and control.resolve() == control and control.lstat().st_uid == int(uid), 'report custody changed')
    for name, directory in [('warm-fetch-receipt.json', 'reports'), ('offline-compile-receipt.json', 'reports'), ('offline-native-receipt.json', 'native-output'), ('offline-compile-build.json', 'reports'), ('runnable-materialization.json', 'reports')]:
        source = mount / directory / name
        if not source.exists(): continue
        st = source.lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_dev == int(device) and st.st_size <= 65536 and st.st_nlink == 1, 'unsafe receipt input')
        target = control / source.name
        need(not target.exists(), 'receipt already retained')
        target.write_bytes(source.read_bytes()); os.chown(target, int(uid), int(gid)); target.chmod(0o600)

def main():
    if len(sys.argv) > 1 and sys.argv[1] == '_namespaces':
        print(json.dumps(namespace_observer(sys.argv[2:]), sort_keys=True)); return
    if len(sys.argv) > 1 and sys.argv[1] in ['_handoff', '_archive', '_reports', '_retain']:
        need(os.geteuid() == 0, 'privileged helper requires ephemeral operator')
        {'_handoff': handoff, '_archive': archive, '_reports': reports, '_retain': retain}[sys.argv[1]](sys.argv[2:]); return
    driver = Driver()
    try:
        {'prepare': driver.prepare, 'execute': driver.execute, 'cleanup': driver.cleanup}[sys.argv[1]]()
    except Exception as error:
        driver.state['error'] = str(error); driver.state['complete'] = False; driver.save(); raise

if __name__ == '__main__':
    try: main()
    except Exception as error: print('Qualification refused: ' + str(error), file=sys.stderr); sys.exit(1)

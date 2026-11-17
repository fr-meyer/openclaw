"""Future privileged ephemeral-CI bootstrap. Import/constructor are inert.
Only injected FakeOps may be exercised under the current source-only approval.
"""
import hashlib
import json
import os
import pathlib
import re
import selectors
import stat
import subprocess
import time
import tomllib

GIB = 1024 ** 3
CAP = 12 * GIB
FLOOR = 8 * GIB
RAM = 6 * GIB
PID = 512
CURRENT_DIRECTION = '05a6409d1e19e9298a254d15a5c92c5522ba3e5a2cac998fc44328408a548240'

class Unverified(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise Unverified(message)


class BoundedEngineDomain:
    def __init__(self, scope, ops=None):
        self.scope = dict(scope)
        self.ops = ops if ops is not None else LinuxOps()
        self.state = 'NEW'
        self.handle = None
        self.sequence = 0
        self.busy = False
        self.failure = None
        self.deadline = None

    def open(self):
        require(self.state == 'NEW', 'one-shot domain')
        self.state = 'OPENING'
        self.deadline = self.ops.clock() + 2700
        try:
            require(self.scope.get('capacity_bytes') == CAP, 'fixed 12GiB capacity')
            require(self.scope.get('outside_allowance_bytes', 0) >= 128 * 1024 ** 2,
                    'explicit outside allowance required')
            self.ops.admit(self.scope)
            # handle is recorded before any resource mutation; partial cleanup has identity.
            self.handle = self.ops.claim(self.scope)
            self.ops.provision(self.handle)
            self.ops.start_engine(self.handle)
            self.state = 'OPEN'
            return self.snapshot()
        except BaseException:
            self.abort('open failed')
            raise

    def engine_env(self):
        require(self.state == 'OPEN', 'domain not open')
        return self.ops.environment(self.handle)

    def snapshot(self):
        require(self.state in ('OPEN', 'OPENING'), 'domain not observable')
        require(self.ops.clock() < self.deadline, 'whole domain monitored 45-minute deadline')
        r = self.ops.observe(self.handle)
        require(r['identity'] == self.handle['identity'], 'domain identity drift')
        require(r['capacity_bytes'] == CAP and r['backing_allocated'] >= CAP,
                'capacity/reservation drift')
        require(r['cpu_max'] == '200000 100000' and r['memory_max'] == RAM
                and r['swap_max'] == 0 and r['pids_max'] == PID, 'aggregate limits drift')
        require(r['complete_domain'] and r['engine_backend'] == 'overlay2',
                'unsupported physical storage domain')
        require(r['free_bytes'] >= FLOOR, 'monitored host free floor')
        require(r['used_bytes'] <= CAP and r['image_bytes'] <= 8 * GIB,
                'monitored image allocation threshold')
        require(r['context_bytes'] <= 2 * GIB, 'monitored context allocation threshold')
        self.sequence += 1
        return dict(r, sequence=self.sequence,
                    hard_capacity_bytes=CAP, thresholds_are_hard_quotas=False)

    def run_phase(self, label, argv, timeout_seconds, output_limit_bytes):
        require(self.state == 'OPEN' and not self.busy, 'phase overlap/state')
        require(type(argv) is list and argv and all(type(a) is str and chr(0) not in a for a in argv),
                'argv must be explicit strings')
        require(type(label) is str and re.fullmatch(r'[a-z0-9-]{1,64}', label), 'phase label')
        require(0 < timeout_seconds <= 2700 and 0 < output_limit_bytes <= 64 * 1024 ** 2,
                'finite command/output bounds')
        self.busy = True
        try:
            self.snapshot()
            proc = self.ops.launch(self.handle, argv)
            out, err = bytearray(), bytearray()
            deadline = self.ops.clock() + timeout_seconds
            while True:
                self.snapshot()  # daemon AND caller, including pull/import/COPY
                require(self.ops.clock() < deadline, 'phase deadline')
                a, b, done, code = self.ops.poll(proc, .10)
                require(len(out) + len(err) + len(a) + len(b) <= output_limit_bytes,
                        'phase output limit')
                out.extend(a)
                err.extend(b)
                if done:
                    break
            require(code == 0, 'phase nonzero exit: ' + str(code))
            self.ops.phase_terminal(self.handle, proc)
            receipt = self.snapshot()
            return {'exit_code': code, 'stdout': out.decode('utf-8', 'replace'),
                    'stderr': err.decode('utf-8', 'replace'), 'receipt': receipt}
        except BaseException:
            self.abort('phase failed: ' + label)
            raise
        finally:
            self.busy = False

    def abort(self, reason):
        if self.state == 'CLOSED':
            return {'status': 'CLOSED', 'absent': True}
        self.failure = str(reason)[:128]
        self.state = 'STOPPING'
        if self.handle is None:
            self.state = 'FAILED'
            return {'status': 'NO_RESOURCE', 'absent': True}
        try:
            self.ops.stop_writers(self.handle)
            self.ops.reconcile(self.handle)
            require(self.ops.writers_absent(self.handle), 'owned writers still populated')
            require(self.ops.mount_users_absent(self.handle), 'mount users unverified')
            self.state = 'TERMINAL'
            return {'status': 'TERMINAL', 'absent': True, 'reservation_retained': True}
        except BaseException as e:
            self.state = 'UNVERIFIED'
            raise Unverified('UNVERIFIED: reservation retained; ' + str(e)) from e

    def close(self):
        if self.state == 'CLOSED':
            return {'status': 'CLOSED', 'absent': True}
        # No cleanup under unknown writers, including partial open failures.
        self.abort(self.failure or 'normal close')
        try:
            if self.handle is not None:
                self.ops.cleanup(self.handle)
        except BaseException as e:
            self.state = 'UNVERIFIED'
            raise Unverified('UNVERIFIED cleanup; reservation retained where possible') from e
        self.state = 'CLOSED'
        return {'status': 'CLOSED', 'absent': True}


class LinuxOps:
    """Root-only future adapter; no privilege escalation and no shell invocation.

    Caller must be the dedicated trusted bootstrap process, never the candidate.
    Trusted tool paths/hashes and runtime authority are supplied out-of-band.
    """
    def __init__(self):
        self.s = None
        self.children = []

    @staticmethod
    def clock():
        return time.monotonic()

    @staticmethod
    def read(path):
        return pathlib.Path(path).read_text().strip()

    @staticmethod
    def put(path, value):
        pathlib.Path(path).write_text(str(value))

    @staticmethod
    def ident(path):
        v = os.lstat(path)
        require(not stat.S_ISLNK(v.st_mode), 'symlink identity')
        return [v.st_dev, v.st_ino]

    def admit(self, s):
        require(os.geteuid() == 0, 'future invocation must already have exact root authority')
        require(len(list(pathlib.Path('/proc/self/task').iterdir())) == 1, 'dedicated single-thread supervisor')
        require(not self.read('/proc/self/task/' + str(os.getpid()) + '/children'), 'no inherited children')
        require(re.fullmatch(r'[a-f0-9]{32}', s.get('nonce', '')), 'nonce')
        auth = pathlib.Path(s['runtime_authorization_path'])
        st = auth.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_mode & 0o022 == 0,
                'authority custody')
        raw = auth.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        require(digest == s['runtime_authorization_sha256'] and digest != CURRENT_DIRECTION,
                'separate exact future authority required')
        a = json.loads(raw)
        require(a['bootstrap_sha256'] == hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
                'authority must bind exact bootstrap source')
        self.authority = a
        require(a['operation'] == 'ephemeral-ci-bounded-engine' and a['nonce'] == s['nonce']
                and a['expires_epoch'] > time.time() and a['capacity_bytes'] == CAP
                and a['root'] == s['root'] and a['tools'] == s['tools']
                and a['worker'] == s['worker'], 'authority scope')
        require(s['runner_provenance'] == a['runner_provenance'] and s['runner_provenance'],
                'external trusted runner provenance required')
        require(a['outside_allowance_bytes'] == s['outside_allowance_bytes'], 'outside allowance')
        self.s = s
        self.tools = {}
        for name in ('python', 'docker', 'dockerd', 'mkfs', 'losetup', 'mount', 'umount'):
            item = s['tools'][name]
            path = pathlib.Path(item['path'])
            require(path.is_absolute() and path.resolve() == path and path.is_file(), 'tool path')
            require(path.stat().st_uid == 0 and path.stat().st_mode & 0o022 == 0, 'tool custody')
            require(hashlib.sha256(path.read_bytes()).hexdigest() == item['sha256'], 'tool pin')
            self.tools[name] = str(path)
        root = pathlib.Path(s['root'])
        require(root.is_absolute() and root.parent.resolve() == root.parent
                and not root.exists() and not root.is_symlink(), 'exclusive root')
        # Strict supported host: real ext4, not overlay/COW/nested mounts.
        mount = self.covering_mount(root.parent)
        require(mount['type'] == 'ext4', 'non-COW ext4 host backing required')
        require(os.statvfs(root.parent).f_frsize == 4096, 'outside metadata bound requires ext4 4KiB')
        require(self.free(root.parent) >= CAP + FLOOR + s['outside_allowance_bytes'],
                'reservation + floor + explicit allowance')
        cg = pathlib.Path('/sys/fs/cgroup')
        require((cg / 'cgroup.controllers').exists(), 'unified cgroup v2 required')
        require({'cpu', 'memory', 'pids'} <= set(self.read(cg / 'cgroup.subtree_control').split()),
                'required controllers must already be delegated; no root controller config edits')
        self.original_cgroup = self.read('/proc/self/cgroup').split('0::', 1)[1]
        require(self.original_cgroup.startswith('/'), 'supervisor original cgroup')

    @staticmethod
    def mounts():
        rows = []
        for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines():
            a, b = line.split(' - ', 1)
            v, w = a.split(), b.split()
            # Reject escaped pathname support rather than misparse it.
            require(chr(92) not in v[4], 'unsupported escaped mount pathname')
            rows.append({'id': int(v[0]), 'device': v[2], 'path': v[4],
                         'type': w[0], 'source': w[1]})
        return rows

    def covering_mount(self, path):
        p = str(path)
        rows = [r for r in self.mounts() if p == r['path'] or p.startswith(r['path'].rstrip('/') + '/')]
        return max(rows, key=lambda r: len(r['path']))

    @staticmethod
    def free(path):
        v = os.statvfs(path)
        return v.f_bavail * v.f_frsize

    def claim(self, s):
        r = pathlib.Path(s['root'])
        # cgroup namespace/name and inode are pinned before use.
        cg = pathlib.Path('/sys/fs/cgroup') / ('oc-' + s['nonce'])
        require(not cg.exists(), 'preexisting cgroup')
        r.mkdir(mode=0o700)
        return {'root': str(r), 'identity': self.ident(r), 'cg': str(cg),
                'cg_identity': None, 'loop': None, 'mount_identity': None,
                'engine': None, 'engine_log_bytes': 0, 'socket_identity': None, 'backing_identity': None,
                'original_cgroup': self.original_cgroup}

    def verify(self, h):
        require(self.ident(h['root']) == h['identity'], 'root replaced')
        if h['cg_identity'] is not None:
            require(self.ident(h['cg']) == h['cg_identity'], 'cgroup replaced')
        if h['backing_identity'] is not None:
            backing = pathlib.Path(h['root']) / 'capacity.img'
            require(self.ident(backing) == h['backing_identity'], 'backing replaced')
            require(backing.stat().st_size == CAP, 'backing capacity drift')

    def provision(self, h):
        self.verify(h)
        cg = pathlib.Path(h['cg'])
        cg.mkdir()
        h['cg_identity'] = self.ident(cg)
        self.put(cg / 'cpu.max', '200000 100000')
        self.put(cg / 'memory.max', RAM)
        self.put(cg / 'memory.swap.max', 0)
        self.put(cg / 'pids.max', PID)
        self.put(cg / 'cgroup.subtree_control', '+cpu +memory +pids')
        for leaf in ('observer', 'writers'):
            (cg / leaf).mkdir()
        self.put(cg / 'observer/cgroup.procs', os.getpid())
        self.put(cg / 'writers/cgroup.subtree_control', '+cpu +memory +pids')
        (cg / 'writers/daemon').mkdir()
        (cg / 'writers/clients').mkdir()
        self.check_limits(h)
        path = pathlib.Path(h['root']) / 'capacity.img'
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        h['backing_identity'] = self.ident(path)
        try:
            os.posix_fallocate(fd, 0, CAP)
            os.fsync(fd)
            v = os.fstat(fd)
            require(v.st_size == CAP and v.st_blocks * 512 >= CAP, 'fully allocated reservation')
            h['backing_identity'] = [v.st_dev, v.st_ino]
        finally:
            os.close(fd)
        self.command(h, [self.tools['mkfs'], '-t', 'ext4', '-F', '-m', '0',
                         '-E', 'nodiscard,lazy_itable_init=0,lazy_journal_init=0', str(path)], 120)
        loop = self.command(h, [self.tools['losetup'], '--find', '--show', '--nooverlap', str(path)], 10).strip()
        require(re.fullmatch(r'/dev/loop[0-9]+', loop), 'loop identity')
        h['loop'] = loop
        mount = pathlib.Path(h['root']) / 'fs'
        mount.mkdir(mode=0o700)
        self.command(h, [self.tools['mount'], '-t', 'ext4', '-o', 'nodev,nosuid', loop, str(mount)], 10)
        m = self.covering_mount(mount)
        require(m['path'] == str(mount) and m['source'] == loop and m['type'] == 'ext4', 'owned mount')
        h['mount_identity'] = m
        # Every disk-backed mutable engine path is inside the fixed filesystem.
        for name in ('data', 'exec', 'tmp', 'home', 'context', 'config', 'logs'):
            (mount / name).mkdir(mode=0o700)
        (mount / 'daemon.json').write_text('{}')
        self.validate_mounts(h)

    def check_limits(self, h):
        c = pathlib.Path(h['cg'])
        require(self.read(c / 'cpu.max') == '200000 100000'
                and int(self.read(c / 'memory.max')) == RAM
                and int(self.read(c / 'memory.swap.max')) == 0
                and int(self.read(c / 'pids.max')) == PID, 'actual aggregate caps before exec')

    def environment(self, h):
        r = pathlib.Path(h['root']) / 'fs'
        return {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
                'HOME': str(r / 'home'), 'TMPDIR': str(r / 'tmp'),
                'DOCKER_CONFIG': str(r / 'config'), 'DOCKER_HOST': 'unix://' + str(r / 'docker.sock'),
                'XDG_CACHE_HOME': str(r / 'home/cache'), 'XDG_CONFIG_HOME': str(r / 'home/config'),
                'XDG_RUNTIME_DIR': str(r / 'exec'),
                'OPENCLAW_CI_DOMAIN_CONTEXT': str(r / 'context'),
                'OPENCLAW_CI_DOMAIN_ROOT': str(r), 'PYTHONDONTWRITEBYTECODE': '1'}

    def spawn(self, h, argv, daemon=False):
        self.verify(h)
        self.check_limits(h)
        cleanup_only = ((argv[0] == self.tools['umount'] and argv[1:] == [h['root'] + '/fs'])
                        or (argv[0] == self.tools['losetup'] and argv[1:] == ['--detach', h['loop']]))
        require(cleanup_only or time.time() < self.authority['expires_epoch'], 'runtime authority expired')
        # No arbitrary executables. Full command semantics remain pinned trusted integrator's duty.
        require(argv[0] in self.tools.values(), 'unapproved executable')
        leaf = pathlib.Path(h['cg']) / 'writers' / ('daemon' if daemon else 'clients')
        path_identities = () if cleanup_only else tuple(h.get('phase_path_identities', ()))
        local_paths = () if cleanup_only else tuple(h.get('phase_local_paths', ()))
        def before_exec():
            self.verify(h)
            for value in local_paths:
                path = pathlib.Path(value)
                require(path.resolve(strict=False) == path, 'local path symlink drift before exec')
            for path, identity in path_identities:
                require(self.ident(path) == identity, 'local path ancestor identity drift before exec')
            self.put(leaf / 'cgroup.procs', os.getpid())
            actual = self.read('/proc/self/cgroup').split('0::', 1)[1]
            require(actual == str(leaf).removeprefix('/sys/fs/cgroup'), 'membership before exec')
            self.check_limits(h)
            # umount must not make its own cwd a user of the filesystem being removed.
            cwd = pathlib.Path(h['root'])
            if not cleanup_only and h['mount_identity']:
                cwd = cwd / 'fs'
            os.chdir(cwd)
        # Trusted single-threaded supervisor only; no shell, no inherited descriptors.
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=self.environment(h), close_fds=True,
                             preexec_fn=before_exec)
        self.children.append(p)
        sel = selectors.DefaultSelector()
        for stream, label in ((p.stdout, 'out'), (p.stderr, 'err')):
            os.set_blocking(stream.fileno(), False)
            sel.register(stream, selectors.EVENT_READ, label)
        return {'p': p, 'selector': sel}

    def launch(self, h, argv):
        h['phase_path_identities'] = []
        h['phase_local_paths'] = []
        if argv[0] == self.tools['python']:
            worker = self.s['worker']
            relative = pathlib.PurePosixPath(worker['relative_path'])
            require(not relative.is_absolute() and '..' not in relative.parts
                    and relative.parts[0] == 'trusted', 'trusted worker relative path')
            path = pathlib.Path(h['root']) / 'fs/context' / str(relative)
            require(path.resolve() == path and path.is_file(), 'canonical trusted worker')
            require(argv[1:5] == ['-I', '-S', '-B', str(path)], 'fixed isolated trusted worker prefix')
            require(hashlib.sha256(path.read_bytes()).hexdigest() == worker['sha256'], 'worker source pin')
            return self.spawn(h, argv)
        require(argv[0] == self.tools['docker'], 'phase executable must be pinned Docker client')
        require(len(argv) > 1 and argv[1] in ('pull', 'create', 'start', 'inspect', 'wait',
                'kill', 'rm', 'cp', 'commit', 'import', 'image', 'info'), 'phase operation')
        require(not any(x.startswith(('--host', '--context', '--config', '-H='))
                        or x in ('-H', '-c') for x in argv[1:]), 'engine endpoint override')
        self.validate_phase(h, argv)
        return self.spawn(h, argv)

    def poll(self, proc, interval):
        out, err = bytearray(), bytearray()
        for key, _ in proc['selector'].select(interval):
            b = os.read(key.fileobj.fileno(), 65536)
            if not b:
                proc['selector'].unregister(key.fileobj)
                key.fileobj.close()
            elif key.data == 'out':
                out.extend(b)
            else:
                err.extend(b)
        done = proc['p'].poll() is not None and not proc['selector'].get_map()
        if done:
            proc['selector'].close()
        return bytes(out), bytes(err), done, proc['p'].returncode

    def command(self, h, argv, timeout):
        p = self.spawn(h, argv)
        end = time.monotonic() + timeout
        data = bytearray()
        total = 0
        while True:
            require(time.monotonic() < end, 'setup command deadline')
            a, b, done, code = self.poll(p, .10)
            total += len(a) + len(b)
            require(total <= 1024 ** 2, 'setup output bound')
            data.extend(a)
            # setup stderr intentionally not mixed into parseable stdout
            if done:
                require(code == 0, 'setup command failed')
                return data.decode('utf-8', 'strict')

    def start_engine(self, h):
        r = pathlib.Path(h['root']) / 'fs'
        args = [self.tools['dockerd'], '--config-file=' + str(r / 'daemon.json'),
                '--host=unix://' + str(r / 'docker.sock'), '--data-root=' + str(r / 'data'),
                '--exec-root=' + str(r / 'exec'), '--pidfile=' + str(r / 'dockerd.pid'),
                '--storage-driver=overlay2', '--exec-opt=native.cgroupdriver=cgroupfs',
                '--cgroup-parent=' + str(pathlib.Path(h['cg']) / 'writers').removeprefix('/sys/fs/cgroup'),
                '--bridge=none', '--iptables=false', '--ip-forward=false', '--ip-masq=false',
                '--log-driver=none', '--userland-proxy=false', '--log-level=error']
        h['engine'] = self.spawn(h, args, daemon=True)
        end = time.monotonic() + 30
        while time.monotonic() < end:
            a, b, done, code = self.poll(h['engine'], .1)
            h['engine_log_bytes'] += len(a) + len(b)
            require(not done and h['engine_log_bytes'] <= 1024 ** 2, 'daemon termination/log limit')
            # Bounded logs are drained, never retained in an unbounded host file.
            sock = r / 'docker.sock'
            if sock.exists():
                require(stat.S_ISSOCK(sock.stat().st_mode), 'engine socket')
                h['socket_identity'] = self.ident(sock)
                info = json.loads(self.command(h, [self.tools['docker'], 'info', '--format', '{{json .}}'], 5))
                require(info['Driver'] == 'overlay2' and info['DockerRootDir'] == str(r / 'data'), 'backend root')
                require(not any('snapshotter' in str(x).lower() or 'containerd' in str(x).lower()
                                for x in info.get('DriverStatus', [])), 'containerd image store unsupported')
                h['engine_info'] = info
                return
        raise Unverified('isolated engine readiness deadline')

    def validate_mounts(self, h):
        m = h['mount_identity']
        if m is None:
            return
        rows = self.mounts()
        require(m in rows, 'mount identity replaced')
        for row in rows:
            if row['path'].startswith(m['path'] + '/'):
                require(row['type'] == 'overlay' and row['path'].startswith(m['path'] + '/data/overlay2/'),
                        'unaccounted nested mount')

    @staticmethod
    def allocated_tree(root):
        # Never follow symlinks, never traverse mounted merged views; all metadata/deleted-open
        # allocation is separately captured by filesystem used blocks.
        total, seen = 0, set()
        if not root.exists():
            return 0
        device = root.stat().st_dev
        for parent, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if os.lstat(pathlib.Path(parent) / d).st_dev == device
                       and not pathlib.Path(parent, d).is_symlink()]
            for name in files:
                s = os.lstat(pathlib.Path(parent) / name)
                key = (s.st_dev, s.st_ino)
                if key not in seen and s.st_dev == device:
                    seen.add(key)
                    total += s.st_blocks * 512
        return total

    def observe(self, h):
        self.verify(h)
        self.check_limits(h)
        require(time.time() < self.authority['expires_epoch'], 'runtime authority expired')
        self.reconcile(h)
        self.validate_mounts(h)
        self.observe_containerd(h)
        r = pathlib.Path(h['root']) / 'fs'
        require(self.ident(r / 'docker.sock') == h['socket_identity'], 'socket replaced')
        engine = h['engine']
        a, b, done, _ = self.poll(engine, 0)
        h['engine_log_bytes'] += len(a) + len(b)
        require(not done and h['engine_log_bytes'] <= 1024 ** 2, 'engine termination/log fault')
        events = dict(line.split() for line in self.read(pathlib.Path(h['cg']) / 'memory.events').splitlines())
        require(int(events.get('oom_kill', 0)) == 0, 'aggregate OOM kill')
        v = os.statvfs(r)
        c = pathlib.Path(h['cg'])
        return {'identity': h['identity'], 'capacity_bytes': CAP,
                'backing_allocated': os.stat(pathlib.Path(h['root']) / 'capacity.img').st_blocks * 512,
                'cpu_max': self.read(c / 'cpu.max'), 'memory_max': int(self.read(c / 'memory.max')),
                'swap_max': int(self.read(c / 'memory.swap.max')), 'pids_max': int(self.read(c / 'pids.max')),
                'complete_domain': True, 'engine_backend': h['engine_info']['Driver'],
                'used_bytes': (v.f_blocks - v.f_bfree) * v.f_frsize,
                # Whole filesystem is conservative image-domain accounting, not a root-only du.
                'image_bytes': (v.f_blocks - v.f_bfree) * v.f_frsize,
                'context_bytes': self.allocated_tree(r / 'context'), 'free_bytes': self.free(h['root']),
                'mount': h['mount_identity'], 'cgroup_identity': h['cg_identity'],
                'containerd_roots': h['containerd_roots'],
                'context_path': str(r / 'context'), 'filesystem_path': str(r),
                'engine_socket': str(r / 'docker.sock')}

    def phase_terminal(self, h, proc):
        require(proc['p'].poll() == 0, 'client not terminal')
        # Client success is not daemon quiescence. Engine remains owned and bounded through close.
        clients = pathlib.Path(h['cg']) / 'writers/clients/cgroup.events'
        require('populated 0' in self.read(clients).splitlines(), 'client descendants survive')

    def stop_writers(self, h):
        self.verify(h)
        if h['cg_identity'] is None:
            return
        cg = pathlib.Path(h['cg']) / 'writers'
        if cg.exists():
            self.put(cg / 'cgroup.kill', 1)
        end = time.monotonic() + 10
        while time.monotonic() < end:
            for p in self.children:
                p.poll()
            if self.writers_absent(h):
                return
            time.sleep(.05)
        raise Unverified('whole writer termination deadline')

    def writers_absent(self, h):
        self.verify(h)
        cg = pathlib.Path(h['cg']) / 'writers'
        return (not cg.exists() or 'populated 0' in self.read(cg / 'cgroup.events').splitlines()) and all(
            p.poll() is not None for p in self.children)

    def mount_users_absent(self, h):
        self.verify(h)
        if h['mount_identity'] is None:
            return True
        device = os.stat(pathlib.Path(h['root']) / 'fs').st_dev
        # Scan all accessible processes, deny on inaccessible metadata. Includes deleted-open FDs.
        for proc in pathlib.Path('/proc').iterdir():
            if not proc.name.isdigit():
                continue
            try:
                for item in [proc / 'cwd', proc / 'root', proc / 'exe', *list((proc / 'fd').iterdir())]:
                    try:
                        if item.stat().st_dev == device:
                            return False
                    except FileNotFoundError:
                        pass
                for line in (proc / 'maps').read_text().splitlines():
                    fields = line.split()
                    if len(fields) > 3:
                        major, minor = (int(x, 16) for x in fields[3].split(':'))
                        if os.makedev(major, minor) == device:
                            return False
            except (FileNotFoundError, ProcessLookupError):
                continue
            except PermissionError as e:
                raise Unverified('inaccessible process mount-user census') from e
        return True

    def cleanup(self, h):
        self.verify(h)
        self.reconcile(h)
        require(self.writers_absent(h) and self.mount_users_absent(h), 'cleanup absence gate')
        # Cleanup helpers must still execute beneath aggregate limits. Recreate clients leaf only.
        r = pathlib.Path(h['root'])
        if h['mount_identity'] is not None:
            self.validate_mounts(h)
            self.command(h, [self.tools['umount'], str(r / 'fs')], 10)
            require(not any(m['id'] == h['mount_identity']['id'] for m in self.mounts()), 'mount persists')
            h['mount_identity'] = None
        if h['loop']:
            self.command(h, [self.tools['losetup'], '--detach', h['loop']], 10)
            h['loop'] = None
        self.reconcile(h)
        require(self.writers_absent(h), 'cleanup helper descendants')
        cg = pathlib.Path(h['cg'])
        if h['cg_identity'] is not None:
            writers = cg / 'writers'
            for parent, dirs, files in os.walk(writers, topdown=False):
                node = pathlib.Path(parent)
                require('populated 0' in self.read(node / 'cgroup.events').splitlines(),
                        'cgroup became populated during cleanup')
                node.rmdir()
        if h['backing_identity'] is not None:
            self.verify(h)
            (r / 'capacity.img').unlink()
            h['backing_identity'] = None
        if h['cg_identity'] is not None:
            self.put(pathlib.Path('/sys/fs/cgroup' + h['original_cgroup']) / 'cgroup.procs', os.getpid())
            (cg / 'observer').rmdir()
            cg.rmdir()
        # Keep bounded root receipt directory, never recursive delete arbitrary paths.

    def reconcile(self, h):
        """Discover owned partial loop/mount effects after kill, never guess absence."""
        self.verify(h)
        backing = pathlib.Path(h['root']) / 'capacity.img'
        loops = []
        if backing.exists():
            for item in pathlib.Path('/sys/block').glob('loop*/loop/backing_file'):
                raw = item.read_text().strip()
                path = pathlib.Path('/' + raw.lstrip('/'))
                try:
                    if self.ident(path) == h['backing_identity']:
                        loops.append('/dev/' + item.parent.parent.name)
                except FileNotFoundError:
                    continue
        require(len(loops) <= 1, 'ambiguous loop backing owners')
        if h['loop'] is not None:
            require(loops == [h['loop']], 'loop identity drift')
        elif loops:
            h['loop'] = loops[0]
        if h['loop'] is not None:
            size = pathlib.Path('/sys/block') / pathlib.Path(h['loop']).name / 'size'
            require(int(self.read(size)) * 512 == CAP, 'loop capacity drift')
        target = str(pathlib.Path(h['root']) / 'fs')
        rows = [m for m in self.mounts() if m['path'] == target]
        require(len(rows) <= 1, 'stacked owned mounts unsupported')
        if rows:
            require(rows[0]['source'] == h['loop'] and rows[0]['type'] == 'ext4',
                    'unexpected mount at owned target')
            if h['mount_identity'] is not None:
                require(rows[0] == h['mount_identity'], 'owned mount changed')
            else:
                h['mount_identity'] = rows[0]
        else:
            require(h['mount_identity'] is None, 'owned mount vanished unexpectedly')

    def validate_phase(self, h, argv):
        # Standalone Docker transport supports long options only; no attached short/alias forms.
        require(not any(a.startswith('-') and not a.startswith('--') for a in argv[2:]),
                'unsupported short option syntax')
        banned = ('--privileged', '--device', '--cgroup-parent', '--pid', '--cgroupns',
                  '--volume', '-v', '--volumes-from', '--cap-add',
                  '--ipc=host', '--uts=host')
        require(not any(any(a == flag or a.startswith(flag + '=')
                            for flag in banned) for a in argv[2:]), 'unsafe phase option')
        for i, arg in enumerate(argv[2:], 2):
            if arg == '--security-opt' or arg.startswith('--security-opt='):
                value = argv[i + 1] if arg == '--security-opt' else arg.split('=', 1)[1]
                require(value in ('no-new-privileges', 'no-new-privileges:true'), 'security relaxation')
        if argv[1] == 'pull':
            require(re.fullmatch(r'[^ ]+@sha256:[a-f0-9]{64}', argv[-1]), 'pull requires immutable digest')
        if argv[1] == 'image':
            require(len(argv) > 2 and argv[2] in ('inspect', 'rm', 'ls'), 'unbounded image operation')
        for i, arg in enumerate(argv[2:], 2):
            if arg == '--mount' or arg.startswith('--mount='):
                value = argv[i + 1] if arg == '--mount' else arg.split('=', 1)[1]
                fields = dict(x.split('=', 1) for x in value.split(',') if '=' in x)
                source = fields.get('source', fields.get('src', ''))
                require(fields.get('type') == 'bind', 'only explicit bind mount syntax supported')
                self.local_path(h, source, pathlib.Path(h['root']) / 'fs/context', allow_base=True)
        if argv[1] == 'cp':
            require(len(argv) == 4 and not any(a.startswith('-') for a in argv[2:]), 'cp shape')
            local = [a for a in argv[2:] if ':' not in a]
            remote = [a for a in argv[2:] if ':' in a]
            require(len(local) == len(remote) == 1
                    and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}:/.*', remote[0]), 'cp endpoints')
            self.local_path(h, local[0])
        if argv[1] == 'import':
            require(len(argv) in (3, 4), 'import shape')
            self.local_path(h, argv[2])

    def local_path(self, h, value, base=None, allow_base=False):
        """Component containment, no symlink ancestors, pinned again in the exec barrier.
        Missing final destinations are supported, never lexical '..' or symlink aliases.
        """
        p = pathlib.Path(value)
        base = pathlib.Path(h['root']) / 'fs' if base is None else base
        require(p.is_absolute() and '..' not in p.parts and (allow_base or p != base),
                'noncanonical local path')
        try:
            p.relative_to(base)
        except ValueError as e:
            raise Unverified('local path outside owned domain') from e
        require(p.resolve(strict=False) == p and base.resolve(strict=False) == base,
                'local path symlink/ancestor escape')
        h.setdefault('phase_local_paths', []).append(str(p))
        identities = h.setdefault('phase_path_identities', [])
        # Record all existing components, including owned root and intermediate ancestors.
        for ancestor in reversed((p, *p.parents)):
            try:
                identities.append((str(ancestor), self.ident(ancestor)))
            except FileNotFoundError:
                continue
        return p

    def observe_containerd(self, h):
        """Validate the actual managed containerd config, process and storage roots.
        Root/state outside this exact private daemon layout are unsupported.
        """
        r = pathlib.Path(h['root']) / 'fs'
        config = r / 'exec/containerd/containerd.toml'
        require(config.resolve() == config and config.is_file(), 'managed containerd config absent')
        raw = config.read_bytes()
        require(len(raw) <= 65536, 'containerd config byte bound')
        parsed = tomllib.loads(raw.decode('utf-8'))
        root, state = parsed.get('root'), parsed.get('state')
        require(root == str(r / 'data/containerd/daemon')
                and state == str(r / 'exec/containerd/daemon'), 'unaccounted containerd storage')
        for value in (root, state):
            require(pathlib.Path(value).resolve() == pathlib.Path(value), 'containerd root symlink')
        # No external containerd endpoint may be substituted for the managed process.
        found = []
        prefix = str(pathlib.Path(h['cg']) / 'writers').removeprefix('/sys/fs/cgroup')
        for proc in pathlib.Path('/proc').iterdir():
            if not proc.name.isdigit():
                continue
            try:
                member = (proc / 'cgroup').read_text().split('0::', 1)[1].strip()
                if member != prefix and not member.startswith(prefix + '/'):
                    continue
                argv = (proc / 'cmdline').read_bytes().split(bytes([0]))
                if argv and pathlib.Path(os.fsdecode(argv[0])).name == 'containerd':
                    require(os.fsencode(str(config)) in argv, 'managed containerd config mismatch')
                    found.append(int(proc.name))
            except (FileNotFoundError, ProcessLookupError):
                continue
        require(len(found) == 1, 'actual managed containerd identity ambiguous')
        h['containerd_roots'] = {'root': root, 'state': state,
                                'config_sha256': hashlib.sha256(raw).hexdigest(), 'pids': found}

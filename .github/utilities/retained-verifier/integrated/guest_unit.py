"""Fixed systemd/collector/evidence component for one retained-verifier unit.

Import and CLI issue no native authority. Native IO is authored here but cannot
bind under the current synthetic-only native_authority gate. One collector is
kept alive across before/start/ready/capture. No caller path, shell or argv API
is exposed, and all observations remain private until Mac custody/replay.
"""
from __future__ import annotations

import copy
import datetime as dt
import math
import os
from pathlib import Path
import re
import stat
import sys
import time

import controller
import host_admission
import native_authority
import probe
import profile
import protocol
import worker
from protocol import Refusal, canonical, closed, decode, require, sha, stamp, utc

HERE = Path(__file__).resolve().parent
HELPER_SHA256 = '0039f448059652d87fdfe49cf2de875a38bfe2224c2711c17cc2c837f9c7c88a'
STREAM_CAP = 65536
READY_CAP = 4096
SNAPSHOT_CAP = 2 * 1024 * 1024
STATE_KEYS = ('LoadState','ActiveState','SubState','Result','ExecMainCode',
              'ExecMainStatus','MainPID','InvocationID','ControlGroup')
OWNERSHIP_KEYS = ('RootDirectory','User','Group','DynamicUser')
_INTENTS = frozenset(('start','observe','ready','wait','stop','cgroup','evidence'))
TOOL_PATHS = ('/usr/bin/systemd-run','/usr/bin/systemctl','/usr/bin/busctl',
              '/usr/sbin/selinuxenabled')


def _hex(value, width=64):
    return type(value) is str and re.fullmatch('[0-9a-f]{'+str(width)+'}',value) is not None


def _tool_pins(capability):
    tools=capability.pins.get('unitTools')
    require(type(tools) is dict and set(tools)==set(TOOL_PATHS) and
            all(_hex(v) for v in tools.values()), 'unit.tools_unbound')
    require(_hex(capability.pins.get('selinuxToolSha256')) and
            capability.pins['selinuxToolSha256']==tools['/usr/sbin/selinuxenabled']==
                host_admission.SELINUX_TOOL_SHA256, 'unit.selinux_source_pin')
    return tools


def _props(raw, capability):
    require(type(raw) is bytes and sha(raw) == profile.DESIGN_PROFILE_SHA,
            'unit.profile_pin')
    props = profile.properties(raw, capability.owner['sessionId'], str(capability.session_root))
    require(len(props) == 55 and len({v.split('=',1)[0] for v in props}) == 55 and
            all(type(v) is str and '\x00' not in v and '\n' not in v for v in props),
            'unit.profile_roster')
    required = ('Type=exec','DynamicUser=yes','MountFlags=private','PrivateNetwork=yes',
        'PrivateIPC=yes','NoNewPrivileges=yes','CapabilityBoundingSet=',
        'AmbientCapabilities=','KillMode=control-group','Restart=no','RuntimeMaxSec=300',
        'MemoryMax=2147483648','MemorySwapMax=0','TasksMax=64','CPUQuota=100%')
    require(all(props.count(v) == 1 for v in required) and
            props.count('RootDirectory='+str(capability.session_root/'root')) == 1 and
            props.count('ExecStart=/code/static-entry ocv-'+capability.owner['sessionId'][:24]) == 1,
            'unit.profile_required')
    return tuple(props)


def _ready(raw, context):
    require(type(raw) is bytes and 0 < len(raw) <= READY_CAP, 'unit.ready_cap')
    value = closed(decode(raw, READY_CAP), {'schema','status','pid','uid','gid',
                    'contextSha256','workerSha256'}, 'unit.ready_schema')
    require(value['schema'] == 'openclaw.retained-verifier-ready.v1' and
            value['status'] == 'ready' and type(value['pid']) is int and value['pid'] > 1 and
            type(value['uid']) is int and 61184 <= value['uid'] <= 65519 and
            type(value['gid']) is int and 61184 <= value['gid'] <= 65519 and
            value['contextSha256'] == sha(canonical(context)) and
            value['workerSha256'] == context['workerSha256'], 'unit.ready_binding')
    return value


def _find_ready(raw, context):
    require(type(raw) is bytes and len(raw) <= STREAM_CAP, 'unit.ready_stream_cap')
    lines=raw.splitlines(keepends=True)
    require(len(lines)<=16,'unit.ready_frame_count')
    records=[]
    for line in lines:
        if not line.endswith(b'\n'):continue
        require(len(line)<=READY_CAP,'unit.ready_frame_cap')
        try:value=decode(line,READY_CAP)
        except Refusal:raise Refusal('unit.pre_ready_stderr') from None
        if type(value) is dict and value.get('schema')=='openclaw.retained-verifier-worker-final.v1':
            raise Refusal('unit.worker_returned_before_gate')
        if type(value) is dict and value.get('schema')=='openclaw.retained-verifier-ready.v1':
            records.append(line)
        else:raise Refusal('unit.pre_ready_stderr')
    require(len(records)<=1,'unit.duplicate_ready')
    if not records:return None
    require(lines[-1].endswith(b'\n'),'unit.pre_ready_partial_tail')
    _ready(records[0],context)
    return records[0]


def _state(value):
    closed(value, STATE_KEYS, 'unit.state_schema')
    require(all(type(v) is str and len(v) <= 256 for v in value.values()), 'unit.state_type')
    require(value['LoadState'] in ('loaded','not-found') and
            value['ActiveState'] in ('active','activating','deactivating','inactive','failed') and
            re.fullmatch('[a-z0-9_-]{1,48}',value['SubState']) and
            re.fullmatch('[0-9]{1,10}',value['MainPID']) and
            re.fullmatch('[0-9]{1,3}',value['ExecMainCode']) and
            re.fullmatch('[0-9]{1,3}',value['ExecMainStatus']), 'unit.state_shape')
    require(int(value['MainPID']) <= 4194304 and int(value['ExecMainCode']) <= 3 and
            int(value['ExecMainStatus']) <= 255, 'unit.state_range')
    return dict(value)


class NativeUnitSession:
    """Controller-facing one-unit lifecycle, with capability-bound specific IO.

    worker_observation returns the private Collector capture dictionary. The
    separately source-bound Mac bridge must replay it and join the ready frame
    before it can issue any input-release request. This component issues no gate.
    """
    def __init__(self, capability, storage, io):
        self.cap = native_authority.require_capability(capability, 'unit', io)
        if type(io) is NativeUnitIO: io.bind(capability)
        self.storage, self.io = storage, io
        self.base = capability.session_root
        self.root, self.evidence = self.base/'root', self.base/'evidence'
        self.owner = capability.owner
        self._attempted, self._finished = set(), set()
        self._context_raw = self._properties = self._ready_raw = self._capture = None
        self._submit_attempted = self._stopped = self._empty = False
        self._wait_timed_out = False
        self._state_after_stop = None

    def _once(self, operation):
        require(operation not in self._attempted, 'unit.operation_consumed')
        self._attempted.add(operation)

    def _time(self, *, reserve=0, cleanup=False):
        now = self.io.now()
        require(type(now) is dt.datetime and now.tzinfo is not None, 'unit.clock')
        end = utc(self.owner['providerStopAt'])
        if cleanup:
            end = min(end+dt.timedelta(seconds=600),utc(self.owner['executionDeadlineUtc']))
        require(now+dt.timedelta(seconds=reserve) < end, 'unit.deadline')
        return now

    def _context(self, context):
        closed(context, worker.CONTEXT_KEYS, 'unit.context_schema')
        original = self.cap.context
        require(set(original) == set(context) and all(context[k] == original[k] for k in
                set(context)-{'inputManifestSha256','workerDeadlineUtc'}) and
                original['inputManifestSha256'] in (None,context['inputManifestSha256']) and
                original['workerDeadlineUtc'] in (None,context['workerDeadlineUtc']) and
                all(context.get(k) == self.owner[k] for k in
                    ('sessionId','vmId','bootId','unitName')),
                'unit.context_owner')
        require(_hex(context['inputManifestSha256']) and
                context['entrySha256'] == HELPER_SHA256 and
                context['profileSha256'] == profile.DESIGN_PROFILE_SHA,
                'unit.context_pins')
        worker.validate_context(context, protocol, self._time(reserve=30), context['workerSha256'])
        raw = canonical(context)
        require(self._context_raw is None or raw == self._context_raw, 'unit.context_changed')
        return raw

    def start_worker_once(self, context):
        raw = self._context(context)
        self._once('start')
        facts = self.storage.ready_for_worker(context)
        closed(facts, {'base','root','evidence','contextSha256','runtimeManifestSha256',
                      'propertiesSha256','inputManifestSha256','stagedAtUtc',
                      'workerDeadlineUtc'}, 'unit.storage_schema')
        require(all(str(facts[k]) == str(v) for k,v in
                (('base',self.base),('root',self.root),('evidence',self.evidence))) and
                facts['contextSha256'] == sha(raw) and
                facts['runtimeManifestSha256'] == context['runtimeManifestSha256'] and
                facts['inputManifestSha256'] == context['inputManifestSha256'] and
                facts['workerDeadlineUtc'] == context['workerDeadlineUtc'] and
                utc(facts['workerDeadlineUtc']) == utc(facts['stagedAtUtc'])+dt.timedelta(seconds=300) and
                utc(facts['stagedAtUtc']) <= self._time(reserve=120) <
                    utc(facts['workerDeadlineUtc']) and
                utc(facts['workerDeadlineUtc'])+dt.timedelta(seconds=120) <=
                    utc(self.owner['providerStopAt']),
                'unit.storage_join')
        props = _props(self.io.profile_bytes(), self.cap)
        require(facts['propertiesSha256'] == sha(canonical(props)), 'unit.properties_join')
        self.io.assert_before_start(context, facts)
        # The SAME IO retains ONE Collector and its Sources across these calls.
        self.io.collector_before(context)
        self.io.assert_unit_absent()
        self.io.intent_once('start', {'contextSha256':sha(raw),'propertiesSha256':facts['propertiesSha256']})
        self._context_raw, self._properties = raw, props
        self._submit_attempted = True  # Acknowledgment failure never permits redispatch.
        self.io.start_unit(props)
        self._finished.add('start')

    def worker_observation(self, context):
        require('start' in self._finished, 'unit.start_not_acknowledged')
        self._context(context)
        self._once('observe')
        self.io.intent_once('observe', {'contextSha256':sha(self._context_raw)})
        raw = self.io.wait_ready(context, 30)
        _ready(raw, context)
        capture = self.io.collector_capture(context)
        closed(capture, {'schema','expected','unit','binding','snapshot','guestProofSha256'},
               'unit.capture_schema')
        require(capture['schema'] == 'openclaw.private-host-capture.v1' and
                type(capture['snapshot']) is bytes and len(capture['snapshot']) <= SNAPSHOT_CAP and
                _hex(capture['guestProofSha256']), 'unit.capture_shape')
        expected, unit, binding = capture['expected'],capture['unit'],capture['binding']
        probe.validate_expected(expected)
        closed(binding, {'bootId','sessionId','unitName','pid','startTimeTicks','invocationId',
                        'profileSha256','sourceAnchorSha256','startedAtUtc','finishedAtUtc'},
               'unit.capture_binding_schema')
        require(all(binding.get(k) == self.owner[k] for k in
                ('sessionId','bootId','unitName')) and
                binding.get('profileSha256') == context['profileSha256'] and
                binding.get('pid') == expected['pid'] and
                binding.get('startTimeTicks') == expected['startTimeTicks'] and
                binding.get('invocationId') == expected['invocationId'] and
                binding['sourceAnchorSha256'] == sha(canonical({k:expected[k] for k in
                    ('mounts','inheritedPaths','executable','jailRoot','stdio')})) and
                dt.timedelta(0) <= utc(binding['finishedAtUtc'])-utc(binding['startedAtUtc']) <=
                    dt.timedelta(seconds=20), 'unit.capture_binding')
        controller.unit_binding(unit, expected, context, sha(canonical(self._properties)))
        controller.ready_binding(raw, context, self._context_raw, expected)
        self._ready_raw = bytes(raw)
        self._capture = copy.deepcopy(capture)
        self._finished.add('observe')
        return copy.deepcopy(capture)

    def read_ready_once(self):
        require('observe' in self._finished and self._ready_raw is not None, 'unit.ready_unobserved')
        self._time(reserve=30)
        self._once('ready')
        self.io.intent_once('ready', {'readySha256':sha(self._ready_raw)})
        self._finished.add('ready')
        return bytes(self._ready_raw)

    def _generation_state(self, state, *, closing=False):
        state = _state(state)
        group = '/system.slice/'+self.owner['unitName']
        require(state['ControlGroup'] in ('',group), 'unit.state_cgroup')
        if self._capture is not None:
            expected = self._capture['expected']
            require(state['MainPID'] in ('0',str(expected['pid'])), 'unit.state_pid_changed')
            if state['LoadState'] == 'loaded' and (not closing or
                    state['ActiveState'] != 'inactive' or state['MainPID'] != '0'):
                require(state['InvocationID'] == expected['invocationId'], 'unit.invocation_changed')
            elif state['InvocationID']:
                require(state['InvocationID'] == expected['invocationId'], 'unit.invocation_changed')
        if state['LoadState'] == 'not-found':
            require(closing and state['ActiveState'] == 'inactive' and state['MainPID'] == '0' and
                    state['ControlGroup'] == '' and state['InvocationID'] == '', 'unit.unexpected_absence')
        return state

    def wait_worker_once(self, seconds):
        require('observe' in self._finished and 'ready' in self._finished and
                type(seconds) in (int,float) and math.isfinite(seconds) and 0 < seconds <= 240,
                'unit.wait_sequence')
        now = self._time(reserve=30)
        context = decode(self._context_raw,16384)
        self.io.assert_released_gate(context, copy.deepcopy(self._capture))
        allowed = min(float(seconds), (utc(context['workerDeadlineUtc'])-now).total_seconds()-30,
                      (utc(self.owner['providerStopAt'])-now).total_seconds()-30)
        require(allowed > 0, 'unit.wait_reserve')
        self._once('wait')
        self.io.intent_once('wait', {'secondsMilliseconds':int(allowed*1000)})
        began = self.io.monotonic();last = began
        require(type(began) in (int,float) and math.isfinite(began), 'unit.monotonic')
        for _ in range(6001):
            current = self.io.monotonic()
            require(type(current) in (int,float) and math.isfinite(current) and current >= last,
                    'unit.monotonic')
            last = current
            if current-began >= allowed:
                self._wait_timed_out = True
                # Recovery must collect FINAL bytes after normal stop, not a live prefix.
                raise Refusal('unit.worker_timeout')
            self._time(reserve=30)
            state = self._generation_state(self.io.unit_state())
            if state['MainPID'] == '0' and state['ActiveState'] in ('active','inactive','failed'):
                require(self.io.cgroup_members() == [], 'unit.terminal_cgroup_not_empty')
                code,status = int(state['ExecMainCode']),int(state['ExecMainStatus'])
                require(code in (1,2,3) and (code == 1 or 1 <= status <= 64), 'unit.exit_unproven')
                output = self.io.read_outputs()
                closed(output, {'stdout','stderr'}, 'unit.output_schema')
                require(all(type(output[k]) is bytes and len(output[k]) <= STREAM_CAP
                            for k in ('stdout','stderr')), 'unit.output_cap')
                self._finished.add('wait')
                return {**output,'returncode':status if code == 1 else -status,'timedOut':False}
            self.io.sleep(min(.05,max(.001,allowed-(current-began))))
        raise Refusal('unit.wait_read_budget')

    def stop_owned_unit_normally(self, unit):
        require(unit == self.owner['unitName'] and self._submit_attempted, 'unit.stop_unowned')
        self._once('stop')
        # Risk-reducing normal closeout is not suppressed by a late clock.
        self.io.intent_once('stop', {'contextSha256':sha(self._context_raw)})
        state = self._generation_state(self.io.stop_state(), closing=True)
        if state['LoadState'] == 'loaded' and not (
                state['ActiveState'] == 'inactive' and state['MainPID'] == '0'):
            if self._capture is None:
                # Unique source-derived unit/root plus pre-start absence and the
                # durable start intent bind cleanup of an uncertain submission.
                # This limited ownership check grants no admission or release.
                self.io.assert_uncertain_submission_owned(decode(self._context_raw,16384), state)
            else:
                self.io.assert_live_generation(self._capture['expected'], state)
            self.io.stop_unit()
            state = self._generation_state(self.io.stop_state(), closing=True)
        require(state['ActiveState'] == 'inactive' and state['MainPID'] == '0', 'unit.stop_not_inactive')
        require(self.io.stop_cgroup_members() == [], 'unit.stop_cgroup_not_empty')
        self._state_after_stop = state
        self._stopped = self._empty = True
        self._finished.add('stop')

    def owned_cgroup_empty(self, unit):
        require(unit == self.owner['unitName'] and self._stopped, 'unit.cgroup_before_stop')
        self._time(cleanup=True)
        self._once('cgroup')
        self.io.intent_once('cgroup', {'unitName':unit})
        state = self._generation_state(self.io.unit_state(), closing=True)
        require(state['ActiveState'] == 'inactive' and state['MainPID'] == '0', 'unit.stop_changed')
        members = self.io.cgroup_members()
        require(type(members) is list and all(type(x) is int and x > 0 for x in members),
                'unit.cgroup_shape')
        self._empty = members == []
        self._finished.add('cgroup')
        return self._empty

    def collect_owned_evidence(self):
        require(self._stopped and self._empty and self._submit_attempted,
                'unit.evidence_before_stopped_empty')
        self._time(cleanup=True)
        self._once('evidence')
        self.io.intent_once('evidence', {'contextSha256':sha(self._context_raw)})
        state = self._generation_state(self.io.unit_state(), closing=True)
        require(state['ActiveState'] == 'inactive' and state['MainPID'] == '0' and
                self.io.cgroup_members() == [], 'unit.evidence_no_longer_stopped_empty')
        value = self.io.read_outputs()
        closed(value, {'stdout','stderr'}, 'unit.output_schema')
        require(all(type(value[k]) is bytes and len(value[k]) <= STREAM_CAP for k in value),
                'unit.output_cap')
        self._finished.add('evidence')
        return value


class NativeUnitIO:
    """Fixed Linux operations. bind() currently refuses native authority.

    Its effect methods contain no arbitrary command/path parameters. Existing
    source-pinned CommandCapture owns and bounds every helper child. A retained
    helper blocks later commands to prevent a late-start/stop race.
    """
    evidence_kind = 'native_guest'
    def __init__(self):
        self._cap = None
        self._collector = None
        self._before = False
        self._anchors = {}

    def bind(self, capability):
        require(self._cap is None and self._collector is None and not self._anchors,
                'unit.native_io_already_bound')
        native_authority.require_capability(capability,'unit',self)
        _tool_pins(capability)  # No native read, child or clock before exact pins.
        self._cap = capability

    def now(self): return dt.datetime.now(dt.timezone.utc)
    def monotonic(self): return time.monotonic()
    def sleep(self, seconds):
        require(type(seconds) in (int,float) and 0 < seconds <= .05,'unit.sleep')
        time.sleep(seconds)

    def _check(self, *, cleanup=False, required_stop=False):
        require(self._cap is not None, 'unit.native_io_unbound')
        native_authority.require_capability(self._cap,'unit',self)
        require(sys.platform == 'linux' and os.uname().machine == 'x86_64' and
                os.geteuid() == 0, 'unit.linux_root')
        if not required_stop:
            native_authority.require_time(self._cap,self.now(),cleanup=cleanup,
                                          reserve=0 if cleanup else 30)
        require(self._plain_read(Path('/proc/sys/kernel/random/boot_id'),128).strip().decode() ==
                self._cap.owner['bootId'], 'unit.boot_changed')
        for path, identity in self._anchors.items():
            info = Path(path).lstat()
            require((info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid) == identity,
                    'unit.anchor_changed')

    @staticmethod
    def _plain_read(path, cap):
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try: raw=os.read(fd,cap+1)
        finally: os.close(fd)
        require(len(raw)<=cap,'unit.read_cap')
        return raw

    def _directory(self, path, mode=None):
        current=Path('/')
        for part in Path(path).parts[1:]:
            current=current/part;info=current.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and
                    not stat.S_IMODE(info.st_mode)&0o022 and not current.is_symlink(),
                    'unit.root_path_chain')
        if mode is not None: require(stat.S_IMODE(info.st_mode)==mode,'unit.directory_mode')
        self._anchors[str(path)] = (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)

    def _owned_read(self, path, cap, mode, *, expected=None, stable=True):
        before=path.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and
                before.st_nlink==1 and stat.S_IMODE(before.st_mode)==mode and
                0<=before.st_size<=cap,'unit.file_identity')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            opened=os.fstat(fd);require(protocol.regular_identity(before)==protocol.regular_identity(opened),
                                       'unit.file_changed')
            raw=os.read(fd,cap+1);after=os.fstat(fd)
        finally:os.close(fd)
        final=path.lstat()
        if stable:
            require(protocol.regular_identity(before)==protocol.regular_identity(after)==
                    protocol.regular_identity(final) and len(raw)==before.st_size,'unit.file_changed')
        else:
            fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink')
            require(all(getattr(before,k)==getattr(after,k)==getattr(final,k) for k in fields) and
                    after.st_size<=cap and final.st_size<=cap,'unit.file_changed')
        require(len(raw)<=cap and (expected is None or sha(raw)==expected),'unit.file_pin')
        return raw

    def profile_bytes(self):
        self._check()
        require(HERE == self._cap.source_root/'guest', 'unit.source_root')
        self._directory(HERE)
        return self._owned_read(HERE/'PROFILE.template.private.json',16384,0o444,
                                expected=profile.DESIGN_PROFILE_SHA)

    def assert_before_start(self, context, facts):
        self._check();base=self._cap.session_root;root=base/'root';evidence=base/'evidence'
        for path,mode in ((base,0o700),(root,0o755),(evidence,0o700),(root/'code',0o755),
                          (root/'control',0o755)):
            self._directory(path,mode)
        self._owned_read(root/'control/context.json',16384,0o444,expected=sha(canonical(context)))
        self._owned_read(root/'code/worker.py',262144,0o444,expected=context['workerSha256'])
        self._owned_read(root/'code/protocol.py',262144,0o444,expected=worker.PROTOCOL_SHA256)
        self._owned_read(root/'code/static-entry',131072,0o555,expected=HELPER_SHA256)
        for name,row in worker.CONSUMER.items():
            raw=self._owned_read(root/'code'/name,262144,0o444,expected=row['sha256'])
            require(len(raw)==row['bytes'],'unit.consumer_size')
        for name in ('worker.stdout','worker.stderr'):
            require(self._owned_read(evidence/name,STREAM_CAP,0o600)==b'', 'unit.preexisting_output')
        pending=root/'control/admission.json'
        require(self._owned_read(pending,16384,0o600)==b'', 'unit.preexisting_gate')
        tools=_tool_pins(self._cap)
        for name in TOOL_PATHS:
            path=Path(name);self._directory(path.parent)
            mode=stat.S_IMODE(path.lstat().st_mode)
            require(mode in (0o555,0o755),'unit.tool_mode')
            self._owned_read(path,4*1024*1024,mode,expected=tools[name])

    def collector_before(self, context):
        self._check();require(self._collector is None,'unit.collector_once')
        ops=host_admission.HostOps(str(self._cap.session_root),self._cap.owner['unitName'])
        self._collector=host_admission.Collector(ops,self._cap.owner['bootId'])
        self._collector.before();self._before=True

    def _command(self, kind):
        require(kind in ('start','stop','show','show_stop','ownership_stop'), 'unit.command_kind')
        self._check(cleanup=kind=='show',required_stop=kind in ('stop','show_stop','ownership_stop'))
        require(self._collector is not None and self._before,'unit.collector_not_prepared')
        port=self._collector.ops.command_port
        require(not port.owned_commands,'unit.command_ownership_retained')
        unit=self._cap.owner['unitName']
        if kind=='start':
            props=_props(self.profile_bytes(),self._cap)
            argv=['/usr/bin/systemd-run','--unit='+unit]
            for value in props:
                if not value.startswith('ExecStart='):argv.extend(('--property',value))
            argv.extend(('/code/static-entry','ocv-'+self._cap.owner['sessionId'][:24]))
        elif kind=='stop':argv=['/usr/bin/systemctl','stop',unit]
        else:
            keys=OWNERSHIP_KEYS if kind=='ownership_stop' else STATE_KEYS
            argv=['/usr/bin/systemctl','show','--no-pager','--property='+','.join(keys),unit]
        result=port.command(tuple(argv),15 if kind in ('start','stop') else 5)
        good=self._collector.generic['ci_native_port'].command_capture_ok(result)
        require(good and all(result.get(k,{}).get('truncated') is False for k in
                             ('stdoutFacts','stderrFacts')), 'unit.command_capture')
        require(type(result.get('stdout')) is bytes and type(result.get('stderr')) is bytes and
                len(result['stdout'])<=16384 and len(result['stderr'])<=4096 and
                type(result.get('exitCode')) is int and -255<=result['exitCode']<=255,
                'unit.command_cap')
        return result

    def _show(self, *, required_stop=False):
        result=self._command('show_stop' if required_stop else 'show');raw=result['stdout']
        try:
            lines=raw.decode('ascii').splitlines();rows={}
            for line in lines:
                key,value=line.split('=',1)
                require(key in STATE_KEYS and key not in rows,'unit.show_schema');rows[key]=value
        except (ValueError,UnicodeError):raise Refusal('unit.show_schema') from None
        if rows.get('LoadState')=='not-found':
            require(result['exitCode'] in (0,1) and rows.get('ActiveState')=='inactive' and
                    rows.get('SubState')=='dead' and all(rows.get(k,v)==v for k,v in
                    (('MainPID','0'),('InvocationID',''),('ControlGroup',''))),'unit.absence_readback')
            rows={**{k:'' for k in STATE_KEYS},**rows,'ExecMainCode':'0','ExecMainStatus':'0',
                  'MainPID':'0','InvocationID':'','ControlGroup':''}
        else:require(result['exitCode']==0,'unit.show_failed')
        return _state(rows)

    def assert_unit_absent(self):
        value=self._show()
        require(value['LoadState']=='not-found' and value['ActiveState']=='inactive' and
                value['MainPID']=='0' and value['ControlGroup']=='','unit.preexisting_unit')

    def intent_once(self, operation, facts):
        self._check(cleanup=operation in ('cgroup','evidence'),required_stop=operation=='stop')
        require(operation in _INTENTS and type(facts) is dict and len(canonical(facts))<=4096,
                'unit.intent_schema')
        evidence=self._cap.session_root/'evidence';self._directory(evidence,0o700)
        protocol.write_once(evidence/('unit-'+operation+'.INTENT.private.json'),canonical({
            'schema':'openclaw.native-unit-intent.v1','operation':operation,'owner':self._cap.owner,
            'atUtc':stamp(self.now()),'facts':facts}))

    def start_unit(self, properties):
        require(tuple(properties)==_props(self.profile_bytes(),self._cap),'unit.properties_changed')
        result=self._command('start');require(result['exitCode']==0,'unit.start_failed')

    def wait_ready(self, context, seconds):
        require(type(seconds) is int and 0<seconds<=30,'unit.ready_seconds')
        end=self.monotonic()+seconds
        for _ in range(601):
            self._check();raw=self._owned_read(self._cap.session_root/'evidence/worker.stderr',
                                             STREAM_CAP,0o600,stable=False)
            ready=_find_ready(raw,context)
            if ready:return ready
            if self.monotonic()>=end:raise Refusal('unit.ready_timeout')
            self.sleep(.05)
        raise Refusal('unit.ready_read_budget')

    def collector_capture(self, context):
        self._check();require(self._collector is not None and self._before,'unit.collector_missing')
        return self._collector.capture(context)

    def assert_released_gate(self, context, capture):
        self._check()
        root=self._cap.session_root/'root';path=root/'input'
        self._directory(path,0o555)
        raw=self._owned_read(root/'control/admission.json',16384,0o444)
        gate=decode(raw,16384);expected=capture['expected']
        worker.validate_gate(gate,context,sha(canonical(context)),
                             {k:expected[k] for k in ('pid','uid','gid')},protocol,self.now())
        require(gate['startTimeTicks']==expected['startTimeTicks'] and
                gate['invocationId']==expected['invocationId'],'unit.gate_generation')

    def unit_state(self): return self._show()
    def stop_state(self): return self._show(required_stop=True)

    def assert_live_generation(self, expected, state):
        self._check(required_stop=True)
        require(state['MainPID'] in ('0',str(expected['pid'])) and
                state['InvocationID']==expected['invocationId'], 'unit.stop_generation')
        if state['MainPID']=='0':return
        raw=self._plain_read(Path('/proc')/str(expected['pid'])/'stat',8192)
        # comm may contain spaces and ')'; the final closing delimiter is fixed
        # by the Linux proc stat grammar, and field22 is starttime.
        try:
            head,tail=raw.rsplit(b') ',1)
            require(head.startswith(str(expected['pid']).encode()+b' ('), 'unit.stop_proc_pid')
            fields=tail.split();ticks=int(fields[19])
        except (ValueError,IndexError):raise Refusal('unit.stop_proc_shape') from None
        require(ticks==expected['startTimeTicks'], 'unit.stop_start_time_changed')

    def assert_uncertain_submission_owned(self, context, state):
        self._check(required_stop=True)
        require(state['LoadState']=='loaded' and
                state['ControlGroup']=='/system.slice/'+self._cap.owner['unitName'],
                'unit.uncertain_cgroup')
        result=self._command('ownership_stop')
        require(result['exitCode']==0,'unit.uncertain_properties_failed')
        try:
            rows={}
            for line in result['stdout'].decode('ascii').splitlines():
                key,value=line.split('=',1)
                require(key in OWNERSHIP_KEYS and key not in rows,'unit.uncertain_properties')
                rows[key]=value
        except (ValueError,UnicodeError):raise Refusal('unit.uncertain_properties') from None
        require(rows=={'RootDirectory':str(self._cap.session_root/'root'),
                'User':context['identityName'],'Group':context['identityName'],
                'DynamicUser':'yes'}, 'unit.uncertain_properties')

    def _cgroup_members(self, *, required_stop=False):
        self._check(cleanup=True,required_stop=required_stop)
        path=Path('/sys/fs/cgroup/system.slice')/self._cap.owner['unitName']/'cgroup.procs'
        try:raw=self._plain_read(path,4096)
        except FileNotFoundError:return []
        require(all(re.fullmatch(rb'[1-9][0-9]{0,9}',line) for line in raw.splitlines()),
                'unit.cgroup_readback')
        values=[int(line) for line in raw.splitlines()]
        require(len(values)==len(set(values)) and all(v<=4194304 for v in values),'unit.cgroup_readback')
        return values

    def cgroup_members(self): return self._cgroup_members()
    def stop_cgroup_members(self): return self._cgroup_members(required_stop=True)

    def read_outputs(self):
        self._check(cleanup=True)
        return {name:self._owned_read(self._cap.session_root/'evidence'/('worker.'+name),
                                     STREAM_CAP,0o600) for name in ('stdout','stderr')}

    def stop_unit(self):
        result=self._command('stop');require(result['exitCode']==0,'unit.stop_command_failed')


if __name__ == '__main__':
    raise SystemExit('guest_unit_native_issuer_unissued')

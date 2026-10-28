"""One source-bound guest RPC stream. Import and CLI have no native effects.

The separately verified outer owner supplies a native capability, bootstrap,
authenticated peer, and private intent directory. Guest request JSON never
issues an owner, replay, release, or Mac custody permit.
"""
from __future__ import annotations

import base64
import binascii
import datetime as dt
import json
import os
from pathlib import Path
import stat

import controller
import durable_intent
import guest_bootstrap
import guest_storage
import guest_unit
import framed_channel
import mac_replay
import native_authority
from protocol import Refusal, canonical, require, sha, utc

MAX_REQUEST = 65536
MAX_RESPONSE = 3 * 1024 * 1024
MAX_AGGREGATE = 4 * 1024 * 1024
MAX_BYTES = 2 * 1024 * 1024
MAX_CALLS = 32
CONTROL_BASE = '/var/lib/openclaw-retained-verifier-control'
METHODS = durable_intent.METHODS
NOARGS = METHODS - {'preflight','prepare','write_public_context_once',
    'start_worker_once','worker_observation','release_copied_inputs_then_gate',
    'wait_worker_once','stop_owned_unit_normally','owned_cgroup_empty'}
ONE_RESULT = frozenset(('identity_once','preflight','prepare',
    'write_public_context_once','unmount_test_normally','start_worker_once',
    'worker_observation','read_ready_once','release_copied_inputs_then_gate',
    'wait_worker_once','read_exact_copied_report','stop_owned_unit_normally',
    'owned_cgroup_empty','collect_owned_evidence',
    'remove_only_copied_session_files_after_custody'))


def _pairs(rows):
    result = {}
    for key, value in rows:
        require(key not in result, 'server.duplicate_json_key')
        result[key] = value
    return result


def _decode(raw, limit):
    require(type(raw) is bytes and len(raw) <= limit, 'server.frame_cap')
    try:
        value = json.loads(raw, object_pairs_hook=_pairs,
            parse_constant=lambda _: require(False, 'server.nonfinite'))
    except (ValueError, UnicodeError, RecursionError):
        raise Refusal('server.malformed_json') from None
    require(canonical(value) == raw, 'server.noncanonical_json')
    return value


def _unpack(value, depth=0):
    require(depth <= 16, 'server.depth')
    if type(value) is dict and set(value) == {'$bytes'}:
        encoded = value['$bytes']
        require(type(encoded) is str and len(encoded) <= 4*((MAX_BYTES+2)//3),
                'server.bytes_cap')
        try: raw = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise Refusal('server.base64') from None
        require(len(raw) <= MAX_BYTES and
                base64.b64encode(raw).decode('ascii') == encoded,
                'server.base64')
        return raw
    if value is None or type(value) in (bool,int,str):
        require(type(value) is not int or -(2**63) <= value < 2**64,
                'server.integer_cap')
        require(type(value) is not str or len(value) <= 65536,
                'server.string_cap')
        return value
    if type(value) is list:
        require(len(value) <= 8192, 'server.list_cap')
        return [_unpack(x, depth+1) for x in value]
    require(type(value) is dict and len(value) <= 8192 and
            all(type(k) is str and len(k) <= 256 and k != '$bytes' for k in value),
            'server.value_type')
    return {k:_unpack(x,depth+1) for k,x in value.items()}


def _pack(value, depth=0, budget=None):
    if budget is None: budget = [MAX_RESPONSE]
    require(depth <= 16, 'server.depth')
    if type(value) is bytes:
        require(len(value) <= MAX_BYTES, 'server.bytes_cap')
        budget[0] -= 4*((len(value)+2)//3)+32
        require(budget[0] >= 0, 'server.response_cap')
        return {'$bytes':base64.b64encode(value).decode('ascii')}
    if value is None or type(value) in (bool,int,str):
        require(type(value) is not int or -(2**63) <= value < 2**64,
                'server.integer_cap')
        require(type(value) is not str or len(value) <= 65536,
                'server.string_cap')
        budget[0] -= len(canonical(value))+1
        require(budget[0] >= 0, 'server.response_cap')
        return value
    if type(value) in (list,tuple):
        require(len(value) <= 8192, 'server.list_cap')
        budget[0] -= 2
        require(budget[0] >= 0, 'server.response_cap')
        return [_pack(x,depth+1,budget) for x in value]
    require(type(value) is dict and len(value) <= 8192 and
            all(type(k) is str and len(k) <= 256 and k != '$bytes' for k in value),
            'server.value_type')
    budget[0] -= sum(len(canonical(k))+2 for k in value)+2
    require(budget[0] >= 0, 'server.response_cap')
    return {k:_pack(x,depth+1,budget) for k,x in value.items()}


def _dir(path, uid):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path,
            'server.journal_path')
    try: fd = os.open(path, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    except OSError: raise Refusal('server.journal_unavailable') from None
    info = os.fstat(fd)
    if not (stat.S_ISDIR(info.st_mode) and info.st_uid == uid and
            stat.S_IMODE(info.st_mode) == 0o700):
        os.close(fd)
        raise Refusal('server.journal_identity')
    return fd


def _checked_gate(context, proof, requested, now):
    """Recompute an independently proven gate at a bounded Mac timestamp."""
    require(type(requested) is dict and
            type(requested.get('checkedAt')) is str and
            type(requested.get('expiresAt')) is str,
            'server.gate_clock_schema')
    checked_at = utc(requested['checkedAt'])
    expires_at = utc(requested['expiresAt'])
    require(type(now) is dt.datetime and now.tzinfo is not None and
            dt.timedelta(0) <= now-checked_at < dt.timedelta(seconds=30) and
            now < expires_at,
            'server.gate_clock')
    gate = controller.gate(context,canonical(context),proof,checked_at)
    require(requested == gate and gate.get('inputReleased') is True,
            'server.gate_changed')
    return gate


class GuestIntentJournal:
    """O_EXCL intent before dispatch; any prior file forbids stream restart."""
    def __init__(self, path, owner, *, uid=0):
        native_authority.validate_owner(owner)
        self.root_path = Path(path)
        self._fd = _dir(self.root_path,uid)
        self.owner_raw = canonical(owner)
        with os.scandir(self._fd) as entries:
            require(next(entries,None) is None, 'server.journal_preexisting')
        self._seq = 0
        self._pending = None

    def _write(self, name, value):
        raw = canonical(value)
        require(len(raw) <= 16384, 'server.journal_record_cap')
        try:
            fd = os.open(name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
                         0o600,dir_fd=self._fd)
            try:
                os.fchmod(fd,0o600)
                view = memoryview(raw)
                while view:
                    count = os.write(fd,view)
                    require(count > 0,'server.journal_short_write')
                    view = view[count:]
                os.fsync(fd)
            finally: os.close(fd)
            os.fsync(self._fd)
        except OSError:
            raise Refusal('server.journal_write_uncertain') from None

    def begin(self, seq, method, request):
        require(self._pending is None and seq == self._seq and
                seq < MAX_CALLS and method in METHODS and type(request) is bytes and
                len(request) <= MAX_REQUEST, 'server.journal_order')
        self._pending = seq  # A failed fsync is still an uncertain intent.
        self._write(f'{seq:03d}.intent.private.json',
                    {'schema':'openclaw.guest-intent.v1','sequence':seq,
                     'method':method,'ownerSha256':sha(self.owner_raw),
                     'requestSha256':sha(request)})

    def settle(self, seq, method, response):
        require(self._pending == seq and seq == self._seq and
                type(response) is bytes and len(response) <= MAX_RESPONSE,
                'server.journal_pending')
        self._write(f'{seq:03d}.settled.private.json',
                    {'schema':'openclaw.guest-settlement.v1','sequence':seq,
                     'method':method,'responseSha256':sha(response),
                     'responseBytes':len(response)})
        self._pending = None; self._seq += 1

    @property
    def sequence(self): return self._seq
    @property
    def pending(self): return self._pending


class GuestServer:
    """One stream; typed outer authority is required before any native method."""
    def __init__(self, capability, storage, unit, bootstrap, peer, journal, *, now):
        require(type(bootstrap) is guest_bootstrap.VerifiedBootstrap and
                bootstrap.purpose in ('private-owned-ssh','ci-native-proof',
                                      'synthetic-contract') and
                type(peer) is guest_bootstrap.PeerAuthority and
                type(storage) is guest_storage.NativeStorageSession and
                type(unit) is guest_unit.NativeUnitSession and
                type(journal) is GuestIntentJournal and callable(now),
                'server.component_unissued')
        kind = {'private-owned-ssh':'private-native',
                'ci-native-proof':'ci-native-proof',
                'synthetic-contract':'synthetic-contract'}[bootstrap.purpose]
        require(capability.kind == kind and capability.owner == bootstrap.owner and
                capability.owner['guestSourceSha256'] == bootstrap.bundle_sha256 and
                storage.cap is capability and unit.cap is capability and
                unit.storage is storage and journal.owner_raw == canonical(capability.owner),
                'server.generation_join')
        if kind != 'synthetic-contract':
            require(journal.root_path ==
                    Path(CONTROL_BASE)/capability.owner['sessionId']/'rpc-intents',
                    'server.journal_source_path')
        peer.require_for(bootstrap, bootstrap.purpose, peer._channel)
        native_authority.require_capability(capability,'storage',storage.io)
        native_authority.require_capability(capability,'unit',unit.io)
        owner_guard = getattr(native_authority,'require_owner_guard',None)
        require(callable(owner_guard), 'server.owner_guard_unissued')
        owner_guard(capability,storage.io if kind == 'synthetic-contract'
                    else bootstrap.owner_guard)
        require(journal.sequence == 0 and journal.pending is None,
                'server.journal_changed')
        self.cap,self.storage,self.unit,self.bootstrap,self.peer,self.journal,self.now = (
            capability,storage,unit,bootstrap,peer,journal,now)
        self.owner = capability.owner
        self.context = capability.context
        self.sequence = self.response_bytes = 0
        self.attempted,self.finished = set(),set()
        self.blocked = False
        self.staged = self.capture = self.ready = self.gate = self._replay_proof = None
        self.unmounted = self.empty = False
        self.outputs = self.report = None
        self.outcome = None
        self._response_hashes = {}

    def _context(self, value, *, final=False):
        require(type(value) is dict and set(value) == set(self.context) and
                all(value[k] == self.context[k] for k in value
                    if k not in ('inputManifestSha256','workerDeadlineUtc')) and
                all(value[k] == self.owner[k] for k in
                    ('vmId','bootId','sessionId','unitName')) and
                len(canonical(value)) <= 16384,
                'server.context_join')
        if final:
            require(self.staged is not None and
                    value['inputManifestSha256'] == self.staged['inputManifestSha256'] and
                    value['workerDeadlineUtc'] == self.staged['workerDeadlineUtc'] and
                    utc(value['workerDeadlineUtc']) ==
                        utc(self.staged['stagedAtUtc'])+dt.timedelta(seconds=300) and
                    utc(value['workerDeadlineUtc'])+dt.timedelta(seconds=120) <=
                        utc(self.owner['providerStopAt']),
                    'server.staged_context')
        else:
            require(value == self.cap.context and
                    value['inputManifestSha256'] is None and
                    value['workerDeadlineUtc'] is None,
                    'server.initial_context')

    def _before(self, method, args):
        done = self.finished
        require(type(args) is list and len(args) == (0 if method in NOARGS else 1),
                'server.arguments')
        require(method not in self.attempted or method == 'test_is_unmounted',
                'server.consumed')
        if method == 'identity_once': require(not done, 'server.order')
        elif method == 'preflight':
            require('identity_once' in done,'server.order'); self._context(args[0])
        elif method == 'prepare':
            require('preflight' in done,'server.order'); self._context(args[0])
        elif method == 'write_public_context_once':
            require('prepare' in done and type(args[0]) is bytes and
                    len(args[0]) <= 16384,'server.order')
            value = _decode(args[0],16384)
            self._context(value,final=True)
            require(canonical(value) == args[0],'server.context_canonical')
        elif method == 'unmount_test_normally':
            require('prepare' in done,'server.order')
        elif method == 'test_is_unmounted':
            require('unmount_test_normally' in done,'server.order')
        elif method == 'start_worker_once':
            require({'write_public_context_once','test_is_unmounted'} <= done and
                    self.unmounted,'server.order')
            self._context(args[0],final=True)
        elif method == 'worker_observation':
            require('start_worker_once' in done,'server.order')
            self._context(args[0],final=True)
        elif method == 'read_ready_once':
            require('worker_observation' in done,'server.order')
        elif method == 'release_copied_inputs_then_gate':
            require('read_ready_once' in done and self.unmounted and
                    type(args[0]) is dict,'server.order')
        elif method == 'wait_worker_once':
            require('release_copied_inputs_then_gate' in done and
                    type(args[0]) is int and 0 < args[0] <= 240,
                    'server.wait_order')
        elif method == 'stop_owned_unit_normally':
            require('start_worker_once' in self.attempted and
                    args[0] == self.owner['unitName'],'server.stop_order')
        elif method == 'owned_cgroup_empty':
            require('stop_owned_unit_normally' in done and
                    args[0] == self.owner['unitName'],'server.cgroup_order')
        elif method == 'collect_owned_evidence':
            require('owned_cgroup_empty' in done and self.empty,
                    'server.evidence_order')
        elif method == 'read_exact_copied_report':
            require('owned_cgroup_empty' in done and self.empty and
                    'unmount_test_normally' in done and self.unmounted,
                    'server.report_order')
        elif method == 'remove_only_copied_session_files_after_custody':
            require({'read_exact_copied_report','collect_owned_evidence',
                     'owned_cgroup_empty','test_is_unmounted'} <= done and
                    self.empty and self.unmounted,
                    'server.custody_order')

    def _release(self, requested):
        """Replay is independently source-bound; a matched JSON gate is insufficient."""
        require(self.capture is not None and self.ready is not None,
                'server.replay_materials')
        evaluator = getattr(mac_replay,'evaluate_bound',None)
        require(callable(evaluator), 'server.source_bound_replay_unissued')
        owner = {k:self.owner[k] for k in
                 ('vmId','bootId','sessionId','unitName','guestSourceSha256')}
        replay = evaluator(self.capture,self.context,owner,
                           capability=self.cap,now=self.now())
        require(type(replay) is dict and replay.get('status') == 'passed' and
                replay.get('ownerGuestSourceSha256') == self.bootstrap.bundle_sha256 and
                type(replay.get('proof')) is dict and
                replay.get('snapshot',{}).get('snapshotSha256') ==
                    sha(self.capture['snapshot']),
                'server.replay_join')
        raw = canonical(self.context)
        controller.ready_binding(self.ready,self.context,raw,
                                 self.capture['expected'])
        gate = _checked_gate(self.context,replay['proof'],requested,self.now())
        issuer = getattr(native_authority,'issue_peer_release_permit',None)
        require(callable(issuer),'server.release_issuer_unissued')
        permit = issuer(self.cap,self.peer,self.bootstrap,self.context,gate,
                        sha(self.capture['snapshot']),sha(self.ready))
        self.storage.release_copied_inputs_then_gate(gate,permit)
        self._replay_proof = replay['proof']
        self.gate = gate

    def _custody(self):
        # The authenticated peer must expose a source-backed, fsynced Mac ACK.
        # No request argument or JSON field can substitute for this issuance.
        require(self.outputs is not None and self.report is not None and
                type(self._replay_proof) is dict and
                self.empty and self.unmounted,
                'server.custody_materials')
        # The earlier STOP/empty and unmount receipts cannot stand in for a
        # current source-owned readback just before copy deletion.
        state = self.unit._generation_state(self.unit.io.stop_state(),closing=True)
        require(state['ActiveState'] == 'inactive' and state['MainPID'] == '0' and
                self.unit.io.stop_cgroup_members() == [] and
                self.storage.test_is_unmounted() is True,
                'server.custody_closeout_changed')
        issuer = getattr(native_authority,'issue_peer_custody_permit',None)
        require(callable(issuer),'server.custody_issuer_unissued')
        expected = {
            'staging-manifest': canonical(self.staged['inputManifest']),
            'host-snapshot': self.capture['snapshot'],
            'host-proof': canonical(self._replay_proof),
            'ready-frame': self.ready,
            'worker-stdout': self.outputs['stdout'],
            'worker-stderr': self.outputs['stderr'],
            'report': self.report,
            'closeout': canonical({'schema':'openclaw.mac-owned-unit-closeout.v1',
                'unitName':self.owner['unitName'],'ownedCgroupEmpty':True,
                'reportSha256':sha(self.report),
                'stdoutSha256':sha(self.outputs['stdout']),
                'stderrSha256':sha(self.outputs['stderr'])})}
        rows = {role:{'bytes':len(raw),'sha256':sha(raw)}
                for role,raw in expected.items()}
        permit = issuer(self.cap,self.peer,self.bootstrap,self.context,
                        rows,dict(self._response_hashes))
        self.storage.remove_only_copied_session_files_after_custody(permit)

    def _dispatch(self, method, args):
        if method == 'identity_once': return self.owner
        if method == 'preflight': return self.storage.preflight(args[0])
        if method == 'prepare': return self.storage.prepare(args[0])
        if method == 'write_public_context_once':
            return self.storage.write_public_context_once(args[0])
        if method == 'unmount_test_normally': return self.storage.unmount_test_normally()
        if method == 'test_is_unmounted': return self.storage.test_is_unmounted()
        if method == 'start_worker_once': return self.unit.start_worker_once(args[0])
        if method == 'worker_observation': return self.unit.worker_observation(args[0])
        if method == 'read_ready_once': return self.unit.read_ready_once()
        if method == 'release_copied_inputs_then_gate': return self._release(args[0])
        if method == 'wait_worker_once': return self.unit.wait_worker_once(args[0])
        if method == 'stop_owned_unit_normally': return self.unit.stop_owned_unit_normally(args[0])
        if method == 'owned_cgroup_empty': return self.unit.owned_cgroup_empty(args[0])
        if method == 'collect_owned_evidence': return self.unit.collect_owned_evidence()
        if method == 'read_exact_copied_report': return self.storage.read_exact_copied_report()
        if method == 'remove_only_copied_session_files_after_custody': return self._custody()
        raise Refusal('server.method')

    def handle(self, raw):
        require(not self.blocked and self.journal.pending is None and
                self.sequence == self.journal.sequence and
                self.sequence < MAX_CALLS, 'server.blocked')
        request = _decode(raw,MAX_REQUEST)
        require(type(request) is dict and set(request) ==
                {'schema','sequence','owner','method','arguments'} and
                request['schema'] == 'openclaw.private-guest-request.v1' and
                request['owner'] == self.owner and
                type(request['sequence']) is int and
                request['sequence'] == self.sequence and
                type(request['method']) is str and
                request['method'] in METHODS,
                'server.request_join')
        method = request['method']
        args = _unpack(request['arguments'])
        cleanup = method in {'test_is_unmounted','stop_owned_unit_normally',
            'owned_cgroup_empty','collect_owned_evidence',
            'read_exact_copied_report',
            'remove_only_copied_session_files_after_custody'}
        # A normal source-owned stop remains available through the unit's own
        # exact ownership checks; the outer VM STOP is independent of this RPC.
        if method != 'stop_owned_unit_normally':
            native_authority.require_time(self.cap,self.now(),cleanup=cleanup)
        self._before(method,args)
        self.journal.begin(self.sequence,method,raw)
        self.attempted.add(method)
        try:
            value = self._dispatch(method,args)
            if method == 'identity_once': require(value == self.owner,'server.identity')
            if method == 'prepare':
                require(type(value) is dict and set(value) ==
                    {'inputManifestSha256','inputManifest','runtimeManifestSha256',
                     'copiesRootOwned','inputMode','propertiesSha256',
                     'stagedAtUtc','workerDeadlineUtc'},'server.staging')
            if method == 'worker_observation':
                require(type(value) is dict and set(value) ==
                    {'schema','expected','unit','binding','snapshot','guestProofSha256'} and
                    type(value['snapshot']) is bytes and len(value['snapshot']) <= MAX_BYTES,
                    'server.capture')
            if method in ('test_is_unmounted','owned_cgroup_empty'):
                require(type(value) is bool,'server.boolean')
            if method == 'read_exact_copied_report':
                require(type(value) is bytes and len(value) == self.context['privacyBytes'] and
                        sha(value) == self.context['privacySha256'],
                        'server.report_pin')
            response = canonical({'schema':'openclaw.private-guest-response.v1',
                'owner':self.owner,'sequence':self.sequence,'method':method,
                'status':'returned','value':_pack(value)})
            require(len(response) <= MAX_RESPONSE and
                    self.response_bytes+len(response) <= MAX_AGGREGATE,
                    'server.response_cap')
            self.journal.settle(self.sequence,method,response)
            self._response_hashes[self.sequence] = sha(response)
            self.response_bytes += len(response)
            self.sequence += 1
            self.finished.add(method)
            if method == 'prepare': self.staged = value
            if method == 'write_public_context_once':
                self.context = _decode(args[0],16384)
            if method == 'test_is_unmounted': self.unmounted = value
            if method == 'worker_observation': self.capture = value
            if method == 'wait_worker_once': self.outcome = value
            if method == 'read_ready_once': self.ready = value
            if method == 'owned_cgroup_empty': self.empty = value
            if method == 'collect_owned_evidence': self.outputs = value
            if method == 'read_exact_copied_report': self.report = value
            return response
        except BaseException:
            self.blocked = True
            # Backend messages and private paths never enter the wire response.
            raise Refusal('server.effect_or_response_uncertain') from None


def serve_framed(server, channel):
    """One persistent authenticated stream; any EOF/error ends this generation.

    The channel owns fixed descriptors, source peer identity and bounded
    deadline-aware I/O. No CLI constructs this server or opens a connection.
    """
    require(type(server) is GuestServer and
            type(channel) is framed_channel.NativeFramedChannel and
            server.peer._channel is channel and
            server.bootstrap.purpose in ('private-owned-ssh','ci-native-proof',
                                         'synthetic-contract') and
            channel.nonreconnecting is True,
            'server.stream_unissued')
    if server.bootstrap.purpose in ('private-owned-ssh','ci-native-proof'):
        channel.assert_for_bootstrap(server.bootstrap)
    deadline=min(utc(server.owner['providerStopAt'])+dt.timedelta(seconds=600),
                 utc(server.owner['executionDeadlineUtc']))
    try:
        while server.sequence < MAX_CALLS:
            require(channel.read_count == channel.write_count ==
                    server.sequence,'server.stream_sequence')
            raw=channel.read_frame_once(MAX_REQUEST,deadline)
            response=server.handle(raw)
            channel.write_frame_once(response,deadline)
            if 'remove_only_copied_session_files_after_custody' in server.finished:
                server.blocked=True
                return server.sequence
        server.blocked=True
        return MAX_CALLS
    except BaseException:
        server.blocked=True
        # Never serialize private exception text, paths, or backend values.
        raise Refusal('server.stream_uncertain') from None


if __name__ == '__main__':
    raise SystemExit('guest_server_no_cli')

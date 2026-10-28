"""Actual CI-only storage/unit/collector/encoded-peer/durable replay chain.

No CLI, import or caller JSON issues native authority. The public bootstrap
must pass a genuine current-build CI session, verified source and peer. The
local encoded route is explicitly CI-only and cannot impersonate owned SSH.
"""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import stat

import copier
import custody
import durable_intent
import guest_bootstrap
import guest_server
import guest_storage
import guest_unit
import integrated_capture
import integrated_failure
import host_admission
import mac_bridge
import native_authority
from protocol import Refusal, canonical, decode, require, sha, utc

ROUTE_KIND = 'same-guest-local-encoded-ci'


class LocalGuestTransport:
    """One actual encoded local peer, admitted only by the genuine CI issuer."""
    evidence_kind = 'ci_local_encoded_transport'
    nonreconnecting = True
    __slots__ = ('_cap', '_server', '_peer', '_journal', '_custody', '_blocked', '_ack_used',
                 '_attempts', '_methods', '_responses')
    def __init__(self):
        self._cap = self._server = self._peer = self._journal = self._custody = None
        self._blocked = self._ack_used = False
        self._attempts, self._methods, self._responses = [], [], []

    @property
    def route_binding(self):
        require(self._cap is not None, 'integrated_transport.unbound')
        return {'owner': self._cap.owner, 'route': ROUTE_KIND,
            'sourceBundleSha256': self._cap.owner['guestSourceSha256'],
            'receiptSha256': self._cap.pins['transportReceiptSha256']}

    def bind(self, cap, server, peer):
        require(self._cap is None and type(server) is guest_server.GuestServer and
                type(peer) is guest_bootstrap.PeerAuthority and server.cap is cap and
                server.peer is peer and peer._channel is self and cap.kind == 'ci-native-proof',
                'integrated_transport.source_binding')
        native_authority.require_capability(cap, 'mac', self)
        peer.require_for(server.bootstrap, 'ci-native-proof', self)
        self._cap, self._server, self._peer = cap, server, peer

    def bind_journal(self, journal):
        require(self._journal is None and self._cap is not None and
                type(journal) is durable_intent.DurableIntent and journal.owner == self._cap.owner and
                journal.root_path == Path(self._cap.pins['macJournalRoot']) and
                journal.pins_sha256 == sha(canonical(self._cap.pins)) and journal.sequence == 0 and
                journal.pending is None, 'integrated_transport.journal_binding')
        self._journal = journal

    def exchange_once(self, raw, *, max_response, deadline_utc):
        require(self._cap is not None and self._journal is not None and not self._blocked and
                not self._journal.uncertain and type(max_response) is int and
                0 < max_response <= durable_intent.MAX_RESPONSE and
                type(deadline_utc) is dt.datetime and deadline_utc.tzinfo is not None and
                dt.datetime.now(dt.timezone.utc) < deadline_utc,
                'integrated_transport.blocked_or_deadline')
        native_authority.require_capability(self._cap, 'mac', self)
        request = mac_bridge._decode(raw, mac_bridge.MAX_REQUEST)
        sequence = len(self._methods)
        require(type(request) is dict and request.get('owner') == self._cap.owner and
                request.get('sequence') == sequence and sequence == len(self._attempts) and
                self._journal.pending == (sequence, request.get('method')) and
                request.get('method') in durable_intent.METHODS,
                'integrated_transport.intent_join')
        self._attempts.append(request['method'])  # Once, before ambiguous server dispatch.
        try:
            response = self._server.handle(raw)
            require(type(response) is bytes and len(response) <= max_response and
                    dt.datetime.now(dt.timezone.utc) < deadline_utc,
                    'integrated_transport.response_cap_or_deadline')
            value = mac_bridge._decode(response, max_response)
            require(value.get('sequence') == sequence and value.get('owner') == self._cap.owner and
                    value.get('method') == request['method'], 'integrated_transport.response_join')
            self._methods.append(request['method']); self._responses.append(sha(response))
            return response
        except BaseException:
            self._blocked = True
            raise Refusal('integrated_transport.effect_or_response_uncertain') from None

    def bind_custody_ack(self, permit, journal):
        require(self._custody is None and journal is self._journal and
                type(permit) is durable_intent.DurableMacCustody and
                permit._key is durable_intent._CUSTODY_KEY and permit._journal is journal and
                permit._digest == journal.custody_digest and journal.custody_claimed and
                journal.pending is None and not journal.uncertain,
                'integrated_transport.typed_custody_unissued')
        journal._verify_evidence()
        self._custody = permit

    def consume_custody_ack(self, owner, context_sha256, rows, response_hashes):
        """Source-backed CI equivalent of the private channel's durable Mac ACK."""
        require(not self._blocked and not self._ack_used and self._journal is not None and
                type(self._custody) is durable_intent.DurableMacCustody and
                self._custody._journal is self._journal and
                owner == self._cap.owner and type(rows) is dict and type(response_hashes) is dict,
                'integrated_transport.ack_unissued')
        self._ack_used = True
        journal = self._journal
        require(journal.custody_claimed and journal.custody_digest is not None and
                journal.final_context_sha256 == context_sha256 and
                journal.pending == (len(self._methods), 'remove_only_copied_session_files_after_custody') and
                set(rows) == durable_intent.REQUIRED_CUSTODY,
                'integrated_transport.ack_state')
        journal._verify_evidence()
        actual_rows = {}
        for role in durable_intent.REQUIRED_CUSTODY:
            raw = durable_intent._read_file(journal.evidence_fd, role+'.bin',
                                             durable_intent.EVIDENCE_CAPS[role])
            actual_rows[role] = {'bytes': len(raw), 'sha256': sha(raw)}
        require(actual_rows == rows and response_hashes == dict(enumerate(self._responses)),
                'integrated_transport.ack_material_join')
        for sequence, method in enumerate(self._methods):
            response = durable_intent._read_file(journal.session_fd,
                '%02d-%s.response.bin' % (sequence, method), durable_intent.MAX_RESPONSE)
            require(sha(response) == self._responses[sequence],
                    'integrated_transport.ack_response_changed')
        ack = durable_intent._read_file(journal.session_fd, 'custody-ack.json', 16384)
        require(sha(ack) == journal.custody_digest and
                sha(durable_intent._read_file(journal.session_fd, 'final-context.json', 16384)) == context_sha256,
                'integrated_transport.ack_fsync_join')
        claim = json.loads(durable_intent._read_file(journal.session_fd,
                                                   'custody-removal-claim.json', 16384))
        require(claim == {'schema': 'openclaw.mac-custody-removal-claim.v1',
                'custodySha256': journal.custody_digest, 'ownerSha256': journal.owner_sha256},
                'integrated_transport.ack_claim_join')
        return {'custodySha256': journal.custody_digest, 'roles': actual_rows,
                'responses': [{'sequence': i, 'sha256': digest} for i, digest in enumerate(self._responses)]}


def _control_directories(cap):
    root = Path(guest_server.CONTROL_BASE)
    require(root == Path('/var/lib/openclaw-retained-verifier-control') and
            os.geteuid() == os.getegid() == 0, 'integrated_guest.fixed_control_root')
    current = Path('/')
    for part in root.parts[1:]:
        current /= part; info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and
                not stat.S_IMODE(info.st_mode) & 0o022 and not current.is_symlink(),
                'integrated_guest.control_parent')
    session = root/cap.owner['sessionId']
    os.mkdir(session, 0o700)
    for name in ('rpc-intents', 'mac-journal'):
        os.mkdir(session/name, 0o700)
    fd = os.open(session, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)
    return session


def _diagnostic_binding(parent,prepared,cap,storage,unit,transport,server,bridge,journal):
    """Memory-only joins; this cannot issue or renew any native authority."""
    import ci_authority
    require(type(cap) is native_authority.SessionCapability and cap._key is native_authority._KEY and
        cap.kind=='ci-native-proof' and type(cap._grant) is ci_authority.CIGrant and
        cap._grant._key is ci_authority._KEY and cap._grant._parent is parent and
        cap._grant._prepared is prepared and cap._grant._channel is transport and cap._channel is transport,
        'integrated_guest.diagnostic_capability')
    require(type(storage) is guest_storage.NativeStorageSession and type(storage.io) is guest_storage.NativeStorageIO and
        type(unit) is guest_unit.NativeUnitSession and type(unit.io) is guest_unit.NativeUnitIO and
        type(transport) is LocalGuestTransport and type(server) is guest_server.GuestServer and
        type(bridge) is mac_bridge.MacBridge and type(journal) is durable_intent.DurableIntent and
        type(server.journal) is guest_server.GuestIntentJournal and
        storage.cap is unit.cap is server.cap is cap and unit.storage is server.storage is storage and
        server.unit is unit and unit.io._cap is cap and transport._cap is cap and
        transport._server is server and transport._peer is server.peer and
        type(server.bootstrap) is guest_bootstrap.VerifiedBootstrap and server.bootstrap._key is guest_bootstrap._KEY and
        server.bootstrap.purpose=='ci-native-proof' and server.bootstrap.owner==cap.owner and
        server.bootstrap.owner_guard is cap._owner_guard and
        type(server.peer) is guest_bootstrap.PeerAuthority and server.peer._key is guest_bootstrap._KEY and
        server.peer._channel is transport and server.peer._bootstrap is server.bootstrap and
        transport._journal is bridge.journal is journal and bridge.capability is cap and
        bridge.transport is transport and cap._ios['storage'] is storage.io and
        cap._ios['unit'] is unit.io and cap._ios['mac'] is transport,
        'integrated_guest.diagnostic_components')
    grant=cap._grant
    require(getattr(parent.io,'_integrated_module_graph',None) is grant._graph,
            'integrated_guest.diagnostic_graph')
    grant._graph.require_loaded_rows(grant._root,dict(grant._graph_rows))
    modules=dict(grant._graph._modules)
    collector=unit.io._collector
    if collector is not None:
        require(type(collector) is host_admission.Collector and type(collector.ops) is host_admission.HostOps and
            collector.ops.root==str(cap.session_root) and collector.ops.unit==cap.owner['unitName'] and
            collector.boot==cap.owner['bootId'],'integrated_guest.diagnostic_collector')
        require(type(collector.generic) is dict and set(collector.generic)==
            {name[:-3]for name in host_admission.GENERIC_PINS},'integrated_guest.diagnostic_generic')
        modules.update(collector.generic)
    return integrated_failure.source_index(modules)


def _diagnostic_state(storage,unit,transport,server,bridge,journal):
    def operations(value,allowed):
        require(type(value) is set and value<=set(allowed),'integrated_guest.diagnostic_operations')
        return sorted(value)
    def pending(value):
        require(value is None or type(value) is tuple and len(value)==2 and type(value[0]) is int and
            0<=value[0]<durable_intent.MAX_CALLS and value[1] in durable_intent.METHODS,
            'integrated_guest.diagnostic_pending')
        return None if value is None else list(value)
    state={'bridgePhase':bridge.phase,'bridgeSequence':bridge.sequence,'serverSequence':server.sequence,
        'transportAttempts':len(transport._attempts),'transportSettled':len(transport._methods),
        'serverAttempted':operations(server.attempted,guest_server.METHODS),
        'serverFinished':operations(server.finished,guest_server.METHODS),
        'unitAttempted':operations(unit._attempted,guest_unit._INTENTS),
        'unitFinished':operations(unit._finished,guest_unit._INTENTS),
        'storageUsed':operations(storage._used,('preflight','prepare','context','unmount','release','report','remove')),
        'macPending':pending(journal.pending),'guestPending':pending(server.journal.pending)}
    require(state['bridgePhase'] in ('new','preparing','prepared','started','admitted','closing','closed','copies_removed') and
        all(type(state[k]) is int and 0<=state[k]<=durable_intent.MAX_CALLS for k in
            ('bridgeSequence','serverSequence','transportAttempts','transportSettled')),
        'integrated_guest.diagnostic_state')
    for name,value in (('bridgeBlocked',bridge.blocked),('transportBlocked',transport._blocked),
        ('serverBlocked',server.blocked),('journalUncertain',journal.uncertain),
        ('unitSubmissionAttempted',unit._submit_attempted),('unitStopped',unit._stopped),
        ('unitEmpty',unit._empty),('testMounted',storage._mounted),('serverUnmounted',server.unmounted)):
        require(type(value) is bool,'integrated_guest.diagnostic_boolean');state[name]=value
    return state


def _diagnostic_command(unit,storage):
    record=unit.io._last_command
    if record is None:return None
    require(type(record) is tuple and len(record)==3,'integrated_guest.diagnostic_command_record')
    kind,argv,result=record;require(type(argv) is tuple and type(result) is dict,
        'integrated_guest.diagnostic_command_record')
    name=unit.cap.owner['unitName'];role=None
    if kind in ('show','show_stop','ownership_stop'):
        keys=guest_unit.OWNERSHIP_KEYS if kind=='ownership_stop'else guest_unit.STATE_KEYS
        expected=('/usr/bin/systemctl','show','--no-pager','--property='+','.join(keys),name)
        role='unit-ownership'if kind=='ownership_stop'else 'unit-state'
    elif kind=='stop':expected=('/usr/bin/systemctl','stop',name);role='unit-stop'
    elif kind=='start':
        props=unit._properties
        require(type(props) is tuple and len(props)==55 and storage.staged is not None and
            sha(canonical(props))==storage.staged['propertiesSha256'],
            'integrated_guest.diagnostic_start_properties')
        expected=['/usr/bin/systemd-run','--unit='+name]
        for value in props:
            if not value.startswith('ExecStart='):expected.extend(('--property',value))
        expected.extend(('/code/static-entry','ocv-'+unit.cap.owner['sessionId'][:24]));expected=tuple(expected)
        role='unit-start-fixed-profile'
    else:raise Refusal('integrated_guest.diagnostic_command_kind')
    require(argv==expected,'integrated_guest.diagnostic_unsafe_argv')
    collector=unit.io._collector
    require(type(collector) is host_admission.Collector,'integrated_guest.diagnostic_capture_source')
    port=collector.ops.command_port
    require(type(port) is collector.generic['ci_native_port'].CommandCapture and
        type(port.io) is guest_unit._UnitCommandIO and port.io.owner is unit.io and type(port.command_results) is dict and
        type(port.owned_commands) is dict and 0<len(port.command_results)<=256 and
        type(port.command_sequence) is int and 1<=port.command_sequence<=256 and
        all(type(k) is int and 1<=k<=port.command_sequence for k in port.command_results) and
        port.command_results.get(port.command_sequence) is result and
        result.get('operationId')==port.command_sequence,'integrated_guest.diagnostic_capture_source')
    value=integrated_failure.command_snapshot(result,port.command_sequence,set(port.owned_commands))
    value['closedCommandRole']=role
    return value


def _failure_snapshot(error,parent,prepared,cap,storage,unit,transport,server,bridge,journal):
    index=_diagnostic_binding(parent,prepared,cap,storage,unit,transport,server,bridge,journal)
    return {'primary':None if error is None else integrated_failure.exception_snapshot(error,index),'index':index,
        'before':_diagnostic_state(storage,unit,transport,server,bridge,journal),
        'command':_diagnostic_command(unit,storage)}


def _refuse_chain(primary,cleanup,snapshot,parent,prepared,cap,storage,unit,transport,server,bridge,journal):
    import guard
    try:
        if snapshot is None:
            snapshot=_failure_snapshot(primary,parent,prepared,cap,storage,unit,transport,server,bridge,journal)
        require('unavailable'not in snapshot,'integrated_guest.diagnostic_unavailable')
        first=snapshot['primary'] if snapshot['primary'] is not None else integrated_failure.exception_snapshot(primary,snapshot['index'])
        evidence=integrated_failure.render(first,
            [integrated_failure.exception_snapshot(error,snapshot['index'])for error in cleanup],
            snapshot['before'],_diagnostic_state(storage,unit,transport,server,bridge,journal),snapshot['command'])
    except BaseException:
        # An invalid/foreign diagnostic object never gets serialized. Failure,
        # blocked state and the existing cleanup/outer poweroff remain mandatory.
        evidence={'schema':'ocv.integrated-native-chain-failure.v1','syntheticOnly':True,
            'privateInputs':False,'environmentIncluded':False,'messagesIncluded':False,
            'retryPermitted':False,'diagnosticUnavailable':True,'cleanupExceptionCount':len(cleanup)}
    raise guard.Refusal('integrated_guest.native_chain_uncertain',{'nativeChain':evidence}) from primary


def _cleanup_owned(unit,storage,journal,owner):
    """Original one-shot cleanup order; collect every error without redispatch."""
    errors=[]
    try:
        if unit._submit_attempted and 'stop' not in unit._attempted:
            unit.stop_owned_unit_normally(owner['unitName'])
            unit.owned_cgroup_empty(owner['unitName'])
    except BaseException as error:errors.append(error)
    try:
        if storage._mounted and 'unmount' not in storage._used:
            storage.unmount_test_normally()
    except BaseException as error:errors.append(error)
    try:journal.close()
    except BaseException as error:errors.append(error)
    return errors


def run_bound(parent, prepared, cap, bootstrap, peer, storage_io, unit_io, transport, *, identity):
    """One real native chain before the original generic Entry requests poweroff."""
    import ci_authority
    require(type(cap) is native_authority.SessionCapability and cap.kind == 'ci-native-proof' and
            type(bootstrap) is guest_bootstrap.VerifiedBootstrap and bootstrap.purpose == 'ci-native-proof' and
            type(peer) is guest_bootstrap.PeerAuthority and type(storage_io) is guest_storage.NativeStorageIO and
            type(unit_io) is guest_unit.NativeUnitIO and type(transport) is LocalGuestTransport,
            'integrated_guest.native_components_required')
    ci_authority._parent(parent, prepared)
    native_authority.require_capability(cap, 'storage', storage_io)
    native_authority.require_capability(cap, 'unit', unit_io)
    native_authority.require_capability(cap, 'mac', transport)
    run = parent.plan.build['runIdentity']
    expected_identity = {'sessionId': cap.owner['sessionId'], 'bootId': parent.plan.boot_id,
        'sourceManifestSha256': parent.plan.markers['ocv.source'], 'sourceCommit': run['sourceCommit'],
        'runId': run['runId'], 'runAttempt': run['runAttempt']}
    require(identity == expected_identity, 'integrated_guest.parent_identity')
    import copied_bootstrap_probe
    copied_bootstrap = copied_bootstrap_probe.run_native_proof(parent, prepared, cap.runtime_source)
    control = _control_directories(cap)
    storage = guest_storage.NativeStorageSession(cap, storage_io)
    unit = guest_unit.NativeUnitSession(cap, storage, unit_io)
    guest_journal = guest_server.GuestIntentJournal(control/'rpc-intents', cap.owner, uid=0)
    server = guest_server.GuestServer(cap, storage, unit, bootstrap, peer, guest_journal,
                                      now=unit_io.now)
    transport.bind(cap, server, peer)
    journal = durable_intent.DurableIntent(Path(cap.pins['macJournalRoot']), cap.owner,
        cap.pins['contextSha256'], sha(canonical(cap.pins)))
    transport.bind_journal(journal)
    bridge = mac_bridge.MacBridge(cap, transport, journal, now=unit_io.now)
    primary=snapshot=None;cleanup=[]
    try:
        bridge.prepare()
        bridge.start_and_replay()
        bridge.closeout(wait_seconds=240)
        require(server.outputs == {key: bridge.outcome[key] for key in ('stdout', 'stderr')} and
                server.report is not None, 'integrated_guest.closeout_custody')
        consumer = custody.Custody(control/'consumer-custody')
        consumer.preserve('worker-stdout', bridge.outcome['stdout'])
        consumer.preserve('worker-stderr', bridge.outcome['stderr'])
        accepted = consumer.accept_consumer(bridge.outcome['stdout'], bridge.outcome['stderr'],
            returncode=bridge.outcome['returncode'], timed_out=bridge.outcome['timedOut'],
            context_sha=sha(bridge.context_raw), report_sha=bridge.context['privacySha256'],
            expected_closure_sha=copier.closure_sha(bridge.staged['inputManifest'],
                bridge.context['sourceSha'], bridge.context['indexDigest']),
            pid=bridge.expected['pid'], uid=bridge.expected['uid'], gid=bridge.expected['gid'],
            expected_worker_sha=bridge.context['workerSha256'])
        require(accepted.get('status') == 'passed', 'integrated_guest.consumer_refused')
        bridge.request_copy_removal()
        audit = durable_intent.DurableIntent.audit_existing(journal.root_path, cap.owner['sessionId'])
        require(audit['status'] == 'settled_no_resume' and audit['unresolved'] == [] and
                bridge.phase == 'copies_removed' and server.empty and server.unmounted and
                storage.test_is_unmounted() is True, 'integrated_guest.final_closeout')
        closeout = {'schema': 'openclaw.mac-owned-unit-closeout.v1',
            'unitName': cap.owner['unitName'], 'ownedCgroupEmpty': True,
            'reportSha256': sha(server.report), 'stdoutSha256': sha(server.outputs['stdout']),
            'stderrSha256': sha(server.outputs['stderr'])}
        checks = {key: True for key in integrated_capture.CHECK_KEYS}
        return integrated_capture.build_roles(identity=identity, checks=checks,
            capture=bridge.capture, context=bridge.context, owner=cap.owner, ready=bridge.ready,
            proof=bridge.replay['proof'], staging=bridge.staged['inputManifest'],
            outputs=server.outputs, outcome=bridge.outcome, report=server.report, closeout=closeout, audit=audit,
            copied_bootstrap=copied_bootstrap)
    except BaseException as error:
        primary=error
        try:snapshot=_failure_snapshot(error,parent,prepared,cap,storage,unit,transport,server,bridge,journal)
        except BaseException:snapshot={'unavailable':True}
    finally:
        # Never replay a poisoned request or duplicate an ambiguous STOP. The
        # original outer bootstrap still independently requests guest poweroff.
        if snapshot is None:
            try:snapshot=_failure_snapshot(None,parent,prepared,cap,storage,unit,transport,server,bridge,journal)
            except BaseException:snapshot={'unavailable':True}
        cleanup=_cleanup_owned(unit,storage,journal,cap.owner)
        if primary is not None or cleanup:
            _refuse_chain(primary if primary is not None else cleanup[0],cleanup,snapshot,
                parent,prepared,cap,storage,unit,transport,server,bridge,journal)


if __name__ == '__main__': raise SystemExit('integrated_guest_requires_genuine_bootstrap')

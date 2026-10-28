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
    finally:
        # Never replay a poisoned request or duplicate an ambiguous STOP. The
        # original outer bootstrap still independently requests guest poweroff.
        try:
            if unit._submit_attempted and 'stop' not in unit._attempted:
                unit.stop_owned_unit_normally(cap.owner['unitName'])
                unit.owned_cgroup_empty(cap.owner['unitName'])
        finally:
            try:
                if storage._mounted and 'unmount' not in storage._used:
                    storage.unmount_test_normally()
            finally: journal.close()


if __name__ == '__main__': raise SystemExit('integrated_guest_requires_genuine_bootstrap')

"""Mac-side fixed guest RPC and replay adapter; operational issuer absent.

This module never opens SSH, IAP, SDK or cloud connections.  The sole future
owner must bind a reviewed, strict owned transport and native capability.
Synthetic tests bind a fake one-call transport.  Guest JSON, caller Booleans
and guest positive verdicts do not create replay or custody authority.
"""
from __future__ import annotations

import base64
import binascii
import datetime as dt
import json
from pathlib import Path
import re

import controller
import durable_intent
import mac_replay
import native_authority
from protocol import canonical, sha, utc

ARMED = False
ROUTE_KIND = 'same-guest-local-encoded-ci'
MAX_REQUEST = durable_intent.MAX_REQUEST
MAX_RESPONSE = durable_intent.MAX_RESPONSE
MAX_AGGREGATE = 4 * 1024 * 1024
MAX_BYTES_VALUE = 2 * 1024 * 1024
MAX_OUTPUT = 131072
MAX_READY = 4096
REPORT_BYTES = 4315
REPORT_SHA256 = '0c2019ff9bd14f93681037d9961ac4c80a14600ef0fe0a99a5065a8aedc5b813'
DISK_IDS = ('11', '12')
PIN_KEYS = frozenset(('contextSha256', 'guestSourceSha256', 'profileSha256',
    'workerSha256', 'entrySha256', 'runtimeManifestSha256',
    'contextContractSha256', 'transportReceiptSha256'))
REPLAY_OWNER_KEYS = ('vmId', 'bootId', 'sessionId', 'unitName',
                     'guestSourceSha256')
CONTEXT_KEYS = frozenset(('bootId','consumerCode','contextNonce','entrySha256',
    'identityName','indexDigest','inputManifestSha256','maxJobSeconds',
    'mountPropagation','operation','privacyBytes','privacySha256',
    'profileSha256','runtimeManifestSha256','scannerSha','schema','sessionId',
    'sourceSha','unitName','vmId','workerDeadlineUtc','workerSha256'))


class Refusal(RuntimeError):
    pass


class UncertainOutcome(Refusal):
    requires_owned_outer_stop = True


def need(ok, code):
    if not ok:
        raise Refusal(code)


def _pairs(rows):
    value = {}
    for key, item in rows:
        need(key not in value, 'bridge.duplicate_json_key')
        value[key] = item
    return value


def _decode(raw, cap):
    need(type(raw) is bytes and len(raw) <= cap, 'bridge.frame_cap')
    try:
        value = json.loads(raw, object_pairs_hook=_pairs,
                           parse_constant=lambda _: need(False, 'bridge.nonfinite'))
    except (ValueError, UnicodeError, RecursionError):
        raise Refusal('bridge.json') from None
    need(canonical(value) == raw, 'bridge.not_canonical')
    return value


def _pack(value, depth=0):
    need(depth <= 16, 'bridge.depth')
    if type(value) is bytes:
        need(len(value) <= MAX_BYTES_VALUE, 'bridge.bytes_cap')
        return {'$bytes': base64.b64encode(value).decode('ascii')}
    if value is None or type(value) in (bool, int, str):
        need(type(value) is not int or -(2**63) <= value < 2**64,
             'bridge.integer_cap')
        need(type(value) is not str or len(value) <= 65536, 'bridge.string_cap')
        return value
    if type(value) in (list, tuple):
        need(len(value) <= 8192, 'bridge.list_cap')
        return [_pack(item, depth + 1) for item in value]
    need(type(value) is dict and len(value) <= 8192 and
         all(type(key) is str and len(key) <= 256 and key != '$bytes' for key in value),
         'bridge.type')
    return {key: _pack(item, depth + 1) for key, item in value.items()}


def _unpack(value, depth=0):
    need(depth <= 16, 'bridge.depth')
    if type(value) is dict and set(value) == {'$bytes'}:
        encoded = value['$bytes']
        need(type(encoded) is str and len(encoded) <=
             4 * ((MAX_BYTES_VALUE + 2) // 3), 'bridge.bytes_cap')
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise Refusal('bridge.base64') from None
        need(len(raw) <= MAX_BYTES_VALUE and
             base64.b64encode(raw).decode('ascii') == encoded,
             'bridge.base64')
        return raw
    if value is None or type(value) in (bool, int, str):
        need(type(value) is not int or -(2**63) <= value < 2**64,
             'bridge.integer_cap')
        need(type(value) is not str or len(value) <= 65536, 'bridge.string_cap')
        return value
    if type(value) is list:
        need(len(value) <= 8192, 'bridge.list_cap')
        return [_unpack(item, depth + 1) for item in value]
    need(type(value) is dict and len(value) <= 8192 and
         all(type(key) is str and len(key) <= 256 and key != '$bytes' for key in value),
         'bridge.type')
    return {key: _unpack(item, depth + 1) for key, item in value.items()}


def _hex64(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


class MacBridge:
    """One in-memory generation; local journal makes uncertain effects terminal."""
    def __init__(self, capability, transport, journal, *, now):
        native_authority.require_capability(capability, 'mac', transport)
        need(type(journal) is durable_intent.DurableIntent and callable(now) and
             callable(getattr(transport, 'exchange_once', None)),
             'bridge.interface')
        self.capability, self.transport, self.journal, self.now = (
            capability, transport, journal, now)
        self.owner, self.context, self.pins = (
            capability.owner, capability.context, capability.pins)
        need(PIN_KEYS <= set(self.pins) and
             all(_hex64(self.pins[k]) for k in PIN_KEYS) and
             type(self.pins.get('macJournalRoot')) is str and
             Path(self.pins['macJournalRoot']).is_absolute() and
             Path(self.pins['macJournalRoot']).resolve() ==
             Path(self.pins['macJournalRoot']) == journal.root_path,
             'bridge.pin_schema')
        need(self.pins['guestSourceSha256'] == self.owner['guestSourceSha256'] and
             self.pins['contextSha256'] == sha(canonical(self.context)) and
             set(self.context) == CONTEXT_KEYS and
             all(self.pins[k] == self.context[k] for k in
                 ('profileSha256', 'workerSha256', 'entrySha256',
                  'runtimeManifestSha256')) and
             self.context.get('schema') == 'openclaw.retained-verifier-context.v1' and
             self.context.get('inputManifestSha256') is None and
             self.context.get('workerDeadlineUtc') is None and
             self.context.get('identityName') ==
                 'ocv-' + self.owner['sessionId'][:24] and
             _hex64(self.context.get('contextNonce')) and
             _hex64(self.context.get('privacySha256')) and
             type(self.context.get('privacyBytes')) is int and
             self.context['privacyBytes'] == REPORT_BYTES and
             type(self.context.get('consumerCode')) is dict and
             type(self.context.get('sourceSha')) is str and
             re.fullmatch('[0-9a-f]{40}', self.context['sourceSha']) and
             type(self.context.get('scannerSha')) is str and
             re.fullmatch('[0-9a-f]{40}', self.context['scannerSha']) and
             type(self.context.get('indexDigest')) is str and
             re.fullmatch('sha256:[0-9a-f]{64}', self.context['indexDigest']) and
             type(self.context.get('maxJobSeconds')) is int and
             self.context['maxJobSeconds'] == 300 and
             self.context.get('operation') == 'retained-report-only' and
             self.context.get('mountPropagation') == 'private' and
             all(self.context.get(k) == self.owner[k] for k in
                 ('vmId', 'bootId', 'sessionId', 'unitName')),
             'bridge.source_join')
        binding = getattr(transport, 'route_binding', None)
        need(type(binding) is dict and set(binding) ==
             {'owner', 'route', 'sourceBundleSha256', 'receiptSha256'} and
             binding['owner'] == self.owner and
             binding['route'] == ROUTE_KIND and
             binding['sourceBundleSha256'] == self.owner['guestSourceSha256'] and
             binding['receiptSha256'] == self.pins['transportReceiptSha256'] and
             getattr(transport, 'nonreconnecting', None) is True,
             'bridge.route_join')
        self.route_raw = canonical(binding)
        need(journal.owner == self.owner and
             journal.context_sha256 == self.pins['contextSha256'] and
             journal.pins_sha256 == sha(canonical(self.pins)) and
             journal.sequence == 0 and journal.pending is None,
             'bridge.journal_join')
        self.sequence = self.response_bytes = 0
        self.phase = 'new'
        self.blocked = False
        self.staged = self.capture = self.replay = self.ready = None
        self.context_raw = canonical(self.context)
        self.expected = self.outcome = None
        self.custody = None
        self.outer_stop_used = False
        self._gate = None

    def _exchange(self, method, args):
        need(not self.blocked and self.journal.sequence == self.sequence and
             self.sequence < durable_intent.MAX_CALLS and
             type(method) is str and method in durable_intent.METHODS and
             type(args) is list, 'bridge.blocked_or_method')
        need(getattr(self.transport, 'nonreconnecting', None) is True and
             canonical(getattr(self.transport, 'route_binding', None)) ==
             self.route_raw, 'bridge.route_changed')
        cleanup = method in {'stop_owned_unit_normally', 'owned_cgroup_empty',
            'test_is_unmounted', 'collect_owned_evidence',
            'read_exact_copied_report','remove_only_copied_session_files_after_custody'}
        if method == 'release_copied_inputs_then_gate':
            need(self._gate is not None and args == [self._gate] and
                 self.phase == 'started', 'bridge.replay_gate_unissued')
        if method == 'remove_only_copied_session_files_after_custody':
            need(self.phase == 'closed' and self.journal.custody_claimed and
                 self.journal.custody_digest is not None,
                 'bridge.custody_gate_unissued')
        try:
            now = self.now()
            native_authority.require_time(self.capability, now, cleanup=cleanup)
            endpoint = utc(self.owner['providerStopAt'])
            if cleanup:
                endpoint = min(endpoint + dt.timedelta(seconds=600),
                               utc(self.owner['executionDeadlineUtc']))
                need(now < endpoint,
                     'bridge.cleanup_window')
        except BaseException:
            raise Refusal('bridge.deadline') from None
        request = canonical({'schema': 'openclaw.private-guest-request.v1',
            'sequence': self.sequence, 'owner': self.owner,
            'method': method, 'arguments': _pack(args)})
        need(len(request) <= MAX_REQUEST, 'bridge.request_cap')
        sequence = self.sequence
        remaining = MAX_AGGREGATE - self.response_bytes
        need(remaining > 0, 'bridge.aggregate_cap')
        response_cap = min(MAX_RESPONSE, remaining)
        self.journal.begin(sequence, method, request)  # Fsync before any transport call.
        response = None
        try:
            response = self.transport.exchange_once(request, max_response=response_cap,
                                                    deadline_utc=endpoint)
            value = _decode(response, response_cap)
            need(type(value) is dict and set(value) ==
                 {'schema', 'owner', 'sequence', 'method', 'status', 'value'} and
                 value['schema'] == 'openclaw.private-guest-response.v1' and
                 value['owner'] == self.owner and
                 type(value['sequence']) is int and value['sequence'] == sequence and
                 value['method'] == method and value['status'] == 'returned',
                 'bridge.response_join')
            result = _unpack(value['value'])
            need(self.response_bytes + len(response) <= MAX_AGGREGATE,
                 'bridge.aggregate_cap')
            self.journal.settle(sequence, method, response)
            self.response_bytes += len(response)
            self.sequence += 1
            return result
        except BaseException as error:
            self.blocked = True
            try:
                # The transport may expose only bytes it actually received.
                # Retain a private bounded sample and full hash if available.
                error_partial = response if response is not None else \
                    getattr(error, 'partial_bytes', None)
                # No opaque exception message or path is serialized.
                self.journal.mark_uncertain(sequence, method,
                                            'transport_or_response_uncertain',
                                            error_partial)
            except BaseException:
                pass  # The durable intent still forbids restart and blind retry.
            raise UncertainOutcome('bridge.effect_or_response_uncertain') from None

    def prepare(self):
        need(self.phase == 'new', 'bridge.order')
        self.phase = 'preparing'
        identity = self._exchange('identity_once', [])
        need(identity == self.owner, 'bridge.identity')
        preflight = self._exchange('preflight', [self.context])
        need(type(preflight) is dict and preflight.get('fresh') is True and
             preflight.get('vmId') == self.owner['vmId'] and
             preflight.get('testReadOnly') is True and
             type(preflight.get('bootFreeBytes')) is int and
             preflight['bootFreeBytes'] >= 2 * 1024 * 1024 * 1024 and
             preflight.get('diskIds') == list(DISK_IDS) and
             preflight.get('noOtherOwner') is True and
             preflight.get('runtimeAuthoritiesBound') is True,
             'bridge.preflight')
        staged = self._exchange('prepare', [self.context])
        need(type(staged) is dict and
             set(staged) == {'inputManifestSha256', 'inputManifest', 'runtimeManifestSha256',
              'copiesRootOwned', 'inputMode', 'propertiesSha256',
              'stagedAtUtc', 'workerDeadlineUtc'} and
             type(staged['inputManifest']) is dict and
             _hex64(staged['inputManifestSha256']) and
             staged['inputManifest'].get('manifestSha256') == staged['inputManifestSha256'] and
             sha(canonical({k:v for k,v in staged['inputManifest'].items()
                            if k != 'manifestSha256'})) == staged['inputManifestSha256'] and
             staged['runtimeManifestSha256'] == self.context['runtimeManifestSha256'] and
             staged['copiesRootOwned'] is True and
             type(staged['inputMode']) is int and staged['inputMode'] == 0 and
             _hex64(staged['propertiesSha256']), 'bridge.staging_join')
        staged_at = utc(staged['stagedAtUtc'])
        deadline = utc(staged['workerDeadlineUtc'])
        now = self.now()
        # Allow at most 5 s positive guest-clock skew and 30 s transport age.
        # A slow copy cannot inherit a pre-copy worker deadline.
        need(type(now) is dt.datetime and now.tzinfo is not None and
             -5 <= (now - staged_at).total_seconds() <= 30 and
             deadline == staged_at + dt.timedelta(seconds=300) and
             deadline + dt.timedelta(seconds=120) <=
                 utc(self.owner['providerStopAt']),
             'bridge.staged_deadline')
        self.journal.preserve('staging-manifest', canonical(staged['inputManifest']))
        self.staged = staged
        # Only two source-returned fields may change after physical staging.
        self.context = dict(self.context,
            inputManifestSha256=staged['inputManifestSha256'],
            workerDeadlineUtc=staged['workerDeadlineUtc'])
        self.context_raw = canonical(self.context)
        need(len(self.context_raw) <= 16384, 'bridge.context_cap')
        self.journal.bind_final_context(self.context_raw)
        self._exchange('write_public_context_once', [self.context_raw])
        self._exchange('unmount_test_normally', [])
        need(self._exchange('test_is_unmounted', []) is True,
             'bridge.test_still_mounted')
        self.phase = 'prepared'
        return {'schema': 'openclaw.mac-bridge-prepared.v1',
                'contextSha256': sha(self.context_raw),
                'inputManifestSha256': staged['inputManifestSha256'],
                'qualificationAuthority': False}

    def start_and_replay(self):
        need(self.phase == 'prepared', 'bridge.order')
        self._exchange('start_worker_once', [self.context])
        self.phase = 'started'
        capture = self._exchange('worker_observation', [self.context])
        need(type(capture) is dict and set(capture) ==
             {'schema', 'expected', 'unit', 'binding', 'snapshot',
              'guestProofSha256'} and
             capture['schema'] == 'openclaw.private-host-capture.v1' and
             type(capture['snapshot']) is bytes and
             len(capture['snapshot']) <= 2 * 1024 * 1024 and
             _hex64(capture['guestProofSha256']), 'bridge.capture_schema')
        ready = self._exchange('read_ready_once', [])
        need(type(ready) is bytes and len(ready) <= MAX_READY, 'bridge.ready_cap')
        self.journal.preserve('host-snapshot', capture['snapshot'])
        self.journal.preserve('ready-frame', ready)
        owner = {key: self.owner[key] for key in REPLAY_OWNER_KEYS}
        replay = mac_replay.evaluate_bound(capture, self.context, owner,
                                          now=self.now(), capability=self.capability)
        need(type(replay) is dict and replay.get('schema') ==
             'openclaw.private-host-replay.v1' and replay.get('status') == 'passed' and
             replay.get('ownerGuestSourceSha256') == self.owner['guestSourceSha256'] and
             type(replay.get('proof')) is dict and
             type(replay.get('snapshot')) is dict and
             replay['snapshot'].get('snapshotSha256') == sha(capture['snapshot']),
             'bridge.replay_join')
        controller.ready_binding(ready, self.context, self.context_raw,
                                 capture['expected'])
        self.journal.preserve('host-proof', canonical(replay['proof']))
        gate = controller.gate(self.context, self.context_raw,
                               replay['proof'], self.now())
        need(gate.get('contextSha256') == sha(self.context_raw) and
             gate.get('status') == 'passed' and gate.get('inputReleased') is True,
             'bridge.gate_join')
        self._gate = gate
        self._exchange('release_copied_inputs_then_gate', [gate])
        self._gate = None
        self.capture, self.ready, self.replay = capture, ready, replay
        self.expected = capture['expected']
        self.phase = 'admitted'
        return {'schema': 'openclaw.mac-bridge-admission.v1',
                'proofSha256': replay['proof']['factsSha256'],
                'contextSha256': sha(self.context_raw),
                'qualificationAuthority': False}

    def closeout(self, *, wait_seconds=None):
        """Normal owned unit closeout; no retries after an uncertain RPC."""
        need(self.phase in ('started', 'admitted') and not self.blocked,
             'bridge.closeout_order')
        admitted = self.phase == 'admitted'
        self.phase = 'closing'
        if admitted:
            need(type(wait_seconds) is int and 0 < wait_seconds <= 240,
                 'bridge.wait_seconds')
            self.outcome = self._exchange('wait_worker_once', [wait_seconds])
            need(type(self.outcome) is dict and set(self.outcome) ==
                 {'stdout', 'stderr', 'returncode', 'timedOut'} and
                 all(type(self.outcome[k]) is bytes and len(self.outcome[k]) <= MAX_OUTPUT
                     for k in ('stdout', 'stderr')) and
                 type(self.outcome['returncode']) is int and
                 -255 <= self.outcome['returncode'] <= 255 and
                 type(self.outcome['timedOut']) is bool,
                 'bridge.wait_result')
        else:
            need(wait_seconds is None, 'bridge.wait_without_gate')
        self._exchange('stop_owned_unit_normally', [self.owner['unitName']])
        need(self._exchange('owned_cgroup_empty', [self.owner['unitName']]) is True,
             'bridge.cgroup_not_empty')
        outputs = self._exchange('collect_owned_evidence', [])
        need(type(outputs) is dict and set(outputs) == {'stdout', 'stderr'} and
             all(type(outputs[k]) is bytes and len(outputs[k]) <= MAX_OUTPUT
                 for k in ('stdout', 'stderr')), 'bridge.outputs')
        if admitted:
            need(all(outputs[k] == self.outcome[k] for k in ('stdout', 'stderr')),
                 'bridge.output_custody_join')
        report = self._exchange('read_exact_copied_report', [])
        need(type(report) is bytes and len(report) == REPORT_BYTES and
             sha(report) == self.context['privacySha256'] == REPORT_SHA256,
             'bridge.report_pin')
        for role, raw in (('worker-stdout', outputs['stdout']),
                          ('worker-stderr', outputs['stderr']), ('report', report)):
            self.journal.preserve(role, raw)
        self.journal.preserve('closeout', canonical({
            'schema': 'openclaw.mac-owned-unit-closeout.v1',
            'unitName': self.owner['unitName'], 'ownedCgroupEmpty': True,
            'reportSha256': sha(report), 'stdoutSha256': sha(outputs['stdout']),
            'stderrSha256': sha(outputs['stderr'])}))
        self.phase = 'closed'
        return {'schema': 'openclaw.mac-bridge-closeout.v1',
                'reportSha256': sha(report), 'ownedCgroupEmpty': True,
                'consumerQualified': False, 'qualificationAuthority': False}

    def request_copy_removal(self):
        need(self.phase == 'closed' and not self.blocked and self.replay is not None,
             'bridge.removal_order')
        # No caller Boolean, JSON or guest verdict is an acceptable substitute.
        self.custody = self.journal.custody_ack()
        need(type(self.custody) is durable_intent.DurableMacCustody and
             self.custody.belongs_to(self.journal), 'bridge.custody_unissued')
        self.journal.claim_custody_for_removal(self.custody)
        binder=getattr(self.transport,'bind_custody_ack',None)
        need(callable(binder),'bridge.custody_channel_unissued')
        try:binder(self.custody,self.journal)
        except BaseException:
            self.blocked=True
            raise
        result = self._exchange('remove_only_copied_session_files_after_custody', [])
        need(result is None, 'bridge.removal_response')
        self.phase = 'copies_removed'
        return {'schema': 'openclaw.mac-bridge-removal.v1',
                'custodySha256': self.journal.custody_digest,
                'qualificationAuthority': False}

    def request_owned_outer_stop_once(self, owner_port):
        """Independent fail-closed closeout hook; never reuses the guest stream."""
        native_authority.require_capability(self.capability, 'outer_stop', owner_port)
        need(not self.outer_stop_used and
             callable(getattr(owner_port, 'normal_stop_once', None)),
             'bridge.outer_stop_consumed')
        self.outer_stop_used = True
        self.journal.begin_outer_stop()
        try:
            result = owner_port.normal_stop_once(self.owner)
            need(type(result) is dict and set(result) ==
                 {'vmState','diskIds','retained','transportClosed'} and
                 result['vmState'] == 'TERMINATED' and
                 result['diskIds'] == list(DISK_IDS) and
                 result['retained'] is True and
                 result['transportClosed'] is True,
                 'bridge.outer_stop_binding')
            self.journal.settle_outer_stop(canonical(result))
            return result
        except BaseException:
            try:
                self.journal.mark_outer_stop_uncertain()
            except BaseException:
                pass
            raise UncertainOutcome('bridge.outer_stop_uncertain') from None


if __name__ == '__main__':
    raise SystemExit('mac_bridge_native_authority_unissued')

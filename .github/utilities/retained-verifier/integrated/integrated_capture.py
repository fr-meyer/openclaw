"""Bounded raw custody roles for ONE combined generic/integrated serial frame.

The outer frame remains ocv.ci-result.v1. The physical serial emitter is one-use,
so these roles must be merged into its existing custody, never emitted as a
second frame or wrapped in a second base64 JSON envelope. Historical host replay
does not issue a fresh guest gate or private VM admission.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re

SNAPSHOT_CAP = 2 * 1024 * 1024
RAW_CAP = 3 * 1024 * 1024 - 65536
JSON_CAP = 4 * 1024 * 1024
SERIAL_CAP = 6 * 1024 * 1024
OUTER_STDOUT_CAP = SERIAL_CAP
OUTER_STDERR_CAP = 1024 * 1024
PREFIX = b'OCV_RESULT_V1:'
EXPECTED_WORKER_SHA256 = 'e028794e30e76a8871ff6e51d660c0efacd3a6effc05067de0c978fe3bac83d2'
ROLE_CAPS = {
    'integrated-summary': 16384,
    'integrated-host-snapshot': SNAPSHOT_CAP,
    'integrated-capture-metadata': 131072,
    'integrated-controller-context': 16384,
    'integrated-owner': 4096,
    'integrated-ready-frame': 4096,
    'integrated-host-proof': 131072,
    'integrated-staging-manifest': 131072,
    'integrated-worker-stdout': 65536,
    'integrated-worker-stderr': 65536,
    'integrated-worker-outcome': 16384,
    'integrated-report': 262144,
    'integrated-closeout': 16384,
    'integrated-durable-audit': 16384,
    'integrated-copied-bootstrap': 65536,
}
BINARY_ROLES = frozenset(('integrated-worker-stdout', 'integrated-worker-stderr'))
IDENTITY_KEYS = frozenset(('sessionId', 'bootId', 'sourceManifestSha256', 'sourceCommit', 'runId', 'runAttempt'))
CHECK_KEYS = frozenset(('genuineBootstrap', 'readOnlyTestMounted', 'normalTestUnmount',
    'exactNativeStorage', 'exactNativeUnit', 'stableTypedHostCapture', 'freshMacReplay',
    'readyGateJoin', 'maintainedConsumerAccepted', 'normalOwnedStop', 'ownedCgroupEmpty',
    'durableCustody', 'copiedInputsRemoved', 'copiedControllerOrigins'))
GENERIC_ROLES = frozenset(('report', 'host-result', 'staging-manifest', 'worker-stdout',
    'worker-stderr', 'controller-context', 'consumer-compatibility', 'host-expectation',
    'unit-readback', 'worker-stderr-raw', 'native-isolation-cases'))


class Refusal(ValueError):
    pass


def need(ok, code):
    if not ok:
        raise Refusal(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw, cap):
    need(type(raw) is bytes and 0 < len(raw) <= cap, 'integrated_capture.json_cap')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'integrated_capture.duplicate_key'); result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _: need(False, 'integrated_capture.nonfinite'))
    except (ValueError, UnicodeError, RecursionError):
        raise Refusal('integrated_capture.json') from None
    need(canonical(value) == raw, 'integrated_capture.noncanonical')
    return value


def _identity(value):
    need(type(value) is dict and set(value) == IDENTITY_KEYS and
         all(type(v) is str for v in value.values()) and
         re.fullmatch('[0-9a-f]{32}', value['sessionId']) and
         re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', value['bootId']) and
         re.fullmatch('[0-9a-f]{64}', value['sourceManifestSha256']) and
         re.fullmatch('[0-9a-f]{40}', value['sourceCommit']) and
         re.fullmatch('[1-9][0-9]{0,19}', value['runId']) and value['runAttempt'] == '1',
         'integrated_capture.identity')
    return dict(value)


def summary(identity, checks):
    _identity(identity)
    need(type(checks) is dict and set(checks) == CHECK_KEYS and
         all(value is True for value in checks.values()), 'integrated_capture.incomplete_checks')
    return {'schema': 'ocv.integrated-native-chain.v1', 'status': 'passed',
            'fixtureOnly': True, 'candidateImage': False, 'candidateQualified': False,
            'privateVmAdmission': False, 'authorityKind': 'ci-native-proof',
            'identity': dict(identity), 'checks': dict(checks)}


def build_roles(*, identity, checks, capture, context, owner, ready, proof,
                staging, outputs, outcome, report, closeout, audit, copied_bootstrap):
    need(type(capture) is dict and set(capture) ==
         {'schema', 'expected', 'unit', 'binding', 'snapshot', 'guestProofSha256'} and
         type(capture['snapshot']) is bytes and len(capture['snapshot']) <= SNAPSHOT_CAP and
         type(outputs) is dict and set(outputs) == {'stdout', 'stderr'},
         'integrated_capture.source_shape')
    roles = {
        'integrated-summary': canonical(summary(identity, checks)),
        'integrated-host-snapshot': capture['snapshot'],
        'integrated-capture-metadata': canonical({k: v for k, v in capture.items() if k != 'snapshot'}),
        'integrated-controller-context': canonical(context),
        'integrated-owner': canonical(owner), 'integrated-ready-frame': ready,
        'integrated-host-proof': canonical(proof),
        'integrated-staging-manifest': canonical(staging),
        'integrated-worker-stdout': outputs['stdout'],
        'integrated-worker-stderr': outputs['stderr'], 'integrated-report': report,
        'integrated-worker-outcome': canonical({'returncode': outcome['returncode'],
            'timedOut': outcome['timedOut'], 'stdoutSha256': sha(outputs['stdout']),
            'stderrSha256': sha(outputs['stderr'])}),
        'integrated-closeout': canonical(closeout), 'integrated-durable-audit': canonical(audit),
        'integrated-copied-bootstrap': canonical({'proof': copied_bootstrap['proof'],
            'wire': decode(copied_bootstrap['raw'], 16384),
            'scriptSha256': copied_bootstrap['scriptSha256'],'placement':copied_bootstrap['placement'],
            'providedSelinux':copied_bootstrap['providedSelinux']}),
    }
    validate_roles(roles)
    return roles


def validate_roles(roles):
    need(type(roles) is dict and set(roles) == set(ROLE_CAPS), 'integrated_capture.roles')
    total = 0
    for role, cap in ROLE_CAPS.items():
        raw = roles[role]
        need(type(raw) is bytes and len(raw) <= cap, 'integrated_capture.role_cap')
        total += len(raw); need(total <= RAW_CAP, 'integrated_capture.raw_cap')
        if role == 'integrated-ready-frame':
            need(raw.endswith(b'\n') and raw.count(b'\n') == 1,
                 'integrated_capture.ready_frame')
            decode(raw[:-1], cap)
        elif role not in BINARY_ROLES:
            decode(raw, cap)
    return total


def combine_custody(legacy, roles):
    """Pure merge specification for the single existing bootstrap emitter."""
    validate_roles(roles)
    need(type(legacy) is dict and set(legacy) == {'schema', 'rawBytes', 'files'} and
         legacy['schema'] == 'ocv.custody.v1' and type(legacy['files']) is list and
         type(legacy['rawBytes']) is int and 0 <= legacy['rawBytes'] <= 131072,
         'integrated_capture.legacy_custody')
    names = [row.get('role') for row in legacy['files'] if type(row) is dict]
    need(len(names) == len(legacy['files']) and len(names) == len(set(names)) and
         not set(names) & set(roles), 'integrated_capture.role_collision')
    rows = [dict(row) for row in legacy['files']]
    for role, raw in sorted(roles.items()):
        rows.append({'role': role, 'bytes': len(raw), 'sha256': sha(raw),
            'base64': base64.b64encode(raw).decode('ascii'),
            'sourceBytes': len(raw), 'sourceSha256': sha(raw), 'truncated': False})
    total = legacy['rawBytes'] + sum(len(raw) for raw in roles.values())
    need(total <= RAW_CAP, 'integrated_capture.combined_raw_cap')
    return {'schema': 'ocv.custody.v1', 'rawBytes': total, 'files': rows}


def serial_frame(value):
    need(type(value) is dict and value.get('schema') == 'ocv.ci-result.v1',
         'integrated_capture.outer_schema')
    raw = canonical(value)
    need(len(raw) <= JSON_CAP, 'integrated_capture.envelope_cap')
    frame = PREFIX + base64.b64encode(raw) + b'\n'
    need(len(frame) <= SERIAL_CAP, 'integrated_capture.serial_cap')
    return frame


def verify_roles(roles, expected, *, source_replay, runtime_rows=None, expected_copied_root=None):
    """Historical pure host replay; `source_replay` is a pinned source callback.

    Native outer-exit custody and the original seven-case verifier are separate
    required callers. A late replay uses the recorded finish time only to check
    historical consistency and can never issue fresh admission/release.
    """
    validate_roles(roles); _identity(expected)
    recorded = decode(roles['integrated-summary'], ROLE_CAPS['integrated-summary'])
    need(recorded == summary(expected, {key: True for key in CHECK_KEYS}),
         'integrated_capture.summary_join')
    context = decode(roles['integrated-controller-context'], 16384)
    owner = decode(roles['integrated-owner'], 4096)
    capture = decode(roles['integrated-capture-metadata'], 131072)
    capture['snapshot'] = roles['integrated-host-snapshot']
    need(type(owner) is dict and owner.get('sessionId') == expected['sessionId'] and
         owner.get('bootId') == expected['bootId'] and
         all(context.get(k) == owner.get(k) for k in ('vmId', 'bootId', 'sessionId', 'unitName')),
         'integrated_capture.owner_join')
    need(callable(source_replay), 'integrated_capture.source_replay_missing')
    replay = source_replay(capture, context, owner, roles=roles, runtime_rows=runtime_rows,
                           historical_finished_at=capture['binding']['finishedAtUtc'],
                           expected_copied_root=expected_copied_root)
    proof = decode(roles['integrated-host-proof'], 131072)
    need(type(replay) is dict and replay.get('schema') == 'ocv.integrated-source-replay.v1' and
         replay.get('status') == 'passed' and
         replay.get('proof') == proof and type(replay.get('snapshot')) is dict and
         replay['snapshot'].get('snapshotSha256') == sha(capture['snapshot']) and
         replay.get('readyFrameSha256') == sha(roles['integrated-ready-frame']) and
         replay.get('consumerStdoutSha256') == sha(roles['integrated-worker-stdout']) and
         replay.get('consumerStderrSha256') == sha(roles['integrated-worker-stderr']),
         'integrated_capture.replay_join')
    need(type(context.get('privacyBytes')) is int and
         len(roles['integrated-report']) == context['privacyBytes'] and
         sha(roles['integrated-report']) == context.get('privacySha256'),
         'integrated_capture.report_join')
    closeout = decode(roles['integrated-closeout'], 16384)
    need(closeout == {'schema': 'openclaw.mac-owned-unit-closeout.v1',
         'unitName': owner['unitName'], 'ownedCgroupEmpty': True,
         'reportSha256': sha(roles['integrated-report']),
         'stdoutSha256': sha(roles['integrated-worker-stdout']),
         'stderrSha256': sha(roles['integrated-worker-stderr'])},
         'integrated_capture.closeout_join')
    audit = decode(roles['integrated-durable-audit'], 16384)
    need(type(audit) is dict and audit.get('schema') == 'openclaw.mac-intent-audit.v1' and
         audit.get('sessionId') == expected['sessionId'] and
         audit.get('status') == 'settled_no_resume' and audit.get('unresolved') == [] and
         audit.get('dispatchPermitted') is False, 'integrated_capture.durable_join')
    return {'schema': 'ocv.integrated-historical-replay.v1', 'status': 'passed',
            'snapshotSha256': sha(capture['snapshot']),
            'contextSha256': sha(roles['integrated-controller-context']),
            'historicalConsistencyOnly': True, 'freshAdmissionAuthority': False,
            'privateVmAdmission': False, 'candidateQualified': False}


def replay_copied_controller(raw,runtime_rows,expected_root,boot_id,*,historical=False):
    import copied_bootstrap_probe
    import copied_location
    need(type(historical)is bool,'integrated_capture.historical_mode')
    copied=decode(raw,65536)
    need(historical or (type(copied)is dict and 'providedSelinux'in copied),
        'integrated_capture.current_provided_probe_required')
    need(type(copied) is dict and set(copied)in({'proof','wire','scriptSha256','placement'},{'proof','wire','scriptSha256','placement','providedSelinux'}) and
        type(copied['proof']) is dict and type(copied['scriptSha256']) is str,
        'integrated_capture.copied_controller_shape')
    need(type(expected_root) is str and copied['proof'].get('root')==expected_root,
         'integrated_capture.copied_root_scope')
    copied_location.validate_pair(copied['placement'],expected_root,runtime_rows,boot_id)
    proof=copied_bootstrap_probe.validate_result(canonical(copied['wire']),expected_root,runtime_rows)
    need(proof==copied['proof'] and copied['scriptSha256']==
        sha(copied_bootstrap_probe.probe_script(expected_root,runtime_rows)),
        'integrated_capture.copied_controller_binding')
    if 'providedSelinux'in copied:
        copied_bootstrap_probe.validate_provided_selinux_proof(copied['providedSelinux'],expected_root,runtime_rows,boot_id)
    return proof


def historical_source_replay(capture, context, owner, *, roles, runtime_rows, historical_finished_at,expected_copied_root):
    """Source-owned probe/ready/maintained-consumer replay, without issuing a gate."""
    import controller
    import copier
    import custody
    import guest_unit
    import mac_replay
    import protocol
    import worker
    need(type(EXPECTED_WORKER_SHA256) is str and
         context.get('workerSha256') == EXPECTED_WORKER_SHA256 and
         context.get('entrySha256') == guest_unit.HELPER_SHA256,
         'integrated_capture.source_worker_pin')
    historical_time = protocol.utc(historical_finished_at)
    worker.validate_context(context, protocol, historical_time, EXPECTED_WORKER_SHA256)
    replay_copied_controller(roles['integrated-copied-bootstrap'],runtime_rows,expected_copied_root,owner['bootId'])
    replay_owner = {key: owner[key] for key in
                    ('vmId', 'bootId', 'sessionId', 'unitName', 'guestSourceSha256')}
    replay = mac_replay._evaluate(capture, context, replay_owner,
        now=historical_time, source_sha=owner['guestSourceSha256'])
    controller.ready_binding(roles['integrated-ready-frame'], context,
                             roles['integrated-controller-context'], capture['expected'])
    outcome = decode(roles['integrated-worker-outcome'], 16384)
    need(type(outcome) is dict and set(outcome) ==
         {'returncode', 'timedOut', 'stdoutSha256', 'stderrSha256'} and
         type(outcome['returncode']) is int and type(outcome['timedOut']) is bool and
         outcome['stdoutSha256'] == sha(roles['integrated-worker-stdout']) and
         outcome['stderrSha256'] == sha(roles['integrated-worker-stderr']),
         'integrated_capture.outcome_join')
    preserved = object.__new__(custody.Custody)
    preserved.rows = {name: custody.bounded(raw, custody.SLOTS[name])[0] for name, raw in
        (('worker-stdout', roles['integrated-worker-stdout']),
         ('worker-stderr', roles['integrated-worker-stderr']))}
    expected = capture['expected']
    preserved.accept_consumer(roles['integrated-worker-stdout'], roles['integrated-worker-stderr'],
        returncode=outcome['returncode'], timed_out=outcome['timedOut'],
        context_sha=sha(roles['integrated-controller-context']), report_sha=context['privacySha256'],
        expected_closure_sha=copier.closure_sha(decode(roles['integrated-staging-manifest'], 131072),
            context['sourceSha'], context['indexDigest']), pid=expected['pid'], uid=expected['uid'],
        gid=expected['gid'], expected_worker_sha=EXPECTED_WORKER_SHA256)
    return {'schema': 'ocv.integrated-source-replay.v1', 'status': 'passed',
        'proof': replay['proof'], 'snapshot': replay['snapshot'],
        'readyFrameSha256': sha(roles['integrated-ready-frame']),
        'consumerStdoutSha256': sha(roles['integrated-worker-stdout']),
        'consumerStderrSha256': sha(roles['integrated-worker-stderr'])}


def expected_runtime_rows(runtime, build):
    """Normalize only host-authenticated current build-control representations."""
    need(type(runtime) is dict and type(runtime.get('files')) is list and
         type(runtime.get('helper')) is dict and type(build) is dict,
         'integrated_capture.runtime_controls')
    rows = []
    for row in runtime['files']:
        need(type(row) is dict and set(row) == {'path', 'sourcePath', 'bytes', 'sha256', 'mode'},
             'integrated_capture.runtime_control_row')
        rows.append({key: row[key] for key in ('path', 'bytes', 'sha256', 'mode')})
    helper = runtime['helper']
    need(helper.get('path') == 'code/static-entry' and helper.get('sha256') == build.get('helperSha256'),
         'integrated_capture.helper_control')
    rows.append({key: helper[key] for key in ('path', 'bytes', 'sha256')} | {'mode': 0o555})
    for row in rows:
        row['archivePath'] = 'static-entry' if row['path'] == 'code/static-entry' else 'runtime/'+row['path']
    import copied_bootstrap_probe
    copied_bootstrap_probe._rows(rows)
    return sorted(rows, key=lambda row: row['path'])


def validate_combined(rows, expected, *, generic_validator, runtime_rows):
    """Require both unchanged seven-case replay and this exact native chain."""
    need(type(rows) is dict and set(rows) == GENERIC_ROLES | set(ROLE_CAPS) and
         callable(generic_validator), 'integrated_capture.combined_roles')
    legacy = {role: rows[role] for role in GENERIC_ROLES}
    result = generic_validator(legacy, expected)
    need(type(result) is dict and result == {'schema': 'ocv.source-replay.v1', 'status': 'passed',
        'contextSha256': sha(rows['controller-context']), 'hostResultSha256': sha(rows['host-result']),
        'consumerCompatibilitySha256': sha(rows['consumer-compatibility'])},
        'integrated_capture.generic_replay')
    generic_context = decode(rows['controller-context'], 16384)
    run = expected['runIdentity']
    identity = {'sessionId': sha(('integrated:'+expected['sessionId']).encode('ascii'))[:32],
        'bootId': generic_context['bootId'], 'sourceManifestSha256': expected['sourceManifestSha256'],
        'sourceCommit': run['sourceCommit'], 'runId': run['runId'], 'runAttempt': run['runAttempt']}
    import copied_location
    replay = verify_roles({role: rows[role] for role in ROLE_CAPS}, identity,
        source_replay=historical_source_replay, runtime_rows=runtime_rows,
        expected_copied_root=copied_location.root_for(runtime_rows,identity['sessionId']))
    need(replay['status'] == 'passed' and replay['freshAdmissionAuthority'] is False,
         'integrated_capture.integrated_replay')
    return result  # Existing outer verifier's exact receipt remains unchanged.


if __name__ == '__main__':
    raise SystemExit('integrated_capture_inert')

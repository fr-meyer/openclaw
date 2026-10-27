"""Bounded public CI serial custody. No process or native authority on import."""
import base64
import hashlib
import json
import re

PREFIX = b'OCV_RESULT_V1:'
SERIAL_CAP = 1048576
JSON_CAP = 262144
RAW_CAP = 131072
ROLE_CAPS = {'report':86000,'host-result':12288,'staging-manifest':12288,
             'worker-stdout':4096,'worker-stderr':4096,'host-diagnostics':8192,
             'controller-context':16384,'consumer-compatibility':12288,
             'host-expectation':12288,'unit-readback':4096,
             'worker-stderr-raw':8192,'native-isolation-cases':12288}


class Refusal(ValueError):
    pass


def require(value, code):
    if not value:
        raise Refusal(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw, cap=JSON_CAP):
    require(type(raw) is bytes and len(raw) <= cap, 'json_cap')
    def pairs(rows):
        result={}
        for key,value in rows:
            require(key not in result, 'json_duplicate')
            result[key]=value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _v: (_ for _ in ()).throw(Refusal('json_constant')))
    except (UnicodeError, json.JSONDecodeError):
        raise Refusal('json_shape') from None


def closed(value, keys, code):
    require(type(value) is dict and set(value) == set(keys), code)
    return value


def extract(stdout):
    require(type(stdout) is bytes and len(stdout) <= SERIAL_CAP, 'serial_cap')
    frames=[line[len(PREFIX):] for line in stdout.splitlines() if line.startswith(PREFIX)]
    require(len(frames) == 1, 'serial_single_frame')
    require(len(frames[0]) <= (JSON_CAP+2)//3*4, 'serial_frame_cap')
    try:
        raw=base64.b64decode(frames[0], validate=True)
    except (ValueError, base64.binascii.Error):
        raise Refusal('serial_base64') from None
    value=decode(raw)
    require(canonical(value) == raw, 'serial_noncanonical')
    return value


def custody_rows(value):
    closed(value, {'schema','rawBytes','files'}, 'custody_schema')
    require(value['schema'] == 'ocv.custody.v1' and type(value['files']) is list and
            0 < len(value['files']) <= len(ROLE_CAPS), 'custody_shape')
    result={};total=0;truncated=False
    for row in value['files']:
        closed(row, {'role','bytes','sha256','base64','sourceBytes','sourceSha256','truncated'}, 'custody_row')
        role=row['role']
        require(type(role) is str and role in ROLE_CAPS and role not in result, 'custody_role')
        require(type(row['bytes']) is int and 0 <= row['bytes'] <= ROLE_CAPS[role] and
                type(row['sourceBytes']) is int and row['sourceBytes'] >= row['bytes'] and
                type(row['truncated']) is bool and type(row['base64']) is str and
                len(row['base64']) <= (ROLE_CAPS[role]+2)//3*4, 'custody_size')
        try:
            data=base64.b64decode(row['base64'], validate=True)
        except (ValueError,base64.binascii.Error):
            raise Refusal('custody_base64') from None
        require(len(data) == row['bytes'] and sha(data) == row['sha256'] and
                type(row['sourceSha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sourceSha256']), 'custody_hash')
        require(row['truncated'] == (row['sourceBytes'] > row['bytes']), 'custody_truncation')
        if not row['truncated']:
            require(row['sourceSha256'] == row['sha256'], 'custody_full_hash')
        total+=len(data);require(total <= RAW_CAP, 'custody_total')
        result[role]=data;truncated |= row['truncated']
    require(type(value['rawBytes']) is int and value['rawBytes'] == total, 'custody_total_join')
    return result,truncated


def verify(outer, expected, *, source_validator=None):
    """Return both failed evidence and a computed pass; never accept a guest boolean.

    The caller preserves outer streams before calling. A missing/invalid frame
    raises, while a well-formed refusal returns its bounded custody. Source
    validator is the independently imported source-bound pure consumer join.
    """
    required={'status','timedOut','truncated','returncode','outerExited','ownedGroupGone',
              'streamsEOF','streamsClosed','ownershipRetained','stdout','stderr'}
    require(type(outer) is dict and required <= set(outer), 'outer_shape')
    value=extract(outer['stdout'])
    closed(value, {'schema','sessionId','runIdentity','sourceManifestSha256','buildControlSha256',
                   'status','adapterResult','custody'}, 'frame_schema')
    require(value['schema'] == 'ocv.ci-result.v1' and
            all(value[k] == expected[k] for k in ('sessionId','runIdentity','sourceManifestSha256','buildControlSha256')),
            'frame_identity')
    require(value['status'] in ('unit_passed_pending_outer_exit','refused','synthetic_validation') and
            type(value['adapterResult']) is dict, 'frame_status')
    rows,truncated=custody_rows(value['custody'])
    result={'schema':'ocv.host-ci-result.v1','status':'refused','reason':'guest_refused',
            'identity':{k:value[k] for k in ('sessionId','runIdentity','sourceManifestSha256','buildControlSha256')},
            'adapterResult':value['adapterResult'],'custody':value['custody'],
            'outer':{k:outer[k] for k in required if k not in ('stdout','stderr')},
            'stdoutSha256':sha(outer['stdout']),'stderrSha256':sha(outer['stderr']),
            'candidateQualified':False}
    success=(outer['status']=='outer_exit_passed' and outer['timedOut'] is False and
             outer['truncated'] is False and type(outer['returncode']) is int and outer['returncode']==0 and
             outer['outerExited'] is True and outer['ownedGroupGone'] is True and
             outer['streamsEOF'] is True and outer['streamsClosed'] is True and outer['ownershipRetained'] is False)
    if not success:
        result['reason']='outer_not_settled';return result
    if value['status'] != 'unit_passed_pending_outer_exit':
        return result
    adapter=value['adapterResult']
    if not (adapter.get('status') == 'unit_passed_pending_outer_exit' and adapter.get('unitStatus') == 'passed' and
            adapter.get('ownedUnitEmpty') is True and adapter.get('custodyComplete') is True and
            adapter.get('closeout') == {'shutdownRequested':True,'outerExitPending':True}):
        result['reason']='adapter_refused';return result
    if truncated or not {'report','host-result','staging-manifest','worker-stdout','worker-stderr','controller-context',
                         'consumer-compatibility','host-expectation','unit-readback',
                         'worker-stderr-raw','native-isolation-cases'} <= set(rows):
        result['reason']='custody_incomplete';return result
    require(callable(source_validator), 'source_validator_missing')
    # No filesystem, command or native effects occur in this source callback.
    # Unknown/False/None must not accidentally turn a missing join into a pass.
    replay=source_validator(rows, expected)
    require(type(replay) is dict and replay == {'schema':'ocv.source-replay.v1','status':'passed',
      'contextSha256':sha(rows['controller-context']),'hostResultSha256':sha(rows['host-result']),
      'consumerCompatibilitySha256':sha(rows['consumer-compatibility'])}, 'source_replay_refused')
    result.update(status='passed', reason=None, linuxIsolationProof=True)
    return result


if __name__ == '__main__':
    raise SystemExit('inert_requires_checked_ci_host')

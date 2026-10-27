"""Pure historical replay of source-bound public CI custody.

The checked host first admits the exact native modules through its public
source manifest. No constructor, file, process or native authority is used
here. Normal return is an exact replay receipt; every failed/unknown contract
raises. This does not issue a fresh resource admission or qualify an image.
"""
import datetime as dt
import itertools
import os
import re

import ci_adapter
import ci_custody
import ci_fixture as fixture
import ci_probe as probe
import ci_profile as profile
import ci_worker as worker
import native_cases
from ci_protocol import Refusal,canonical,closed,decode,require,sha,utc


SLOTS={'report':86000,'host-result':12288,'staging-manifest':12288,
       'worker-stdout':4096,'worker-stderr':4096,'controller-context':16384,
       'consumer-compatibility':12288,'host-expectation':12288,'unit-readback':4096}
SLOTS.update({'worker-stderr-raw':8192,'native-isolation-cases':12288})
FACT_KEYS={'schema','sessionId','bootId','pid','startTimeTicks','uid','gid','invocationId',
           'unitName','identityName','profileSha256','cgroupPath','namespaces','seccompMode',
           'seccompFilterCount','capabilitySets','noNewPrivileges','supplementaryGroups',
           'peerProcessesChecked','executable','jailRoot','mounts','environment','limits',
           'stdio','children','stableTuple','readCalls','readBytes','factsSha256'}
CODE_KEYS={'entrySha256','workerSha256','runtimeManifestSha256','consumerCode'}
CONSUMER_FILES={'hosted_export.py','hosted_privacy.py','public-member-comparisons-v105-workboard.json'}
WORKER_CODE_FILES=CONSUMER_FILES|{'ci_fixture.py','native_cases.py'}


def integer(value,low=0,high=(1<<63)-1):
    return type(value) is int and low<=value<=high


def hash_value(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None


def document(raw,cap,code):
    value=decode(raw,cap)
    require(canonical(value)==raw,code)
    return value


def trusted_expected(expected):
    required={'sessionId','sourceManifestSha256','buildControlSha256','runIdentity',
              'code','profileSha256','propertiesSha256','consumerSourceHashes'}
    require(type(expected) is dict and set(expected) in (required,required|{'contextSha256'}),'replay.expected')
    require(type(expected['sessionId']) is str and re.fullmatch('[0-9a-f]{32}',expected['sessionId']),
            'replay.session')
    require(all(hash_value(expected[k]) for k in ('sourceManifestSha256','buildControlSha256',
                                                  'profileSha256','propertiesSha256')),
            'replay.expected_hash')
    require(expected['profileSha256']==profile.DESIGN_PROFILE_SHA,'replay.profile')
    code=closed(expected['code'],CODE_KEYS,'replay.code')
    require(all(hash_value(code[k]) for k in ('entrySha256','workerSha256','runtimeManifestSha256')),
            'replay.code_hash')
    require(type(code['consumerCode']) is dict and set(code['consumerCode'])==WORKER_CODE_FILES,
            'replay.consumer_code')
    for row in code['consumerCode'].values():
        closed(row,{'bytes','sha256'},'replay.consumer_code_row')
        require(integer(row['bytes'],1,131072) and hash_value(row['sha256']),'replay.consumer_code_row')
    sources=closed(expected['consumerSourceHashes'],CONSUMER_FILES,'replay.compat_source_keys')
    require(all(hash_value(value) for value in sources.values()),'replay.compat_source_hash')
    require(all(code['consumerCode'][name]['sha256']==pin for name,pin in sources.items()),
            'replay.worker_consumer_source_join')
    require(sources==native_cases.IMPORT_PINS,'replay.native_import_source_join')
    run=closed(expected['runIdentity'],{'repository','workflowRef','sourceCommit','runId','runAttempt'},
               'replay.run_identity')
    require(run['repository']=='fr-meyer/openclaw' and
            run['workflowRef']=='fr-meyer/openclaw/.github/workflows/authorized-beta-focused-validation.yml@refs/heads/retained-verifier-prerequisites' and
            type(run['sourceCommit']) is str and re.fullmatch('[0-9a-f]{40}',run['sourceCommit']) and
            type(run['runId']) is str and re.fullmatch('[1-9][0-9]*',run['runId']) and
            run['runAttempt']=='1','replay.run_identity')


def context_join(raw,expected):
    context=closed(document(raw,SLOTS['controller-context'],'replay.context_canonical'),
                   worker.CONTEXT_KEYS,'replay.context_schema')
    require(context.get('sessionId')==expected['sessionId'],'replay.context_session')
    if 'contextSha256' in expected:
        require(hash_value(expected['contextSha256']) and sha(raw)==expected['contextSha256'],
                'replay.context_hash')
    # This is validation at the context's own historical start boundary, not
    # now(), expiry extension, gate issuance or a claim of fresh admission.
    historical_start=utc(context.get('workerDeadlineUtc'))-dt.timedelta(seconds=300)
    worker.validate_context(context,historical_start,expected['code'])
    require(context['profileSha256']==expected['profileSha256'] and
            context['inputManifestSha256']==sha(canonical({'report':fixture.REPORT_SHA,'blob':fixture.BLOB_SHA})),
            'replay.context_inputs')
    return context


def mounts_join(observed,expected):
    require(type(observed) is list and len(observed)==len(expected),'replay.mount_roster')
    indexed={row['target']:row for row in expected};seen=set();ids=set()
    for row in observed:
        closed(row,probe.MOUNT_KEYS|{'mountId','parentId'},'replay.mount_schema')
        target=row['target']
        require(type(target) is str and target in indexed and target not in seen,'replay.mount_target')
        require(integer(row['mountId'],1) and integer(row['parentId'],1) and row['mountId'] not in ids,
                'replay.mount_id')
        want=indexed[target]
        for key in probe.MOUNT_KEYS:
            value=sorted(want[key]) if key in ('vfsOptions','fsOptions','optionalFields') else want[key]
            require(type(row[key]) is type(value) and row[key]==value,'replay.mount_binding')
        require(row['optionalFields']==[],'replay.mount_private')
        seen.add(target);ids.add(row['mountId'])
    require(seen==probe.MOUNT_TARGETS,'replay.mount_roster')


def stdio_join(observed,expected):
    closed(observed,{'stdin','stdout','stderr'},'replay.stdio_schema')
    keys=probe.IDENTITY_KEYS|{'rdev','flags','mountId','nlink','size'}
    for label,row in observed.items():
        closed(row,keys,'replay.fd_schema')
        require(all(integer(row[k]) for k in keys-{'type'}) and row['ino']>0 and row['mountId']>0,
                'replay.fd_shape')
        want=expected[label]
        require(all(type(row[k]) is type(v) and row[k]==v for k,v in want.items()),'replay.fd_binding')
        if label=='stdin':
            require(row['type']=='char' and row['rdev']==os.makedev(1,3) and
                    row['flags'] in (os.O_RDONLY,os.O_RDONLY|0o100000),'replay.fd_stdin')
        else:
            require(row['type']=='regular' and row['uid']==row['gid']==0 and row['mode']==0o600 and
                    row['rdev']==0 and row['nlink']==1 and row['size']<=65536 and
                    row['flags'] in (os.O_WRONLY|os.O_APPEND,os.O_WRONLY|os.O_APPEND|0o100000),
                    'replay.fd_output')


def facts_join(raw,source_expected,context):
    facts=closed(document(raw,SLOTS['host-result'],'replay.facts_canonical'),FACT_KEYS,'replay.facts_schema')
    clean={k:v for k,v in facts.items() if k!='factsSha256'}
    require(hash_value(facts['factsSha256']) and facts['factsSha256']==sha(canonical(clean)),
            'replay.facts_hash')
    require(facts['schema']==probe.FACT_SCHEMA,'replay.facts_schema')
    for key in ('sessionId','bootId','pid','startTimeTicks','uid','gid','invocationId','unitName',
                'identityName','profileSha256','cgroupPath'):
        require(type(facts[key]) is type(source_expected[key]) and facts[key]==source_expected[key],
                'replay.facts_identity')
    require(facts['sessionId']==context['sessionId'] and facts['bootId']==context['bootId'],
            'replay.facts_context')
    require(integer(facts['seccompMode']) and facts['seccompMode']==2 and
            integer(facts['seccompFilterCount'],1,4096) and type(facts['noNewPrivileges']) is int and
            facts['noNewPrivileges']==1,'replay.process_protection')
    caps=closed(facts['capabilitySets'],probe.CAP_KEYS,'replay.caps_schema')
    require(all(type(v) is int and v==0 for v in caps.values()),'replay.capabilities')
    require(type(facts['supplementaryGroups']) is list and
            facts['supplementaryGroups'] in ([],[facts['gid']]) and
            type(facts['children']) is list and facts['children']==[] and facts['stableTuple'] is True,
            'replay.process_shape')
    require(integer(facts['peerProcessesChecked'],1,probe.MAX_PIDS) and
            integer(facts['readCalls'],1,probe.MAX_READS) and integer(facts['readBytes'],1,probe.MAX_BYTES),
            'replay.observation_bounds')
    namespaces=closed(facts['namespaces'],probe.NAMESPACE_NAMES,'replay.namespaces')
    require(all(integer(v,1) for v in namespaces.values()),'replay.namespace_shape')
    for name,value in namespaces.items():
        host=source_expected['hostNamespaces'][name]
        require(value!=host if name in ('mnt','net','ipc') else value==host,'replay.namespace_binding')
    for key in ('executable','jailRoot'):
        closed(facts[key],{'dev','ino'},'replay.object_schema')
        require(all(type(facts[key][k]) is int and facts[key][k]==source_expected[key][k]
                    for k in ('dev','ino')),'replay.object_binding')
    require(type(facts['limits']) is dict and set(facts['limits'])==probe.LIMIT_KEYS and
            all(type(v) is int for v in facts['limits'].values()) and facts['limits']==source_expected['limits'],
            'replay.resource_limits')
    environment=closed(facts['environment'],{'entryCount','bytes','sha256','canonicalSha256'},'replay.environment')
    entries=[(k+'='+v).encode() for k,v in probe.ENVIRONMENT.items()]
    allowed={sha(b'\x00'.join(order)+b'\x00') for order in itertools.permutations(entries)}
    require(type(environment['entryCount']) is int and environment['entryCount']==4 and
            type(environment['bytes']) is int and environment['bytes']==sum(len(x)+1 for x in entries) and
            hash_value(environment['sha256']) and hash_value(environment['canonicalSha256']) and
            environment['canonicalSha256']==sha(canonical(probe.ENVIRONMENT)) and environment['sha256'] in allowed,
            'replay.environment_binding')
    mounts_join(facts['mounts'],source_expected['mounts'])
    stdio_join(facts['stdio'],source_expected['stdio'])
    return facts


def compatibility_join(raw,expected):
    value=closed(document(raw,SLOTS['consumer-compatibility'],'replay.compat_canonical'),
                 {'schema','status','testsRun','failures','sourceHashes','elapsedMilliseconds','fixtureOnly','nativeProof'},
                 'replay.compat_schema')
    require(value['schema']=='ocv.consumer-compat.v1' and value['status']=='passed' and
            type(value['testsRun']) is int and value['testsRun']==7 and value['failures']==[] and
            type(value['failures']) is list and integer(value['elapsedMilliseconds'],0,240000) and
            value['fixtureOnly'] is True and value['nativeProof'] is False and
            value['sourceHashes']==expected['consumerSourceHashes'] and
            type(value['sourceHashes']) is dict and set(value['sourceHashes'])==CONSUMER_FILES,
            'replay.compat_binding')


def native_cases_join(rows,expected,facts):
    raw=rows['worker-stderr-raw']
    require(raw.endswith(b'\n') and b'\r'not in raw,'replay.raw_stderr_lines')
    lines=raw.splitlines(keepends=True)
    require(len(lines)==3 and all(line.endswith(b'\n') and line!=b'\n' for line in lines),
            'replay.raw_stderr_lines')
    require(lines[0]+lines[1]==rows['worker-stderr'] and lines[2][:-1]==rows['native-isolation-cases'],
            'replay.raw_stderr_join')
    # Full raw custody precedes parsing in the host controller. The sole extra
    # line is this exact canonical source-owned case result, never stripped by
    # a substring or an unrecognized schema. Synthetic/unissued cases refuse.
    value=document(rows['native-isolation-cases'],4096,'replay.native_cases_canonical')
    native_cases.validate_result(value,expected_pid=facts['pid'],
                                 expected_context_sha=sha(rows['controller-context']))
    require(value['producer']=='native_linux' and value['importHashes']==expected['consumerSourceHashes'],
            'replay.native_case_producer')


class CapturedCustodyView:
    """Read-only memory view for the unchanged pure accept_consumer method.

    No Custody/native constructor is bypassed or invoked; that validator reads
    only these captured hashes/truncation flags and supplied immutable streams.
    The host already preserved those bytes before this pure replay.
    """
    def __init__(self,rows):
        self.rows={role:{'sha256':sha(rows[role]),'truncated':False}
                   for role in ('worker-stdout','worker-stderr')}


def validate(rows,expected):
    trusted_expected(expected)
    require(type(rows) is dict and set(rows)==set(SLOTS),'replay.custody_roster')
    require(all(type(rows[k]) is bytes and len(rows[k])<=cap for k,cap in SLOTS.items()) and
            sum(map(len,rows.values()))<=131072,'replay.custody_bound')
    context=context_join(rows['controller-context'],expected)
    source_expected=document(rows['host-expectation'],SLOTS['host-expectation'],'replay.expected_canonical')
    probe.validate_expected(source_expected)
    root='/var/lib/ci-verifier/'+expected['sessionId']+'/root'
    require(source_expected['jailRoot']['path']==root and
            source_expected['executable']['path']==root+'/usr/bin/python3.11' and
            source_expected['profileSha256']==expected['profileSha256'] and
            all(type(v) is int for v in source_expected['limits'].values()),'replay.expected_source_binding')
    unit=document(rows['unit-readback'],SLOTS['unit-readback'],'replay.unit_canonical')
    ci_adapter.unit_binding(unit,source_expected,context,expected['propertiesSha256'])
    facts=facts_join(rows['host-result'],source_expected,context)
    require(rows['report']==fixture.REPORT,'replay.report_bytes')
    require(document(rows['staging-manifest'],SLOTS['staging-manifest'],'replay.staging_canonical')==
            {'report':fixture.REPORT_SHA,'blob':fixture.BLOB_SHA},'replay.staging_binding')
    compatibility_join(rows['consumer-compatibility'],expected)
    native_cases_join(rows,expected,facts)
    ci_custody.Custody.accept_consumer(CapturedCustodyView(rows),rows['worker-stdout'],rows['worker-stderr'],
        returncode=0,timed_out=False,context_sha=sha(rows['controller-context']),
        report_sha=fixture.REPORT_SHA,expected_closure_sha=fixture.CLOSURE_SHA,
        pid=facts['pid'],uid=facts['uid'],gid=facts['gid'],expected_worker_sha=expected['code']['workerSha256'])
    return {'schema':'ocv.source-replay.v1','status':'passed','contextSha256':sha(rows['controller-context']),
            'hostResultSha256':sha(rows['host-result']),
            'consumerCompatibilitySha256':sha(rows['consumer-compatibility'])}


if __name__=='__main__':raise SystemExit('inert_requires_checked_ci_host')

"""Fixed CI adapter for one approved, private, unqualified 10.9 OCI build.

The DISARMED path reads only the image request. All network calls are fixed
GitHub metadata/artifact GETs except the separately scoped final create-only PUT.
No signing, grants, credential creation, GCP guest call, Docker load or image
execution is implemented here. The workflow owns the sole BuildKit invocation.
"""
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

import image_build_contract_v109 as contract

IMAGE_DIR = "scripts/fork-release/candidates/v2026.10.9-image-only"
SOURCE_DIR = "scripts/fork-release/candidates/v2026.10.9-source-only"


def root():
    return Path(__file__).resolve().parents[2]


def read(path, maximum=2097152):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        contract.need(stat.S_ISREG(before.st_mode) and before.st_size<=maximum and before.st_nlink==1,
                      "image.regular_bounded_input")
        with os.fdopen(fd,'rb')as stream:
            data=stream.read(maximum+1);after=os.fstat(stream.fileno())
        contract.need(len(data)==before.st_size and len(data)<=maximum and
            (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
            (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),"image.input_changed")
        return data
    except BaseException:
        try:os.close(fd)
        except OSError:pass
        raise


def private_dir(path):
    path=Path(path).absolute()
    contract.need(path.resolve()==path,"image.private_path")
    path.mkdir(mode=0o700)
    return path


def save(path,data):
    with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as f:
        f.write(data);f.flush();os.fsync(f.fileno())


def record(path,value):
    save(path,contract.encode(value))


def outputs(values):
    with Path(os.environ['GITHUB_OUTPUT']).open('a')as f:
        for key,value in values.items():
            value=str(value)
            contract.need(re.fullmatch(r'[a-z_]+',key) and value and all(32<=ord(c)<127 for c in value),"image.output_value")
            f.write(key+'='+value+'\n')


def context():
    event=contract.parse(read(os.environ['GITHUB_EVENT_PATH']),2097152)
    return {'repository':os.environ.get('GITHUB_REPOSITORY'),'actor':os.environ.get('GITHUB_ACTOR'),
        'event':os.environ.get('GITHUB_EVENT_NAME'),'ref':os.environ.get('GITHUB_REF'),
        'sha':os.environ.get('GITHUB_SHA'),'workflowSha':os.environ.get('ACTUAL_WORKFLOW_SHA'),
        'runId':os.environ.get('GITHUB_RUN_ID'),'attempt':int(os.environ.get('GITHUB_RUN_ATTEMPT','0')),
        'before':event.get('before'),'after':event.get('after'),'created':event.get('created'),
        'deleted':event.get('deleted'),'forced':event.get('forced')}


def image_request(expected=None,active=False):
    raw=read(root()/IMAGE_DIR/'image-request.json',65536)
    if expected is not None:contract.need(contract.sha(raw)==expected,"image.request_changed")
    return raw,contract.validate_request(contract.parse(raw,65536),active=active,now=time.time()if active else None)


def source_inputs(request):
    # These fixed imports are the same reviewed owners used by source CI. No
    # artifact chooses an implementation, filename, callback or command.
    import source_validation_contract_v109 as source_contract
    names=(('ci-bindings.json','sourceBindingsSha256'),('source-request.json','sourceRequestSha256'),
           ('generation-receipt.json','generationReceiptSha256'),('manifest.json','manifestSha256'),
           ('inventory.json','inventorySha256'))
    data={}
    for name,key in names:
        b=read(root()/SOURCE_DIR/name)
        contract.need(contract.sha(b)==request[key],"image.source_control_pin")
        data[name]=b
    bindings=source_contract.validate_bindings(source_contract.parse(data['ci-bindings.json']))
    selected=source_contract.validate_request(source_contract.parse(data['source-request.json']),bindings)
    contract.need(selected['phase']==request['sourceValidation']['phase'] and selected['phase']in('validation','correction'),
                  "image.source_phase")
    source_contract.validate_generation(data['generation-receipt.json'],bindings,selected['phase'])
    source=selected['source']
    contract.need(source['sourceSha']==request['sourceSha'] and source['sourceTree']==request['sourceTree'] and
        source['manifestSha256']==request['manifestSha256'] and source['inventorySha256']==request['inventorySha256'] and
        source_contract.preparation_for(bindings,selected['preparationAttempt'])['sourceSha']==request['preparationSourceSha'],
        "image.source_binding")
    return source_contract,bindings,selected,data


class GitHub:
    def __init__(self,path):
        self.path=private_dir(path);self.sequence=0
    def get(self,suffix,binary=False):
        self.sequence+=1
        # Every caller constructs the repository-relative suffix from fixed
        # endpoints and positively parsed decimal IDs or the fixed workflow path.
        contract.need(type(suffix)is str and not suffix.startswith('/') and '\n'not in suffix,"image.github_path")
        endpoint='repos/'+contract.REPOSITORY+'/'+suffix
        env={'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':os.environ.get('HOME','/home/runner'),
            'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','GH_TOKEN':os.environ.get('GH_TOKEN','')}
        try:
            child=subprocess.run(['gh','api','--hostname','github.com','--method','GET','-H','Cache-Control: max-age=0',endpoint],
                env=env,capture_output=True,timeout=30,check=False)
            code,stdout,stderr=child.returncode,child.stdout,child.stderr
        except subprocess.TimeoutExpired as e:
            code,stdout,stderr=None,e.stdout or b'',e.stderr or b''
        stem=f'{self.sequence:03d}'
        save(self.path/(stem+'.stdout.private'),stdout[:2097152]);save(self.path/(stem+'.stderr.private'),stderr[:16384])
        record(self.path/(stem+'.frame.private.json'),{'endpoint':endpoint,'exitCode':code,'stdoutBytes':len(stdout),
            'stdoutSha256':contract.sha(stdout),'stderrBytes':len(stderr),'stderrSha256':contract.sha(stderr)})
        contract.need(type(code)is int and code==0 and not stderr and len(stdout)<=2097152,"image.github_read_refused")
        return stdout if binary else contract.parse(stdout)


def history(api,request,ctx):
    runs=api.get('actions/workflows/future-v109-image-build.yml/runs?branch='+contract.BRANCH+'&per_page=100')
    contract.need(type(runs)is dict and type(runs.get('workflow_runs'))is list and len(runs['workflow_runs'])<=64,
                  "image.history_bound")
    prior={}
    for row in runs['workflow_runs']:
        rid=str(row.get('id'))
        contract.need(contract.RUN.fullmatch(rid) is not None,"image.run_id")
        if rid!=ctx['runId']:prior[rid]=api.get('actions/runs/'+rid+'/jobs?filter=all&per_page=100')
    contract.validate_image_history(request,ctx,runs,prior)
    import source_validation_v109 as source_owner
    measured=[source_owner.observed_jobs(page["jobs"],time.time(),True,
        {"image-admission":15,"build-private-image":90})[0]for page in prior.values()]
    return contract.family_budget(measured)


def source_snapshot(api,request,source_contract,bindings,selected,data):
    pin=request['sourceValidation'];rid=pin['runId']
    run=api.get('actions/runs/'+rid)
    jobs=api.get('actions/runs/'+rid+'/jobs?filter=all&per_page=100')
    artifacts=api.get('actions/runs/'+rid+'/artifacts?per_page=100')
    contract.need(type(artifacts)is dict and artifacts.get('total_count')==1 and
        len(artifacts.get('artifacts',[]))==1 and artifacts['artifacts'][0].get('id')==pin['artifactId'] and
        type(artifacts['artifacts'][0].get('size_in_bytes'))is int and
        0<artifacts['artifacts'][0]['size_in_bytes']<=contract.MAX_ARTIFACT,"image.source_artifact_bound")
    archive=api.get('actions/artifacts/'+str(pin['artifactId'])+'/zip',binary=True)
    expected={'runId':rid,'runAttempt':1,'pipelineHead':pin['pipelineHead'],'requestSha256':request['sourceRequestSha256']}
    validator=lambda raw:source_contract.validate_source_result(raw,bindings,data['source-request.json'],expected,
        expected_result_sha256=pin['resultSha256'])
    value=contract.validate_source_snapshot(request,run,jobs,artifacts,archive,validator)
    # Historical source authority is checked at the actual immutable job times,
    # not made current again by an image approval.
    auth=bindings['authorization'];contract.need(type(auth)is dict,"image.source_authorization_missing")
    start,end=source_contract.utc(auth['approvedAt']),source_contract.utc(auth['expiresAt'])
    for job in jobs['jobs']:
        a,b=contract.utc(job.get('started_at')),contract.utc(job.get('completed_at'))
        contract.need(start<=a<=b<=end,"image.source_job_clock")
    return value


def admission():
    raw,request=image_request()
    if request['state']!='APPROVED_BUILD':
        outputs({'enabled':'false'});return {'status':'disarmed','imageBuilt':False,'productionAuthorized':False}
    # Remove the capability from inherited environments before any subprocess.
    envelope=os.environ.pop('OCI_UPLOAD_ENVELOPE','').encode()
    now=time.time();ctx=contract.validate_context(context(),request,now)
    source_contract,bindings,selected,data=source_inputs(request)
    api=GitHub(Path(os.environ['RUNNER_TEMP'])/'v109-image-admission')
    source_snapshot(api,request,source_contract,bindings,selected,data);history(api,request,ctx)
    import private_oci_transfer as transfer
    deadline=contract.validate_envelope(envelope,request,ctx,transfer.validate_capability,time.time())
    window=contract.build_window(deadline,time.time(),request['authorization']['expiresAt'])
    record(api.path/'admission.private.json',{'schema':'openclaw.v109.image-admission.v1','status':'admitted_unqualified',
        'sourceSha':request['sourceSha'],'sourceTree':request['sourceTree'],'requestSha256':contract.sha(raw),
        'sourceValidationRunId':request['sourceValidation']['runId'],'workflowSha':ctx['sha'],'runId':ctx['runId'],
        'attempt':1,'uploadDeadlineEpoch':int(deadline),'imageBuilt':False,'qualified':False,'productionAuthorized':False})
    outputs({'enabled':'true','source_sha':request['sourceSha'],'source_tree':request['sourceTree'],
        'built_at':request['builtAt'],'request_sha256':contract.sha(raw),'upload_deadline_epoch':int(deadline)})
    return {'status':'admitted_unqualified','sourceSha':request['sourceSha'],'imageBuilt':False,'productionAuthorized':False}


def checked():
    expected=os.environ.get('APPROVED_IMAGE_REQUEST_SHA256','')
    contract.need(contract.pin(expected),'image.request_pin_required')
    raw,request=image_request(expected,active=True)
    ctx=contract.validate_context(context(),request,time.time())
    return raw,request,ctx


def verify_source():
    raw,request,ctx=checked()
    source_contract,bindings,selected,data=source_inputs(request)
    import source_validation_v108 as shared
    import lockfile_policy_v109 as lock_policy
    source=root().parent/'source'
    def git(*argv):
        contract.need(argv and argv[0]in('show','rev-parse','ls-tree','merge-base','cat-file','rev-list','diff-tree'),
                      'image.readonly_git_command')
        env={'PATH':'/usr/bin:/bin','HOME':os.environ.get('HOME','/home/runner'),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
            'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_NO_LAZY_FETCH':'1','GIT_OPTIONAL_LOCKS':'0',
            'GIT_NO_REPLACE_OBJECTS':'1','GIT_LITERAL_PATHSPECS':'1','GIT_TERMINAL_PROMPT':'0'}
        p=subprocess.run(['git','-c','protocol.allow=never','-c','core.hooksPath=/dev/null','-c','diff.external=',
            '-C',str(source),*argv],env=env,capture_output=True,timeout=30,check=False)
        contract.need(p.returncode==0 and not p.stderr and len(p.stdout)<=64*1024*1024,'image.source_git_refused')
        return p.stdout
    contract.need(git('rev-parse','HEAD')==(request['sourceSha']+'\n').encode(),'image.source_checkout')
    initial=root()/SOURCE_DIR/'generation-receipt-initial.json'
    result=source_contract.verify_derived_source(git,bindings,selected['phase'],data['generation-receipt.json'],
        read_tree=lambda sha,tree:shared._v4_tree(git,sha,tree),verify_lock=lock_policy.verify_lock_security,
        initial_generation_raw=read(initial)if initial.exists()else None)
    package=contract.parse(read(source/'package.json'))
    contract.need(package.get('version')=='2026.10.9','image.package_version')
    contract.need(result['sourceSha']==request['sourceSha'] and result['sourceTree']==request['sourceTree'],
                  'image.derived_source_identity')
    outputs({'version':'2026.10.9'})
    return {'status':'verified_exact_source','sourceSha':request['sourceSha'],'sourceTree':request['sourceTree'],
        'imageBuilt':False,'productionAuthorized':False}


def deadline():
    raw,request,ctx=checked()
    api=GitHub(Path(os.environ['RUNNER_TEMP'])/'v109-image-prebuild')
    history(api,request,ctx)
    value=os.environ.get('APPROVED_UPLOAD_DEADLINE_EPOCH','')
    contract.need(re.fullmatch(r'[1-9][0-9]{0,11}',value) is not None,'image.upload_deadline_required')
    window=contract.build_window(int(value),time.time(),request['authorization']['expiresAt'])
    record(api.path/'physical-build-intent.private.json',{'schema':'openclaw.v109.physical-build-intent.v1',
        'requestSha256':contract.sha(raw),'sourceSha':request['sourceSha'],'sourceTree':request['sourceTree'],
        'workflowSha':ctx['sha'],'runId':ctx['runId'],'attempt':1,'createdAt':datetime.now(timezone.utc).isoformat(),**window})
    outputs({'build_timeout_minutes':window['timeoutMinutes']})
    return {'status':'physical_build_intent','maximumBuildMinutes':window['timeoutMinutes'],
        'archiveAttestUploadReserveSeconds':contract.RESERVE_SECONDS,'capacityGuaranteed':False,'productionAuthorized':False}


def record_build():
    _,request,_=checked();where=Path(os.environ['RUNNER_TEMP'])/'v109-image'
    raw=os.environ.pop('ORIGINAL_BUILD_METADATA','').encode();digest=os.environ.get('OCI_DIGEST','')
    # Preserve bounded original bytes before JSON, digest or type adjudication.
    save(where/'build-metadata.json',raw[:2097152])
    record(where/'build-metadata-frame.private.json',{'bytes':len(raw),'sha256':contract.sha(raw),'complete':len(raw)<=2097152})
    contract.need(len(raw)<=2097152 and re.fullmatch(r'sha256:[0-9a-f]{64}',digest) is not None,'image.build_metadata_bound')
    obj=contract.parse(raw)
    contract.need(type(obj)is dict and obj.get('containerimage.digest')==digest,'image.original_build_metadata')
    return {'status':'original_build_metadata_bound','sourceSha':request['sourceSha'],'indexDigest':digest,
        'metadataSha256':contract.sha(raw),'qualified':False,'productionAuthorized':False}


def prepare():
    _,request,ctx=checked();source_inputs(request)
    import private_oci_producer_v109 as producer
    temp=Path(os.environ['RUNNER_TEMP']);base=temp/'v109-image';out=temp/'v109-private-retention'
    result=producer.prepare_from_build(root()/SOURCE_DIR/'manifest.json',root()/SOURCE_DIR/'inventory.json',
        base/'build-metadata.json',base/'resources.json',base/'oci/default',out,temp/'v109-retention.json',
        source_sha=request['sourceSha'],source_tree=request['sourceTree'],workflow_sha=ctx['sha'],run_id=ctx['runId'],
        attempt='1',built_at=request['builtAt'])
    outputs({'archive_sha256':result['archiveSha256'],'archive_bytes':result['archiveBytes']})
    return {'status':'prepared_unqualified','archiveSha256':result['archiveSha256'],'archiveBytes':result['archiveBytes'],
        'qualified':False,'productionAuthorized':False}


def put():
    envelope=os.environ.pop('OCI_UPLOAD_ENVELOPE','').encode()
    _,request,ctx=checked();source_inputs(request)
    import private_oci_transfer as transport
    temp=Path(os.environ['RUNNER_TEMP']);out=temp/'v109-private-retention'
    result=contract.parse(read(temp/'v109-retention.json'))
    contract.need(result.get('status')=='prepared' and result.get('sourceSha')==request['sourceSha'] and
        result.get('sourceTree')==request['sourceTree'] and result.get('producer')==
        {'workflowSha':ctx['sha'],'runId':ctx['runId'],'attempt':'1'} and result.get('qualified') is False,
        'image.prepared_archive_identity')
    contract.validate_envelope(envelope,request,ctx,transport.validate_capability,time.time(),before_build=False)
    env=contract.parse(envelope,32768)
    plan={'schema':'openclaw.private-oci-transfer-plan.v1','sourceSha':request['sourceSha'],'toolingSha':ctx['sha'],
        'runId':ctx['runId'],'attempt':'1','archiveSha256':result['archiveSha256'],'archiveBytes':result['archiveBytes'],
        **{k:request['privateObject'][k]for k in ('bucket','object','signer')},'generation':None}
    contract.validate_transfer_plan(plan,request,ctx,result['archiveSha256'],result['archiveBytes'])
    raw=contract.encode(plan);save(out/'transfer-plan.json',raw)
    value=transport.transfer(plan,contract.sha(raw),env['url'],'PUT',out/'retained-oci.tar',out/'transfer.json',
        http.client.HTTPSConnection,time.time)
    contract.need(value.get('status')=='transferred','image.transfer_not_proven')
    return {k:value[k]for k in ('status','method','sourceSha','toolingSha','runId','attempt','archiveSha256','archiveBytes','generation','objectIdentitySha256','productionAuthorized','imageQualified')}


def complete():
    _,request,ctx=checked()
    value=contract.parse(read(Path(os.environ['RUNNER_TEMP'])/'v109-private-retention/transfer.json'))
    good=all(os.environ.get(k)=='success'for k in ('SOURCE_OUTCOME','BUILD_OUTCOME','RESOURCE_OUTCOME','ATTEST_OUTCOME','TRANSFER_OUTCOME'))
    contract.need(value.get('status')=='transferred' and value.get('sourceSha')==request['sourceSha'] and
        value.get('toolingSha')==ctx['sha'] and value.get('runId')==ctx['runId'] and value.get('attempt')=='1' and
        type(value.get('archiveBytes'))is int and 0<value['archiveBytes']<=contract.MAX_ARCHIVE and
        contract.pin(value.get('archiveSha256')) and contract.pin(value.get('objectIdentitySha256')) and
        type(value.get('generation'))is str and re.fullmatch(r'[1-9][0-9]{0,19}',value['generation']),
                  'image.private_retention_not_proven')
    result={'schema':'openclaw.v109.private-image-result.v1','status':'private_retained_unqualified'if good else'private_forensic_retention_unqualified',
        'sourceSha':request['sourceSha'],'sourceTree':request['sourceTree'],'archiveSha256':value['archiveSha256'],
        'archiveBytes':value['archiveBytes'],'producer':{'workflowSha':value['toolingSha'],'runId':value['runId'],'attempt':1},
        'generation':value['generation'],'objectIdentitySha256':value['objectIdentitySha256'],
        'producerAttestationRequiredAtReceiver':True,'embeddedSourceVerified':False,
        'privacyPassed':False,'qualified':False,'nativeImageExecuted':False,'productionAuthorized':False}
    contract.need(len(contract.encode(result))<=16384,'image.safe_result_limit')
    record(Path(os.environ['RUNNER_TEMP'])/'v109-image-result.json',result)
    if not good:
        print(json.dumps(result,sort_keys=True));raise contract.Refusal('image.hosted_build_gate_failed')
    return result


COMMANDS={'admission':admission,'verify-source':verify_source,'deadline':deadline,'record-build':record_build,
          'prepare':prepare,'put':put,'complete':complete}

def main():
    try:
        contract.need(len(sys.argv)==2 and sys.argv[1]in COMMANDS,'image.fixed_command')
        result=COMMANDS[sys.argv[1]]();print(json.dumps(result,sort_keys=True));return 0
    except Exception as exc:
        reason=str(exc)if isinstance(exc,contract.Refusal)else'image.local_operation_refused'
        print(json.dumps({'status':'refused','reason':reason,'qualified':False,'productionAuthorized':False},sort_keys=True))
        return 1

if __name__=='__main__':raise SystemExit(main())

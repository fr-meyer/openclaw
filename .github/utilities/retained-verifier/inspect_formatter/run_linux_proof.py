"""Admit only the fixed, synthetic Docker formatter witness on hosted Linux."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import time

ARCHIVE_BYTES=85591344
ARCHIVE_SHA='995d1ef289677f74fd58d8d2c35727b6a4ee389c69db8638a3e42d0487aa5b0f'
DOCKER_BYTES=44260160
DOCKER_SHA='6f7a95d27f98fc8c5f6b220898988bf8f61dd9b040936797917cbdc72c6cabe6'
MEMBER='docker/docker'
NORMAL_SHA='15faa49589584e0c198f6794488e5c3c9855a23ac6e45ff1979a68f3cd4fbde4'
PRIOR_SHA='4bfd502bc12b74ddc66f6c12227ba659490d03b39d68a236309b608bc35aca34'


def need(value,code):
    if value is not True:raise RuntimeError(code)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')


def load(path):
    name='ocv_formatter_'+path.parent.name+'_'+path.stem
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    spec.loader.exec_module(module);return module


def extract_docker(archive,destination,*,deadline):
    """Authenticate the whole archive and one regular member; no tar extraction."""
    before=archive.lstat()
    need(stat.S_ISREG(before.st_mode) and not archive.is_symlink() and before.st_nlink==1
         and before.st_uid==os.getuid() and before.st_size==ARCHIVE_BYTES,'formatter.archive_identity')
    digest=hashlib.sha256()
    with archive.open('rb')as stream:
        while True:
            need(time.monotonic()<deadline,'formatter.archive_deadline')
            raw=stream.read(1048576)
            if not raw:break
            digest.update(raw)
    need(digest.hexdigest()==ARCHIVE_SHA,'formatter.archive_hash')
    found=False;count=0
    with tarfile.open(archive,mode='r:gz')as source:
        for member in source:
            count+=1;need(count<=128 and time.monotonic()<deadline,'formatter.archive_bound')
            if member.name!=MEMBER:continue
            need(not found and member.isreg() and not member.issparse() and member.size==DOCKER_BYTES,
                 'formatter.docker_member');found=True
            opened=source.extractfile(member);need(opened is not None,'formatter.member_stream')
            fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o555)
            digest=hashlib.sha256();total=0
            with opened,os.fdopen(fd,'wb')as target:
                while True:
                    need(time.monotonic()<deadline,'formatter.member_deadline')
                    raw=opened.read(min(1048576,DOCKER_BYTES+1-total))
                    if not raw:break
                    total+=len(raw);need(total<=DOCKER_BYTES,'formatter.member_bound');digest.update(raw)
                    need(target.write(raw)==len(raw),'formatter.member_write')
                target.flush();os.fchmod(target.fileno(),0o555);os.fsync(target.fileno())
            need(total==DOCKER_BYTES and digest.hexdigest()==DOCKER_SHA,'formatter.member_hash')
    need(found,'formatter.member_missing')
    after=archive.lstat();identity=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_nlink,
                                           v.st_size,v.st_mtime_ns,v.st_ctime_ns)
    need(identity(before)==identity(after),'formatter.archive_changed')
    after=destination.lstat()
    need(stat.S_ISREG(after.st_mode) and after.st_nlink==1 and after.st_uid==os.getuid() and
         after.st_size==DOCKER_BYTES and stat.S_IMODE(after.st_mode)==0o555,'formatter.member_identity')


def require_proof(actual,pin):
    need(type(actual)is dict and actual.get('schema')=='ocv.generic-docker-inspect-formatter-linux-proof.v1'
      and actual.get('status')=='PASS' and actual.get('sourceManifestSha256')==pin
      and actual.get('dockerSha256')==DOCKER_SHA and actual.get('dockerBytes')==DOCKER_BYTES
      and actual.get('dockerVersion')=='29.8.2' and actual.get('normalTemplateSha256')==NORMAL_SHA
      and actual.get('priorTemplateSha256')==PRIOR_SHA and type(actual.get('cases'))is list
      and len(actual['cases'])==26 and type(actual.get('maximumFormattedBytes'))is int
      and 0<actual['maximumFormattedBytes']<=16384 and actual.get('formattedCaptureCapBytes')==16384
      and actual.get('apiVersion')=='1.53' and actual.get('maximumRequestsPerCli')==4
      and actual.get('fixedPingAndInspectRoutesOnly')is True and actual.get('syntheticBinds')==36 and actual.get('syntheticSourcePathBytes')==192
      and all(actual.get(k)is True for k in ('bothActualCliTemplatesExecuted','originalMissingTmpfsErrorReproduced',
        'optionalTmpfsPreserved','requiredFieldsRefused','sourceAndRwNegativesPreserved',
        'allCliGroupsReapedAbsentAndPipesClosed','allSyntheticSocketsThreadsAndPathsClosed'))
      and all(actual.get(k)is False for k in ('daemonContainerImageOrDatabaseExecuted','privateDataAccessed',
        'officialPublishedChecksumMatched','privateAdmissionEstablished')),'formatter.proof_assertions')


def main():
    source=Path(__file__).resolve().parents[1]
    host=load(source/'host/ci_host.py')
    manifest,rows=host.bootstrap_source(source,os.environ.get('OCV_SOURCE_MANIFEST_SHA'))
    # Reuse the reviewed capture, custody, write-once and expected-input helpers.
    helpers=load(source/'metadata/run_linux_proof.py')
    context=load(source/'host/host_context.py')
    permit=context.make_native_permit(source,helpers.expected_inputs(),os.environ['OCV_MISSION_ID'])
    need(os.environ.get('OCV_PROOF_MODE')=='docker_inspect_formatter','formatter.proof_mode')
    clock=json.loads(context._read_regular(permit.temp/'ocv-job-clock.json',4096))
    need(type(clock)is dict and set(clock)=={'schema','monotonicNs'} and
         clock['schema']=='ocv-job-clock-v1' and type(clock['monotonicNs'])is int and
         0<clock['monotonicNs']<=time.monotonic_ns(),'formatter.job_clock')
    end=clock['monotonicNs']/1e9+2700;need(end-time.monotonic()>600,'formatter.job_remaining')
    project=permit.project;project.mkdir(mode=0o755);project.chmod(0o755)
    artifacts=permit.temp/'ocv-ci-artifacts';artifacts.mkdir(mode=0o755)
    pin=rows['inspect_formatter/SOURCE-MANIFEST.json']['sha256']
    result={'schema':'ocv.formatter-host-proof-result.v1','status':'failed','fixtureOnly':True,
      'candidateQualified':False,'privateAdmissionEstablished':False,'sourceManifestSha256':sha(manifest),
      'formatterSourceManifestSha256':pin,'runIdentity':{'repository':'fr-meyer/openclaw',
       'workflowRef':os.environ['GITHUB_WORKFLOW_REF'],'sourceCommit':os.environ['GITHUB_SHA'],
       'runId':permit.run_id,'runAttempt':'1'},'commands':[]}
    captures={'stdout':b'','stderr':b''};settled=True
    try:
        settled=False
        units=helpers.run_command(context,permit,'python_tests',{'source_root':str(source),'suite':'host'},
                                  min(end-30,time.monotonic()+60))
        result['commands'].append({'role':'python_tests','suite':'host',**helpers.closed_command(units)})
        settled=helpers.command_settled(units);captures={k:units[k]for k in captures}
        need(helpers.command_passed(units),'formatter.host_tests_failed');unit_result=json.loads(units['stdout'])
        need(unit_result.get('schema')=='ocv-source-tests-v1' and unit_result.get('suite')=='host'
          and unit_result.get('successful')is True and type(unit_result.get('testsRun'))is int
          and unit_result['testsRun']>=6,'formatter.host_tests_assertions');result['hostSourceTests']=unit_result
        settled=False
        download=helpers.run_command(context,permit,'formatter_docker_download',{'project':str(project)},
                                    min(end-30,time.monotonic()+130))
        result['commands'].append({'role':'formatter_docker_download',**helpers.closed_command(download)})
        settled=helpers.command_settled(download);captures={k:download[k]for k in captures}
        need(helpers.command_passed(download),'formatter.download_failed')
        extract_docker(project/'formatter-docker.tgz',project/'formatter-docker',
                       deadline=min(end-30,time.monotonic()+60))
        settled=False
        proof=helpers.run_command(context,permit,'formatter_namespace',{'project':str(project),
          'source_root':str(source),'source_manifest_sha':pin},min(end-30,time.monotonic()+300))
        result['commands'].append({'role':'formatter_namespace',**helpers.closed_command(proof)})
        settled=helpers.command_settled(proof);captures={k:proof[k]for k in captures}
        need(helpers.command_passed(proof),'formatter.namespace_failed')
        need(len(proof['stdout'])<=16384 and len(proof['stderr'])<=4096,'formatter.proof_output')
        actual=json.loads(proof['stdout']);require_proof(actual,pin);result.update(status='passed',proof=actual)
    except BaseException as error:
        text=str(error);result['failure']={'type':type(error).__name__,
          'reason':text if re.fullmatch('[A-Za-z0-9_.-]{1,160}',text)else'formatter.boundary_unknown'}
    finally:
        result['ownedProcessSettlementEstablished']=settled
        result['dockerArchiveAndProjectRetained']=True
        raw=canonical(result);need(len(raw)+sum(map(len,captures.values()))<=3*1024*1024,'formatter.artifact_bound')
        for name in captures:helpers.write_once(artifacts/('formatter-'+name+'.bin'),captures[name])
        helpers.write_once(artifacts/'formatter-result.json',raw)
    return 0 if result['status']=='passed'else 1


if __name__=='__main__':raise SystemExit(main())

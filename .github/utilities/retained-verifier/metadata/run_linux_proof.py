"""Admit and supervise only the fixed public, synthetic SQLite ABI proof."""
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

NODE_BYTES=126879696
NODE_SHA='e32e2d16081cf644f88392934288086e7662529d0d43277c34f7aad2207cfafb'
NODE_MEMBER='node-v24.22.1-linux-x64/bin/node'
ARCHIVE_CAP=100663296
CAPTURE_CAP=1024*1024


def need(value,code):
    if value is not True:raise RuntimeError(code)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')


def write_once(path,raw,mode=0o644):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb')as stream:
        need(stream.write(raw)==len(raw),'metadata.write_short');stream.flush();os.fsync(stream.fileno())


def load(path):
    name='ocv_metadata_'+path.stem
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    spec.loader.exec_module(module);return module


def extract_node(archive,destination,*,deadline):
    """Read one regular member; archive paths are never extracted to disk."""
    fact=archive.lstat()
    need(stat.S_ISREG(fact.st_mode) and fact.st_nlink==1 and not archive.is_symlink()
         and 0<fact.st_size<=ARCHIVE_CAP,'metadata.archive_identity')
    found=False;count=0
    with tarfile.open(archive,mode='r:xz')as source:
        for member in source:
            count+=1;need(count<=20000 and time.monotonic()<deadline,'metadata.archive_bound')
            if member.name!=NODE_MEMBER:continue
            need(not found and member.isreg() and not member.issparse() and
                 member.size==NODE_BYTES,'metadata.node_member');found=True
            opened=source.extractfile(member);need(opened is not None,'metadata.node_stream')
            fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o555)
            digest=hashlib.sha256();total=0
            with opened,os.fdopen(fd,'wb')as target:
                while True:
                    need(time.monotonic()<deadline,'metadata.archive_deadline')
                    raw=opened.read(min(1048576,NODE_BYTES+1-total))
                    if not raw:break
                    total+=len(raw);need(total<=NODE_BYTES,'metadata.node_bound')
                    digest.update(raw);need(target.write(raw)==len(raw),'metadata.node_write')
                target.flush();os.fchmod(target.fileno(),0o555);os.fsync(target.fileno())
            need(total==NODE_BYTES and digest.hexdigest()==NODE_SHA,'metadata.node_hash')
    need(found,'metadata.node_missing')
    after=archive.lstat()
    fields=lambda v:(v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
    need(fields(after)==fields(fact),'metadata.archive_changed')
    fact=destination.lstat()
    need(stat.S_ISREG(fact.st_mode) and fact.st_nlink==1 and fact.st_size==NODE_BYTES and
         stat.S_IMODE(fact.st_mode)==0o555,'metadata.node_identity')


def expected_inputs():
    return {'expected_source':os.environ['OCV_EXPECTED_SOURCE'],
      'expected_tree':os.environ['OCV_EXPECTED_TREE'],'workflow_sha':os.environ['OCV_WORKFLOW_SHA'],
      'source_manifest_sha':os.environ['OCV_SOURCE_MANIFEST_SHA'],
      'source_manifest_path':'PUBLIC-SOURCE-MANIFEST.json','run_id':os.environ['GITHUB_RUN_ID']}


def run_command(context,permit,role,arguments,deadline):
    scope=context.seal_command(permit,role,arguments,cwd=str(permit.project),environment=dict(context.ENV))
    value=context.run_owned(permit,scope,cwd=str(permit.project),environment=dict(context.ENV),deadline=deadline)
    need(type(value)is dict and type(value.get('stdout'))is bytes and type(value.get('stderr'))is bytes,
         'metadata.command_record')
    need(len(value['stdout'])<=CAPTURE_CAP and len(value['stderr'])<=CAPTURE_CAP,'metadata.command_capture')
    return value


def closed_command(value):
    keys=('status','returncode','timedOut','ownershipRetained','spawned','outerExited',
          'ownedGroupGone','streamsEOF','streamsClosed','truncated')
    return {**{k:value.get(k)for k in keys},
      'stdoutBytes':len(value['stdout']),'stdoutSha256':sha(value['stdout']),
      'stderrBytes':len(value['stderr']),'stderrSha256':sha(value['stderr'])}


def command_passed(value):
    return (value.get('status')=='outer_exit_passed' and value.get('returncode')==0 and
      value.get('timedOut')is False and value.get('ownershipRetained')is False and
      all(value.get(k)is True for k in ('outerExited','ownedGroupGone','streamsEOF','streamsClosed')) and
      value.get('truncated')is False)


def command_settled(value):
    return (value.get('ownershipRetained')is False and
      all(value.get(k)is True for k in ('outerExited','ownedGroupGone','streamsEOF','streamsClosed')))


def main():
    source=Path(__file__).resolve().parents[1]
    # This is the existing admission owner, not a substitute caller-supplied
    # PASS. It verifies the complete manifest, workflow and actual Git source.
    host=load(source/'host/ci_host.py')
    _manifest,rows=host.bootstrap_source(source,os.environ.get('OCV_SOURCE_MANIFEST_SHA'))
    context=load(source/'host/host_context.py')
    permit=context.make_native_permit(source,expected_inputs(),os.environ['OCV_MISSION_ID'])
    need(os.environ.get('OCV_PROOF_MODE')=='metadata_sqlite','metadata.proof_mode')
    clock=json.loads(context._read_regular(permit.temp/'ocv-job-clock.json',4096))
    need(type(clock)is dict and set(clock)=={'schema','monotonicNs'} and
         clock['schema']=='ocv-job-clock-v1' and type(clock['monotonicNs'])is int and
         0<clock['monotonicNs']<=time.monotonic_ns(),'metadata.job_clock')
    end=clock['monotonicNs']/1e9+2700
    need(end-time.monotonic()>600,'metadata.job_remaining')
    project=permit.project;project.mkdir(mode=0o755);project.chmod(0o755)
    artifacts=permit.temp/'ocv-ci-artifacts';artifacts.mkdir(mode=0o755)
    result={'schema':'ocv.metadata-host-proof-result.v1','status':'failed',
      'fixtureOnly':True,'candidateQualified':False,'privateAdmissionEstablished':False,
      'sourceManifestSha256':sha(_manifest),'metadataSourceManifestSha256':rows['metadata/SOURCE-MANIFEST.json']['sha256'],
      'runIdentity':{'repository':'fr-meyer/openclaw','workflowRef':os.environ['GITHUB_WORKFLOW_REF'],
        'sourceCommit':os.environ['GITHUB_SHA'],'runId':permit.run_id,'runAttempt':'1'},'commands':[]}
    captures={'stdout':b'','stderr':b''};settled=True
    try:
        settled=False
        units=run_command(context,permit,'python_tests',{'source_root':str(source),'suite':'host'},
                          min(end-30,time.monotonic()+60))
        result['commands'].append({'role':'python_tests','suite':'host',**closed_command(units)})
        settled=command_settled(units);captures={k:units[k]for k in captures}
        need(command_passed(units),'metadata.host_tests_failed')
        unit_result=json.loads(units['stdout'])
        need(unit_result.get('schema')=='ocv-source-tests-v1' and unit_result.get('suite')=='host' and
             unit_result.get('successful')is True and type(unit_result.get('testsRun'))is int and
             unit_result['testsRun']>=6,'metadata.host_test_assertions')
        result['hostSourceTests']=unit_result
        settled=False
        download=run_command(context,permit,'metadata_node_download',{'project':str(project)},
                             min(end-30,time.monotonic()+130))
        result['commands'].append({'role':'metadata_node_download',**closed_command(download)})
        settled=command_settled(download)
        captures={k:download[k]for k in captures};need(command_passed(download),'metadata.download_failed')
        extract_node(project/'metadata-node.tar.xz',project/'metadata-node',deadline=min(end-30,time.monotonic()+60))
        settled=False
        proof=run_command(context,permit,'metadata_sqlite_namespace',{'project':str(project),
          'source_root':str(source),'source_manifest_sha':rows['metadata/SOURCE-MANIFEST.json']['sha256']},
          min(end-30,time.monotonic()+300))
        result['commands'].append({'role':'metadata_sqlite_namespace',**closed_command(proof)})
        settled=command_settled(proof)
        captures={k:proof[k]for k in captures};need(command_passed(proof),'metadata.namespace_failed')
        need(len(proof['stdout'])<=16384 and len(proof['stderr'])<=4096,'metadata.proof_output')
        actual=json.loads(proof['stdout'])
        need(type(actual)is dict and actual.get('schema')=='ocv.generic-retained-metadata-linux-proof.v1'
          and actual.get('status')=='PASS' and actual.get('nodeSha256')==NODE_SHA
          and actual.get('sourceManifestSha256')==rows['metadata/SOURCE-MANIFEST.json']['sha256']
          and type(actual.get('syntheticDatabases'))is int and actual['syntheticDatabases']==11
          and all(actual.get(k)is True for k in ('existingWalAndShmReadonlyPositive','partialWalRefused',
            'actualAuthorizerRefusals','actualChildKillAndReapVirtualDeadline','allOwnedMountsAndPathsRemoved'))
          and actual.get('retainedDataAccessed')is False and actual.get('privateAdmissionEstablished')is False,
          'metadata.proof_assertions')
        result.update(status='passed',proof=actual)
    except BaseException as error:
        text=str(error)
        result['failure']={'type':type(error).__name__,
          'reason':text if re.fullmatch('[A-Za-z0-9_.-]{1,160}',text)else'metadata.boundary_unknown'}
    finally:
        # An uncertain owned child keeps its project and intent evidence.
        result['ownedProcessSettlementEstablished']=settled
        result['nodeArchiveAndProjectRetained']=True
        for name in captures:write_once(artifacts/('metadata-'+name+'.bin'),captures[name])
        write_once(artifacts/'metadata-result.json',canonical(result))
    return 0 if result['status']=='passed' else 1


if __name__=='__main__':raise SystemExit(main())

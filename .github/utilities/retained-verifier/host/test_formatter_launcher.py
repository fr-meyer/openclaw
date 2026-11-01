"""Pure fixed-command, archive, request and CLI-custody boundary tests.

The genuine Linux CLI witness is deliberately never executed by this suite.
"""
import copy
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import signal
import stat
import sys
import tarfile
import tempfile
import time
import types
import unittest
from contextlib import ExitStack
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parents[1]


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    spec.loader.exec_module(module);return module


entry=load('formatter_entry_tests',SOURCE/'inspect_formatter/run_linux_proof.py')
proof=load('formatter_linux_tests',SOURCE/'inspect_formatter/linux_proof.py')
factory=load('formatter_command_tests',SOURCE/'host/command_factories.py')


class FormatterHost(unittest.TestCase):
    def sealed_fixture(self):
        stack=ExitStack();self.addCleanup(stack.close)
        root=Path(stack.enter_context(tempfile.TemporaryDirectory(dir='/tmp'))).resolve();root.chmod(0o755)
        source=root/'source';source.mkdir(mode=0o755);(source/'host').mkdir();(source/'inspect_formatter').mkdir()
        files={'host/command_factories.py':(SOURCE/'host/command_factories.py').read_bytes(),
          'inspect_formatter/linux_proof.py':b'# synthetic never executed\n',
          'inspect_formatter/SOURCE-MANIFEST.json':b'{"synthetic":true}\n'};rows={}
        for name,raw in files.items():
            (source/name).write_bytes(raw)
            rows[name]={'path':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'mode':0o444}
        project=root/'project';project.mkdir(mode=0o755)
        context=entry.load(SOURCE/'host/host_context.py')
        permit=context.NativePermit(context._KEY,source=source,workspace=source,temp=root,project=project,
          expected={},mission='c'*32,rows=rows,outer=None,uid=os.getuid(),gid=os.getgid(),run_id='42')
        context._ISSUED[id(permit)]=permit;stack.callback(context._ISSUED.pop,id(permit))
        stack.enter_context(patch.dict(os.environ,{'GITHUB_RUN_ID':'42','GITHUB_RUN_ATTEMPT':'1'}))
        return context,permit,{'project':str(project),'source_root':str(source),
          'source_manifest_sha':rows['inspect_formatter/SOURCE-MANIFEST.json']['sha256']}

    def archive(self,root,rows):
        path=root/'fixture.tgz'
        with tarfile.open(path,'w:gz')as stream:
            for kind,name,body in rows:
                info=tarfile.TarInfo(name);info.type=kind
                if kind==tarfile.REGTYPE:info.size=len(body)
                else:info.linkname='outside'
                stream.addfile(info,io.BytesIO(body)if kind==tarfile.REGTYPE else None)
        return path

    def pins(self,archive,data):
        stack=ExitStack();self.addCleanup(stack.close)
        for name,value in (('ARCHIVE_BYTES',archive.stat().st_size),
          ('ARCHIVE_SHA',hashlib.sha256(archive.read_bytes()).hexdigest()),
          ('DOCKER_BYTES',len(data)),('DOCKER_SHA',hashlib.sha256(data).hexdigest())):
            stack.enter_context(patch.object(entry,name,value))

    def test_fixed_download_and_isolated_namespace_have_no_caller_command(self):
        download=factory.formatter_docker_download('/tmp/ocv-'+'a'*32)
        self.assertEqual(download[-1],'https://download.docker.com/linux/static/stable/x86_64/docker-29.8.2.tgz')
        self.assertEqual(download[download.index('--retry')+1],'0');self.assertNotIn('--location',download)
        self.assertEqual(download[download.index('--max-filesize')+1],'100663296')
        argv=factory.formatter_namespace('/tmp/ocv-'+'a'*32,'/source','b'*64)
        self.assertEqual(argv[:5],('/usr/bin/sudo','-n','--','/usr/bin/env','-i'))
        for flag in ('--mount','--net','--pid','--fork','--mount-proc','--kill-child=KILL'):
            self.assertIn(flag,argv)
        self.assertIn('/source/inspect_formatter/linux_proof.py',argv)
        self.assertEqual(argv[-4:],('--docker','/tmp/ocv-'+'a'*32+'/formatter-docker','--source-manifest-sha256','b'*64))
        for path in ('relative','/tmp/../x','/tmp/x;id','/'):
            with self.assertRaises(ValueError):factory.formatter_namespace('/tmp/project',path,'b'*64)
        for pin in ('',True,'b'*63,'b'*64+';id'):
            with self.assertRaises(ValueError):factory.formatter_namespace('/tmp/project','/source',pin)

    def test_actual_existing_sealer_requires_exact_source_and_closed_environment(self):
        context,permit,args=self.sealed_fixture()
        scope=context.seal_command(permit,'formatter_namespace',args,cwd=str(permit.project),environment=dict(context.ENV))
        self.assertEqual(scope.argv,factory.formatter_namespace(**args));self.assertEqual(scope.environment,context.ENV)
        for defect in ('pin','source','changed','environment','extra_argument'):
            with self.subTest(defect=defect):
                context,permit,args=self.sealed_fixture();env=dict(context.ENV)
                if defect=='pin':args['source_manifest_sha']='0'*64
                if defect=='source':args['source_root']=str(permit.temp)
                if defect=='changed':(permit.source/'inspect_formatter/linux_proof.py').write_bytes(b'changed')
                if defect=='environment':env['DOCKER_HOST']='unix:///var/run/docker.sock'
                if defect=='extra_argument':args['command']='arbitrary'
                with self.assertRaises(context.Refusal):
                    context.seal_command(permit,'formatter_namespace',args,cwd=str(permit.project),environment=env)
                self.assertEqual(permit.scopes,{})

    def test_archive_and_exact_member_authentication_never_extract_other_paths(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);data=b'fixed-docker'
            archive=self.archive(root,[(tarfile.REGTYPE,'../../ignored',b'not extracted'),
                                       (tarfile.REGTYPE,entry.MEMBER,data)]);self.pins(archive,data)
            entry.extract_docker(archive,root/'docker',deadline=time.monotonic()+5)
            self.assertEqual((root/'docker').read_bytes(),data)
            self.assertEqual(stat.S_IMODE((root/'docker').stat().st_mode),0o555)
            self.assertEqual(sorted(p.name for p in root.iterdir()),['docker','fixture.tgz'])

    def test_archive_symlink_hardlink_missing_duplicate_hash_size_deadline_and_existing_refuse(self):
        for failure in ('symlink','hardlink','missing','duplicate','archive_hash','member_hash','size','deadline','existing'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory()as temp:
                root=Path(temp);rows=[(tarfile.REGTYPE,entry.MEMBER,b'docker')]
                if failure=='symlink':rows=[(tarfile.SYMTYPE,entry.MEMBER,b'')]
                if failure=='hardlink':rows=[(tarfile.LNKTYPE,entry.MEMBER,b'')]
                if failure=='missing':rows=[(tarfile.REGTYPE,'other',b'docker')]
                if failure=='duplicate':rows*=2
                archive=self.archive(root,rows);self.pins(archive,b'docker')
                if failure=='archive_hash':entry.ARCHIVE_SHA='0'*64
                if failure=='member_hash':entry.DOCKER_SHA='0'*64
                if failure=='size':entry.DOCKER_BYTES=7
                if failure=='existing':(root/'docker').write_bytes(b'KEEP')
                with self.assertRaises((RuntimeError,FileExistsError)):
                    entry.extract_docker(archive,root/'docker',deadline=time.monotonic()+(-1 if failure=='deadline'else 5))
                if failure=='existing':self.assertEqual((root/'docker').read_bytes(),b'KEEP')

    def test_request_policy_admits_only_fixed_resource_and_bounded_handshake(self):
        routes=[('HEAD','/_ping'),('GET','/_ping'),('GET','/v1.53/containers/'+proof.CID+'/json')]
        for method,path in routes:
            self.assertEqual(proof.request_route((method+' '+path+' HTTP/1.1\r\nHost: local\r\n\r\n').encode()),(method,path))
        for raw in (b'GET /containers/other/json HTTP/1.1\r\n\r\n',b'POST /_ping HTTP/1.1\r\n\r\n',
          b'GET /_ping HTTP/1.1\r\nAuthorization: secret\r\n\r\n',
          b'GET /_ping HTTP/1.1\r\nContent-Length: 1\r\n\r\nx',
          b'GET /_ping HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n',
          b'GET /_ping HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n',b'x'*8193):
            with self.assertRaises((RuntimeError,ValueError)):proof.request_route(raw)

        # Exercise the actual run_case vector with effects below its owned CLI
        # and socket seams; private source invokes generic inspect, not the
        # container subcommand. No process/socket operation occurs here.
        with tempfile.TemporaryDirectory()as temp,\
          patch.object(proof,'InspectServer',return_value=types.SimpleNamespace(close=lambda:None)),\
          patch.object(proof,'cli_capture',return_value={'synthetic':True})as capture:
            proof.run_case(Path('/fixed/docker'),Path(temp),'fixed-template',proof.fixture(),time.monotonic()+20)
            argv=capture.call_args.args[0]
            self.assertEqual(argv[5:],['inspect','--format','fixed-template',proof.CID])
            self.assertEqual(argv[:2],['/fixed/docker','--config'])
            self.assertEqual(argv[3],'--host');self.assertTrue(argv[4].startswith('unix://'+temp+'/'))
            self.assertNotIn('container',argv)

    def test_generic_geometry_and_pure_expected_atoms_stay_bounded(self):
        value=proof.fixture();self.assertEqual(len(value['Mounts']),36)
        self.assertTrue(all(len(m['Source'])==192 for m in value['Mounts']))
        for prior in (False,True):
            expected=proof.projected(value,prior)
            self.assertLessEqual(len(proof.compact(expected))+1,16384)
            self.assertTrue(all(row[4]is True and row[2]is False for row in expected['Mounts']))
            changed=copy.deepcopy(value);changed['Mounts'][0]['Source']='/substituted';changed['Mounts'][0]['RW']=True
            out=proof.projected(changed,prior);self.assertIs(out['Mounts'][0][4],False);self.assertIs(out['Mounts'][0][2],True)
        self.assertEqual(hashlib.sha256((SOURCE/'inspect_formatter/normal-inspect-template.txt').read_bytes()).hexdigest(),proof.NORMAL_SHA)
        self.assertEqual(hashlib.sha256((SOURCE/'inspect_formatter/prior-inspect-template.txt').read_bytes()).hexdigest(),proof.PRIOR_SHA)


class FormatterEntry(unittest.TestCase):
    def actual(self):
        return {'schema':'ocv.generic-docker-inspect-formatter-linux-proof.v1','status':'PASS',
          'sourceManifestSha256':'a'*64,'dockerSha256':entry.DOCKER_SHA,'dockerBytes':entry.DOCKER_BYTES,
          'dockerVersion':'29.8.2','normalTemplateSha256':entry.NORMAL_SHA,'priorTemplateSha256':entry.PRIOR_SHA,
          'cases':[{}for _ in range(26)],'maximumFormattedBytes':15000,'formattedCaptureCapBytes':16384,
          'apiVersion':'1.53','maximumRequestsPerCli':4,'fixedPingAndInspectRoutesOnly':True,
          'syntheticBinds':36,'syntheticSourcePathBytes':192,
          **{k:True for k in ('bothActualCliTemplatesExecuted','originalMissingTmpfsErrorReproduced',
            'optionalTmpfsPreserved','requiredFieldsRefused','sourceAndRwNegativesPreserved',
            'allCliGroupsReapedAbsentAndPipesClosed','allSyntheticSocketsThreadsAndPathsClosed')},
          **{k:False for k in ('daemonContainerImageOrDatabaseExecuted','privateDataAccessed',
            'officialPublishedChecksumMatched','privateAdmissionEstablished')}}

    def test_exact_new_proof_obligations_missing_false_changed_or_unsettled_cannot_pass(self):
        actual=self.actual();entry.require_proof(actual,'a'*64)
        for key in actual:
            changed=dict(actual);changed.pop(key)
            with self.subTest(key=key),self.assertRaises(RuntimeError):entry.require_proof(changed,'a'*64)
        for key,value in (('cases',[{}]*25),('maximumFormattedBytes',16385),
          ('allCliGroupsReapedAbsentAndPipesClosed',False),('fixedPingAndInspectRoutesOnly',False),
          ('dockerSha256','0'*64),('normalTemplateSha256','0'*64),('priorTemplateSha256','0'*64)):
            changed=dict(actual);changed[key]=value
            with self.subTest(key=key),self.assertRaises(RuntimeError):entry.require_proof(changed,'a'*64)

    def test_actual_entry_three_typed_commands_and_three_output_closeout_with_no_native_effects(self):
        helpers=entry.load(SOURCE/'metadata/run_linux_proof.py')
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);actual=self.actual();calls=[]
            context=types.SimpleNamespace(ENV={'PATH':'/usr/bin:/bin'},
              _read_regular=lambda path,cap:entry.canonical({'schema':'ocv-job-clock-v1','monotonicNs':time.monotonic_ns()-1000000}))
            permit=types.SimpleNamespace(temp=root,project=root/'project',run_id='42')
            context.make_native_permit=lambda *args:permit
            host=types.SimpleNamespace(bootstrap_source=lambda *args:(b'{}',{'inspect_formatter/SOURCE-MANIFEST.json':{'sha256':'a'*64}}))
            def owned(context,permit,role,arguments,deadline):
                calls.append((role,arguments))
                body=({'schema':'ocv-source-tests-v1','suite':'host','successful':True,'testsRun':6}
                      if role=='python_tests'else actual if role=='formatter_namespace'else None)
                return {'stdout':entry.canonical(body)if body is not None else b'','stderr':b'',
                  'status':'outer_exit_passed','returncode':0,'timedOut':False,'ownershipRetained':False,
                  'spawned':True,'outerExited':True,'ownedGroupGone':True,'streamsEOF':True,'streamsClosed':True,'truncated':False}
            cloned=types.SimpleNamespace(**{k:getattr(helpers,k)for k in
               ('expected_inputs','closed_command','command_settled','command_passed','write_once')},run_command=owned)
            modules={'ci_host.py':host,'host_context.py':context,'run_linux_proof.py':cloned}
            environment={'OCV_PROOF_MODE':'docker_inspect_formatter','OCV_MISSION_ID':'c'*32,
              'OCV_EXPECTED_SOURCE':'d'*40,'OCV_EXPECTED_TREE':'e'*40,'OCV_WORKFLOW_SHA':'f'*64,
              'OCV_SOURCE_MANIFEST_SHA':'a'*64,'GITHUB_RUN_ID':'42','GITHUB_WORKFLOW_REF':'synthetic',
              'GITHUB_SHA':'d'*40}
            with patch.object(entry,'load',side_effect=lambda path:modules[path.name]),\
                 patch.object(entry,'extract_docker')as extracted,patch.dict(os.environ,environment):
                self.assertEqual(entry.main(),0);extracted.assert_called_once()
            self.assertEqual([c[0]for c in calls],['python_tests','formatter_docker_download','formatter_namespace'])
            self.assertEqual(calls[-1][1]['source_manifest_sha'],'a'*64)
            artifacts=root/'ocv-ci-artifacts'
            self.assertEqual(sorted(p.name for p in artifacts.iterdir()),
              ['formatter-result.json','formatter-stderr.bin','formatter-stdout.bin'])
            result=__import__('json').loads((artifacts/'formatter-result.json').read_bytes())
            self.assertEqual(result['status'],'passed');self.assertIs(result['ownedProcessSettlementEstablished'],True)


class FakePipe:
    def __init__(self,fd):self.fd=fd;self.closed=False
    def fileno(self):return self.fd
    def close(self):self.closed=True


class FakeSelector:
    def __init__(self):self.keys={};self.closed=False
    def register(self,pipe,event,data):self.keys[pipe.fd]=types.SimpleNamespace(fileobj=pipe,data=data)
    def unregister(self,pipe):del self.keys[pipe.fd]
    def get_map(self):return self.keys
    def select(self,seconds):return [(key,1)for key in list(self.keys.values())]
    def close(self):self.closed=True


class CliCustody(unittest.TestCase):
    def execute(self,defect=None):
        child=types.SimpleNamespace(pid=42,stdout=FakePipe(11),stderr=FakePipe(12),returncode=None if defect=='timeout'else 0)
        child.poll=lambda:child.returncode
        child.wait=lambda timeout:setattr(child,'returncode',0)or 0
        selector=FakeSelector();chunks={11:[b'x'*16385 if defect=='overflow'else b'{}\n',b''],12:[b'']};signals=[]
        def read(fd,size):return chunks[fd].pop(0)
        def term(pid,sig):signals.append((pid,sig));child.returncode=-sig
        with patch.object(proof.subprocess,'Popen',side_effect=OSError('synthetic')if defect=='spawn'else None,return_value=child)as spawn,\
          patch.object(proof.selectors,'DefaultSelector',return_value=selector),patch.object(proof.os,'set_blocking'),\
          patch.object(proof.os,'read',side_effect=read),patch.object(proof.os,'killpg',side_effect=term),\
          patch.object(proof,'group_absent',side_effect=lambda pid:child.returncode is not None),\
          patch.object(proof.time,'monotonic',return_value=10):
            if defect:
                with self.assertRaises((RuntimeError,OSError)):proof.cli_capture(['/fixed'],{},1 if defect=='timeout'else 20)
            else:
                result=proof.cli_capture(['/fixed'],{},20)
                self.assertEqual(result['stdout'],b'{}\n')
                self.assertTrue(all(result[k]for k in ('reaped','groupAbsent','streamsEOF','streamsClosed')))
            if defect!='spawn':
                self.assertTrue(child.stdout.closed and child.stderr.closed)
                self.assertTrue(spawn.call_args.kwargs['start_new_session'])
            self.assertTrue(selector.closed)
        if defect=='timeout':self.assertEqual(signals,[(42,signal.SIGTERM)])

    def test_actual_capture_success_requires_reap_group_absence_and_both_eof(self):self.execute()
    def test_actual_capture_timeout_overflow_and_spawn_refuse_with_owned_cleanup(self):
        for defect in ('timeout','overflow','spawn'):
            with self.subTest(defect=defect):self.execute(defect)


if __name__=='__main__':unittest.main()

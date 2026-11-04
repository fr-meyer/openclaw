"""Pure command, archive-authentication and uncertain-closeout regressions."""
import hashlib
import copy
import importlib.util
import io
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch
from contextlib import ExitStack

SOURCE=Path(__file__).resolve().parents[1]


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    spec.loader.exec_module(module);return module


entry=load('metadata_entry_tests',SOURCE/'metadata/run_linux_proof.py')
factory=load('metadata_command_tests',SOURCE/'host/command_factories.py')


class MetadataHost(unittest.TestCase):
    def sealed_fixture(self):
        stack=ExitStack();self.addCleanup(stack.close)
        temp=stack.enter_context(tempfile.TemporaryDirectory(dir='/tmp'))
        root=Path(temp).resolve();root.chmod(0o755)
        source=root/'source';source.mkdir(mode=0o755)
        (source/'host').mkdir();(source/'metadata').mkdir()
        rows={}
        files={'host/command_factories.py':(SOURCE/'host/command_factories.py').read_bytes(),
          'metadata/linux_proof.py':b'# Synthetic unexecuted source fixture\n',
          'metadata/SOURCE-MANIFEST.json':b'{"synthetic":true}\n'}
        for name,raw in files.items():
            (source/name).write_bytes(raw)
            rows[name]={'path':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'mode':0o444}
        project=root/'project';project.mkdir(mode=0o755)
        context=entry.load(SOURCE/'host/host_context.py')
        # Data-only internal issuance fixture; the genuine platform/source
        # admission factory and every native process operation remain unused.
        permit=context.NativePermit(context._KEY,source=source,workspace=source,temp=root,
          project=project,expected={},mission='c'*32,rows=rows,outer=None,
          uid=os.getuid(),gid=os.getgid(),run_id='42')
        context._ISSUED[id(permit)]=permit
        stack.callback(context._ISSUED.pop,id(permit))
        stack.enter_context(patch.dict(os.environ,{'GITHUB_RUN_ID':'42','GITHUB_RUN_ATTEMPT':'1'}))
        args={'project':str(project),'source_root':str(source),
          'source_manifest_sha':rows['metadata/SOURCE-MANIFEST.json']['sha256']}
        return context,permit,args

    def archive(self,root,rows):
        path=root/'node.tar.xz'
        with tarfile.open(path,'w:xz')as stream:
            for kind,name,body in rows:
                info=tarfile.TarInfo(name);info.type=kind
                if kind==tarfile.REGTYPE:info.size=len(body)
                else:info.linkname='outside'
                stream.addfile(info,io.BytesIO(body)if kind==tarfile.REGTYPE else None)
        return path

    def test_fixed_download_and_namespace_have_no_caller_command_or_inherited_environment(self):
        download=factory.metadata_node_download('/tmp/ocv-'+'a'*32)
        self.assertEqual(download[-1],'https://nodejs.org/dist/v24.22.1/node-v24.22.1-linux-x64.tar.xz')
        self.assertEqual(download[download.index('--retry')+1],'0')
        self.assertEqual(download[download.index('--max-filesize')+1],'100663296')
        self.assertNotIn('--location',download)
        argv=factory.metadata_sqlite_namespace('/tmp/ocv-'+'a'*32,'/source','b'*64)
        self.assertEqual(argv[:5],('/usr/bin/sudo','-n','--','/usr/bin/env','-i'))
        for flag in ('--mount','--net','--pid','--fork','--mount-proc','--kill-child=KILL'):
            self.assertIn(flag,argv)
        self.assertIn('/source/metadata/linux_proof.py',argv)
        self.assertEqual(argv[-2:],('--source-manifest-sha256','b'*64))

    def test_namespace_rejects_path_or_manifest_substitution(self):
        for path in ('relative','/tmp/../outside','/tmp/x;id','/'):
            with self.subTest(path=path),self.assertRaises(ValueError):
                factory.metadata_sqlite_namespace('/tmp/project',path,'b'*64)
        for pin in ('',True,'b'*63,'b'*64+';id'):
            with self.subTest(pin=pin),self.assertRaises(ValueError):
                factory.metadata_sqlite_namespace('/tmp/project','/source',pin)

    def test_actual_existing_sealer_binds_metadata_source_and_closed_environment(self):
        context,permit,args=self.sealed_fixture()
        scope=context.seal_command(permit,'metadata_sqlite_namespace',args,
          cwd=str(permit.project),environment=dict(context.ENV))
        self.assertFalse(scope.consumed)
        self.assertEqual(scope.argv,factory.metadata_sqlite_namespace(**args))
        self.assertEqual(scope.environment,context.ENV)
        self.assertNotIn('GITHUB_TOKEN',scope.environment)

    def test_actual_sealer_refuses_wrong_manifest_source_changed_bytes_and_extra_environment(self):
        for defect in ('manifest','source','changed','environment'):
            with self.subTest(defect=defect):
                context,permit,args=self.sealed_fixture();env=dict(context.ENV)
                if defect=='manifest':args['source_manifest_sha']='0'*64
                if defect=='source':args['source_root']=str(permit.temp)
                if defect=='changed':(permit.source/'metadata/linux_proof.py').write_bytes(b'changed\n')
                if defect=='environment':env['GITHUB_TOKEN']='synthetic-must-not-forward'
                with self.assertRaises(context.Refusal):
                    context.seal_command(permit,'metadata_sqlite_namespace',args,
                      cwd=str(permit.project),environment=env)
                self.assertEqual(permit.scopes,{})

    def test_exact_member_hash_mode_and_no_arbitrary_archive_extraction(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp);data=b'node'
            archive=self.archive(root,[(tarfile.REGTYPE,'../../not-extracted',b'ignored'),
              (tarfile.REGTYPE,entry.NODE_MEMBER,data)])
            with patch.object(entry,'NODE_BYTES',len(data)),patch.object(entry,'NODE_SHA',hashlib.sha256(data).hexdigest()):
                old=os.umask(0o077)
                try:entry.extract_node(archive,root/'node',deadline=time.monotonic()+5)
                finally:os.umask(old)
            self.assertEqual((root/'node').read_bytes(),data)
            self.assertEqual(stat.S_IMODE((root/'node').stat().st_mode),0o555)
            self.assertEqual(sorted(p.name for p in root.iterdir()),['node','node.tar.xz'])

    def test_symlink_hardlink_missing_and_duplicate_member_refuse(self):
        cases=[[(tarfile.SYMTYPE,entry.NODE_MEMBER,b'')],[(tarfile.LNKTYPE,entry.NODE_MEMBER,b'')],
          [(tarfile.REGTYPE,'unrelated',b'node')],[(tarfile.REGTYPE,entry.NODE_MEMBER,b'node')]*2]
        for rows in cases:
            with self.subTest(rows=rows),tempfile.TemporaryDirectory()as temp:
                root=Path(temp);archive=self.archive(root,rows)
                with patch.object(entry,'NODE_BYTES',4),patch.object(entry,'NODE_SHA',hashlib.sha256(b'node').hexdigest()):
                    with self.assertRaises(RuntimeError):entry.extract_node(archive,root/'node',deadline=time.monotonic()+5)

    def test_wrong_size_hash_expired_deadline_or_existing_destination_refuse(self):
        for failure in ('size','hash','deadline','existing'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory()as temp:
                root=Path(temp);archive=self.archive(root,[(tarfile.REGTYPE,entry.NODE_MEMBER,b'node')])
                if failure=='existing':(root/'node').write_bytes(b'KEEP')
                with patch.object(entry,'NODE_BYTES',5 if failure=='size'else 4),\
                     patch.object(entry,'NODE_SHA','0'*64 if failure=='hash'else hashlib.sha256(b'node').hexdigest()):
                    with self.assertRaises((RuntimeError,FileExistsError)):
                        entry.extract_node(archive,root/'node',deadline=time.monotonic()+(-1 if failure=='deadline'else 5))
                if failure=='existing':self.assertEqual((root/'node').read_bytes(),b'KEEP')

    def test_failed_or_unknown_process_custody_cannot_become_pass(self):
        full={'status':'outer_exit_passed','returncode':0,'timedOut':False,'ownershipRetained':False,
          'outerExited':True,'ownedGroupGone':True,'streamsEOF':True,'streamsClosed':True,'truncated':False}
        self.assertTrue(entry.command_passed(full));self.assertTrue(entry.command_settled(full))
        for key in full:
            changed=dict(full);changed[key]=None
            with self.subTest(key=key):self.assertFalse(entry.command_passed(changed))
        for key in ('ownershipRetained','outerExited','ownedGroupGone','streamsEOF','streamsClosed'):
            changed=dict(full);changed[key]=None
            with self.subTest(key=key):self.assertFalse(entry.command_settled(changed))
        failed=dict(full,status='outer_exit_failed',returncode=1)
        self.assertFalse(entry.command_passed(failed));self.assertTrue(entry.command_settled(failed))

    def test_closed_schema_init_witness_requires_all_cases_exact_limits_and_terminal_children(self):
        rows={'metadata/metadata_reader.cjs':{'sha256':'e'*64},'metadata/source_table.sql':{'bytes':4644}}
        names=['small','long','public_table','generated_function','expression_index']
        init={'schema':'ocv.synthetic-sqlite-schema-init-witness.v1','nodeVersion':'24.22.1','sqliteVersion':'3.51.0',
          'limits':{'length':262144,'sqlLength':8192,'attach':0},'readonly':True,'extensionsDisabled':True,
          'authorizerUnchanged':True,'sourceCopiesReadableByReader':True,'sourceReaderSha256':'e'*64,'publicSourceCreateBytes':4644,
          'syntheticLongCreateBytes':5144,'fixedPrimitiveIds':list(range(1,10)),
          'exactReadonlyAuthorizerNegativeCases':7,'negativeCheckFailureCode':None,'privateDataAccessed':False,'applicationRowsReturned':False,
          'cases':[{'name':n,'initializationPassed':True,'failure':None,
            'connectionReturned':True,'connectionClosed':True,'statementCloseFailureCode':None,'databaseCloseFailureCode':None,'versionValidated':True,'authorizerCallbacks':3,'denied':[]}for n in names]}
        init['aboveLimitCreateBytes']=10277;init['aboveLimit']={'name':'above_limit','initializationPassed':False,
          'failure':{'primitive':8,'code':11,'kind':1},'connectionReturned':True,'connectionClosed':True,
          'statementCloseFailureCode':None,'databaseCloseFailureCode':None,'versionValidated':False,
          'authorizerCallbacks':1,'denied':[]}
        full=[{'name':n,'status':'COMPLETED','failure':None,
          'childClosedAndReaped':True,'deadlineReached':False}for n in names[1:]]
        full.append({'name':'above_limit','status':'REFUSED','failure':{'ordinal':0,'pathSha256':'a'*64,'stage':4,'code':11,'sqliteVersion':None},'childClosedAndReaped':True,'deadlineReached':False})
        good={'schemaInitialization':init,'fullReaderSchemaInitialization':full}
        entry.require_schema_initialization(good,rows)
        positive=copy.deepcopy(good);positive['fullReaderSchemaInitialization'][0].update(status='COMPLETED',failure=None)
        entry.require_schema_initialization(positive,rows)
        unopened=copy.deepcopy(good);unopened['schemaInitialization']['cases'][1].update(initializationPassed=False,versionValidated=False,connectionReturned=False,connectionClosed=False,failure={'primitive':1,'code':11,'kind':1})
        with self.assertRaisesRegex(RuntimeError,'metadata.schema_init_within_bound'):entry.require_schema_initialization(unopened,rows)
        for defect in('limit','baseline','missing','source','private','uncertain','deadline','boolcode','unclosed','closefailure','unopenedpass','missingversion','unreadable','withinrefusal','aboveaccepted','aboveboolkind','aboveversion','aboveextra'):
            bad=copy.deepcopy(good)
            if defect=='limit':bad['schemaInitialization']['limits']['sqlLength']=16384
            elif defect=='baseline':bad['schemaInitialization']['cases'][0]['initializationPassed']=False
            elif defect=='missing':bad['fullReaderSchemaInitialization'].pop()
            elif defect=='source':bad['schemaInitialization']['sourceReaderSha256']='0'*64
            elif defect=='private':bad['schemaInitialization']['privateDataAccessed']=True
            elif defect=='uncertain':bad['fullReaderSchemaInitialization'][0]['childClosedAndReaped']=False
            elif defect=='deadline':bad['fullReaderSchemaInitialization'][0]['deadlineReached']=True
            elif defect=='boolcode':bad['fullReaderSchemaInitialization'][-1]['failure']['code']=True
            elif defect=='unclosed':bad['schemaInitialization']['cases'][1]['connectionClosed']=False
            elif defect=='closefailure':bad['schemaInitialization']['cases'][1]['databaseCloseFailureCode']=5
            elif defect=='unopenedpass':bad['schemaInitialization']['cases'][0].update(connectionReturned=False,connectionClosed=False)
            elif defect=='missingversion':bad['schemaInitialization']['cases'][0]['versionValidated']=False
            elif defect=='unreadable':bad['schemaInitialization']['sourceCopiesReadableByReader']=False
            elif defect=='withinrefusal':bad['fullReaderSchemaInitialization'][0].update(status='REFUSED',failure={'ordinal':0,'pathSha256':'a'*64,'stage':4,'code':11,'sqliteVersion':None})
            elif defect=='aboveaccepted':bad['schemaInitialization']['aboveLimit']['initializationPassed']=True
            elif defect=='aboveboolkind':bad['schemaInitialization']['aboveLimit']['failure']['kind']=True
            elif defect=='aboveversion':bad['schemaInitialization']['aboveLimit']['versionValidated']=True
            else:bad['schemaInitialization']['aboveLimit']['extra']=0
            with self.subTest(defect=defect),self.assertRaises(RuntimeError):entry.require_schema_initialization(bad,rows)

    def test_synthetic_nested_child_failure_retains_bounded_diagnostics_without_becoming_pass(self):
        proof=load('schema_diagnostic_source_test',SOURCE/'metadata/linux_proof.py')
        import json,base64,subprocess,types
        for stdout,stderr in((b'{"cases":[{"primitive":1,"code":11}]}',b'AssertionError: synthetic constructor lifecycle'),(b'x'*16385,b'y'*4097)):
            result=types.SimpleNamespace(returncode=1,stdout=stdout,stderr=stderr)
            capture=io.StringIO()
            with patch('sys.stdout',capture),self.assertRaises(RuntimeError):proof.schema_require(result,'schema-probe')
            value=json.loads(capture.getvalue());self.assertEqual(value['schema'],'ocv.synthetic-schema-child-failure.v1')
            self.assertEqual(value['exitCode'],1);self.assertTrue(value['syntheticOnly']);self.assertFalse(value['retainedDataAccessed']);self.assertLessEqual(len(capture.getvalue().encode()),16384)
            for name,raw in(('stdout',stdout),('stderr',stderr)):
                self.assertEqual(value[name]['bytes'],len(raw));self.assertEqual(base64.b64decode(value[name]['base64']),raw[:4096]);self.assertIs(value[name]['truncated'],len(raw)>4096)
        good=types.SimpleNamespace(returncode=0,stdout=b'{}',stderr=b'')
        capture=io.StringIO()
        with patch('sys.stdout',capture):self.assertIs(proof.schema_require(good,'schema-probe'),good)
        self.assertEqual(capture.getvalue(),'')
        capture=io.StringIO()
        error=subprocess.TimeoutExpired(['synthetic'],70,output=b'partial-synthetic',stderr=b'synthetic-timeout')
        with patch.object(proof.subprocess,'run',side_effect=error),patch('sys.stdout',capture),self.assertRaises(subprocess.TimeoutExpired):proof.run(['synthetic'],diagnostic='schema-probe')
        self.assertTrue(json.loads(capture.getvalue())['timedOut'])
        capture=io.StringIO()
        with patch.object(proof.subprocess,'run',return_value=types.SimpleNamespace(returncode=0,stdout=b'x'*16385,stderr=b'')),patch('sys.stdout',capture),self.assertRaises(RuntimeError):proof.run(['synthetic'],diagnostic='schema-probe')
        self.assertEqual(json.loads(capture.getvalue())['stdout']['bytes'],16385)

    def test_schema_marker_cases_preserve_four_strict_typed_guards(self):
        good={'schemaMarkerFourStrictPredicatesAndMasks':True,'schemaMarkerCases':[
          {'mask':mask,'status':'REFUSED'if mask else'COMPLETED','code':12900+mask if mask else None,
           'childClosedAndReaped':True,'deadlineReached':False}for mask in(0,1,2,4,8,15)]}
        entry.require_schema_markers(good)
        for defect in('missing','boolmask','boolcode','extra','wrongbit','mismatchpass','baselinefail','unclosed','deadline','flag'):
            bad=copy.deepcopy(good);rows=bad['schemaMarkerCases']
            if defect=='missing':rows.pop()
            elif defect=='boolmask':rows[1]['mask']=True
            elif defect=='boolcode':rows[1]['code']=True
            elif defect=='extra':rows[1]['raw']='must-not-pass'
            elif defect=='wrongbit':rows[1]['code']=12902
            elif defect=='mismatchpass':rows[1]['status']='COMPLETED'
            elif defect=='baselinefail':rows[0]['status']='REFUSED'
            elif defect=='unclosed':rows[1]['childClosedAndReaped']=False
            elif defect=='deadline':rows[1]['deadlineReached']=True
            else:bad['schemaMarkerFourStrictPredicatesAndMasks']=False
            with self.subTest(defect=defect),self.assertRaises(RuntimeError):entry.require_schema_markers(bad)

    def writer_rows(self):
        values=['2026.10.5','synthetic-previous-build','synthetic-unknown-build',None,'','x'*128,'é'*64,'2026.10.5',None,'','synthetic-other']
        return [{'ordinal':n,'writerStamp':entry.synthetic_stamp(v),'appVersionMatches':v=='2026.10.5'}for n,v in enumerate(values)]

    def test_optional_writer_observation_typed_bidirectional_consistency_and_all11(self):
        rows=self.writer_rows();entry.require_observation_rows(rows)
        proof=load('optional_writer_projection_test',SOURCE/'metadata/linux_proof.py')
        self.assertEqual(proof.observations({'status':'METADATA_CONSISTENT','rows':rows}),rows)
        for defect in('true-null','false-current','true-other','number','missing','extra','boolbytes','oversize','nontext','null-bytes','badsha','ordinal','omitted','current-wrong-length','empty-wrong-hash','empty-wrong-length'):
            bad=copy.deepcopy(rows);row=bad[0];d=row['writerStamp']
            if defect=='true-null':row['writerStamp']={'kind':'null','utf8Bytes':None,'sha256':None}
            elif defect=='false-current':row['appVersionMatches']=False
            elif defect=='true-other':d['sha256']='0'*64
            elif defect=='current-wrong-length':d['utf8Bytes']=0;row['appVersionMatches']=False
            elif defect=='empty-wrong-hash':d['utf8Bytes']=0;d['sha256']='0'*64;row['appVersionMatches']=False
            elif defect=='empty-wrong-length':d['sha256']=hashlib.sha256(b'').hexdigest();row['appVersionMatches']=False
            elif defect=='number':row['appVersionMatches']=1
            elif defect=='missing':del row['writerStamp']
            elif defect=='extra':d['raw']='not-permitted'
            elif defect=='boolbytes':d['utf8Bytes']=True
            elif defect=='oversize':d['utf8Bytes']=129
            elif defect=='nontext':d['kind']='nontext'
            elif defect=='null-bytes':row['writerStamp']={'kind':'null','utf8Bytes':0,'sha256':None}
            elif defect=='badsha':d['sha256']='not-hash'
            elif defect=='ordinal':row['ordinal']=True
            else:bad.pop()
            with self.subTest(defect=defect),self.assertRaises(RuntimeError):entry.require_observation_rows(bad)

    def test_optional_writer_case_roster_and_refusal_binding(self):
        expected={'current':('2026.10.5',None),'null':(None,None),'empty':('',None),'synthetic':('synthetic-previous-build',None),
          'unknown':('synthetic-unknown-build',None),'nontext':(None,12932),'blob':(None,12932),'ascii128':('x'*128,None),'ascii129':(None,12933),
          'utf8_128':('é'*64,None),'utf8_129':(None,12933)}
        good={'writerStampOptionalMetadataAndByteBounds':True,'writerObservationRows':self.writer_rows(),'writerStampCases':[
          {'name':name,'status':'REFUSED'if code else'COMPLETED','code':code,'writerStamp':None if code else entry.synthetic_stamp(v),
           'appVersionMatches':None if code else v=='2026.10.5','childClosedAndReaped':True,'deadlineReached':False}for name,(v,code)in expected.items()]}
        entry.require_writer_stamp_cases(good)
        for defect in('missing','extra','substitution','false-current','unsafe-success','unsafe-hash','boolcode','unclosed','deadline','flag','all11-substitution'):
            bad=copy.deepcopy(good);row=bad['writerStampCases'][0]
            if defect=='missing':del row['writerStamp']
            elif defect=='extra':row['raw']='not-permitted'
            elif defect=='substitution':row['writerStamp']['sha256']='0'*64
            elif defect=='false-current':row['appVersionMatches']=False
            elif defect=='unsafe-success':bad['writerStampCases'][5]['status']='COMPLETED'
            elif defect=='unsafe-hash':bad['writerStampCases'][5]['writerStamp']=entry.synthetic_stamp('')
            elif defect=='boolcode':bad['writerStampCases'][5]['code']=True
            elif defect=='unclosed':row['childClosedAndReaped']=False
            elif defect=='deadline':row['deadlineReached']=True
            elif defect=='all11-substitution':bad['writerObservationRows'][1]['writerStamp']=entry.synthetic_stamp('synthetic-different')
            else:bad['writerStampOptionalMetadataAndByteBounds']=False
            with self.subTest(defect=defect),self.assertRaises(RuntimeError):entry.require_writer_stamp_cases(bad)

    def test_exact_four_source_copies_use_owned_readable_work_and_reject_substitution(self):
        proof=load('schema_copy_source_test',SOURCE/'metadata/linux_proof.py')
        rows=[{'path':n,'bytes':(SOURCE/'metadata'/n).stat().st_size,
          'sha256':hashlib.sha256((SOURCE/'metadata'/n).read_bytes()).hexdigest()}for n in proof.SCHEMA_SOURCE_LEAVES]
        with tempfile.TemporaryDirectory()as raw:
            root=Path(raw).resolve();work=root/'work';work.mkdir(mode=0o755)
            copied=proof.copy_schema_sources(SOURCE/'metadata',work,{'files':rows})
            self.assertEqual(copied,work/'schema-programs');self.assertEqual(stat.S_IMODE(copied.stat().st_mode),0o755)
            self.assertEqual(sorted(x.name for x in copied.iterdir()),sorted(proof.SCHEMA_SOURCE_LEAVES))
            for row in rows:
                target=copied/row['path'];self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o444)
                self.assertEqual(target.read_bytes(),(SOURCE/'metadata'/row['path']).read_bytes());self.assertEqual(target.stat().st_nlink,1)
            with self.assertRaises(FileExistsError):proof.copy_schema_sources(SOURCE/'metadata',work,{'files':rows})
            wrong=copy.deepcopy(rows);wrong[0]['sha256']='0'*64
            another=root/'another';another.mkdir(mode=0o755)
            with self.assertRaises(RuntimeError):proof.copy_schema_sources(SOURCE/'metadata',another,{'files':wrong})
            self.assertFalse((another/'schema-programs'/rows[0]['path']).exists())
            fake=root/'fake';fake.mkdir();third=root/'third';third.mkdir(mode=0o755)
            for row in rows:(fake/row['path']).symlink_to(SOURCE/'metadata'/row['path'])
            with self.assertRaises(RuntimeError):proof.copy_schema_sources(fake,third,{'files':rows})
            self.assertFalse((third/'schema-programs'/rows[0]['path']).exists())


    def fd_witness(self):
        rows={'metadata/'+name:{'sha256':pin}for name,pin in(
          ('native-copy-worker.mjs','a'*64),('native-copy-worker-before.mjs','b'*64),('test-held-fd-linux.mjs','c'*64))}
        value={'schema':'ocv.synthetic-worker-real-fd-proof.v1','status':'PASS',
          'interpreter':{'version':'24.22.1','platform':'linux','arch':'x64','uid':1000,'gid':1000},
          'cases':[{'name':name,'passed':True}for name in entry.FD_CASES],'caseCount':len(entry.FD_CASES),
          'realFd':{'readonlyNoFollowOpen':True,'heldIdentityCheckedBeforeSingleClose':True,'oldClosedFstatErrno':-9,
            'oldClosedFstatCode':'EBADF','oldRunPhaseReproduced':True,'fixedRunPhasePassed':True,
            'allOwnedDescriptorsClosed':True,'allOwnedFilesRemoved':True},
          'scope':{'ordinarySyntheticFilesOnly':True,'actualRunPhase':True,'actualFilesystem':True,
            'syntheticDatabasePorts':True,'syntheticPackagePorts':True,'candidatePackagesImported':False,
            'sqliteImported':False,'databasesOpened':False,'privateDataAccessed':False,'nativeMaintenanceProved':False},
          'deniedEffectAttempts':0}
        return {'maintenanceFdLifecycle':{'workerSha256':'a'*64,'beforeWorkerSha256':'b'*64,
          'fixtureSha256':'c'*64,'proof':value}},rows

    def test_real_fd_witness_requires_exact_sources_runtime_closed_cases_and_limited_scope(self):
        good,rows=self.fd_witness();entry.require_maintenance_fd_lifecycle(good,rows)
        for defect in('missing','extra','worker','before','fixture','runtime','uid','gid','root','missingcase','duplicatecase',
                      'caseextra','failedcase','boolcount','baderrno','unknowncode','unclosed','unremoved','falsefs',
                      'fakepackageshidden','candidate','sqlite','database','private','maintenance','effect','booleffect'):
            bad=copy.deepcopy(good);witness=bad['maintenanceFdLifecycle'];value=witness['proof']
            if defect=='missing':del witness['fixtureSha256']
            elif defect=='extra':witness['raw']='synthetic-not-permitted'
            elif defect=='worker':witness['workerSha256']='0'*64
            elif defect=='before':witness['beforeWorkerSha256']='0'*64
            elif defect=='fixture':witness['fixtureSha256']='0'*64
            elif defect=='runtime':value['interpreter']['version']='24.0.0'
            elif defect=='uid':value['interpreter']['uid']=True
            elif defect=='gid':value['interpreter']['gid']=False
            elif defect=='root':value['interpreter']['uid']=0
            elif defect=='missingcase':value['cases'].pop()
            elif defect=='duplicatecase':value['cases'][1]['name']=value['cases'][0]['name']
            elif defect=='caseextra':value['cases'][0]['raw']='not-permitted'
            elif defect=='failedcase':value['cases'][0]['passed']=False
            elif defect=='boolcount':value['caseCount']=True
            elif defect=='baderrno':value['realFd']['oldClosedFstatErrno']=True
            elif defect=='unknowncode':value['realFd']['oldClosedFstatCode']='UNKNOWN'
            elif defect=='unclosed':value['realFd']['allOwnedDescriptorsClosed']=False
            elif defect=='unremoved':value['realFd']['allOwnedFilesRemoved']=False
            elif defect=='falsefs':value['scope']['actualFilesystem']=False
            elif defect=='fakepackageshidden':value['scope']['syntheticPackagePorts']=False
            elif defect=='candidate':value['scope']['candidatePackagesImported']=True
            elif defect=='sqlite':value['scope']['sqliteImported']=True
            elif defect=='database':value['scope']['databasesOpened']=True
            elif defect=='private':value['scope']['privateDataAccessed']=True
            elif defect=='maintenance':value['scope']['nativeMaintenanceProved']=True
            elif defect=='effect':value['deniedEffectAttempts']=1
            else:value['deniedEffectAttempts']=False
            with self.subTest(defect=defect),self.assertRaises(RuntimeError):entry.require_maintenance_fd_lifecycle(bad,rows)
        for container,keys in ((good['maintenanceFdLifecycle']['proof']['realFd'],('readonlyNoFollowOpen','heldIdentityCheckedBeforeSingleClose','oldRunPhaseReproduced','fixedRunPhasePassed')),
                               (good['maintenanceFdLifecycle']['proof']['scope'],('ordinarySyntheticFilesOnly','actualRunPhase','syntheticDatabasePorts'))):
            for key in keys:
                old=container[key];container[key]=False
                with self.subTest(guard=key),self.assertRaises(RuntimeError):entry.require_maintenance_fd_lifecycle(good,rows)
                container[key]=old

    def test_fd_source_closure_copies_only_three_exact_readable_files_and_rejects_substitution(self):
        proof=load('fd_copy_source_test',SOURCE/'metadata/linux_proof.py')
        self.assertEqual(proof.FD_SOURCE_LEAVES,('native-copy-worker.mjs','native-copy-worker-before.mjs','test-held-fd-linux.mjs'))
        rows=[{'path':name,'bytes':(SOURCE/'metadata'/name).stat().st_size,
          'sha256':hashlib.sha256((SOURCE/'metadata'/name).read_bytes()).hexdigest()}for name in proof.FD_SOURCE_LEAVES]
        with tempfile.TemporaryDirectory()as raw:
            root=Path(raw).resolve();work=root/'work';work.mkdir(mode=0o755)
            copied=proof.copy_fd_sources(SOURCE/'metadata',work,{'files':rows})
            self.assertEqual(copied,work/'fd-programs');self.assertEqual(stat.S_IMODE(copied.stat().st_mode),0o755)
            self.assertEqual(sorted(x.name for x in copied.iterdir()),sorted(proof.FD_SOURCE_LEAVES))
            for row in rows:
                target=copied/row['path'];self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o444)
                self.assertEqual(target.read_bytes(),(SOURCE/'metadata'/row['path']).read_bytes());self.assertEqual(target.stat().st_nlink,1)
            wrong=copy.deepcopy(rows);wrong[0]['sha256']='0'*64
            another=root/'another';another.mkdir(mode=0o755)
            with self.assertRaises(RuntimeError):proof.copy_fd_sources(SOURCE/'metadata',another,{'files':wrong})
            self.assertFalse((another/'fd-programs'/rows[0]['path']).exists())
            with self.assertRaises(RuntimeError):proof.copy_fixed_sources(SOURCE/'metadata',work,{'files':rows},kind='caller-selected')
            fake=root/'fake';fake.mkdir();third=root/'third';third.mkdir(mode=0o755)
            for row in rows:(fake/row['path']).symlink_to(SOURCE/'metadata'/row['path'])
            with self.assertRaises(RuntimeError):proof.copy_fd_sources(fake,third,{'files':rows})
            self.assertFalse((third/'fd-programs'/rows[0]['path']).exists())


if __name__=='__main__':unittest.main()

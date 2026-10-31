"""Pure command, archive-authentication and uncertain-closeout regressions."""
import hashlib
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


if __name__=='__main__':unittest.main()

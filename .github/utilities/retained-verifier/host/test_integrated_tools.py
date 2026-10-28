"""Actual catalog owner/alias joins on inert fixed tool metadata only."""
import unittest
import json
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import build_entry
import build_recipe
import host_context
import integrated_fixture as fixture


class ToolOps:
    def __init__(self, spec):
        self.spec=spec;self.changed_alias=False;self.wrong_owner=False;self.changed_after_read=False
        self.read=False
    def stat_original(self,path):
        return {'sourcePath':self.spec['path'],'type':'regular','dev':1,
            'ino':7 if (self.changed_alias and path!=self.spec['path']) or
                       (self.changed_after_read and self.read) else 2,
            'size':4,'uid':0,'gid':0,'mode':0o755,'mtimeNs':1,'ctimeNs':1,
            'aliasProofSha256':('a' if path==self.spec['path'] else 'b')*64}
    def read_original(self,path,cap):
        self.read=True;return {'bytes':b'tool'}
    def run(self,argv,timeout):
        owner='wrong' if self.wrong_owner else self.spec['package']
        return {'exitCode':0,'timedOut':False,'captureComplete':True,'ownedChildExited':True,
            'ownershipRetained':False,'stdout':(owner+': '+argv[-1]+'\n').encode(),'stderr':b''}


class IntegratedToolTests(unittest.TestCase):
    def test_authenticated_entry_source_is_the_exact_retained_public_source(self):
        root=Path(__file__).resolve().parents[1]
        raw=(root/'native/static_entry.c').read_bytes()
        self.assertEqual(len(raw),11765)
        self.assertEqual(build_entry.sha(raw),'29aa405e68a011d81dbf94d4aaf7e39899f62144eaaca6cceac884f183e335fe')
        build_entry.retained_helper_source(raw)
        self.assertIn(b'#define REFUSE(label) stop("entry_refused_" label',raw)
        self.assertNotIn(b'printf(',raw)
    def test_helper_source_pin_precedes_the_only_compile_and_fixed_result_pin_precedes_return(self):
        root=Path(__file__).resolve().parents[1];raw=(root/'native/static_entry.c').read_bytes();calls=[]
        helper={'path':'code/static-entry','sourceSha256':build_entry.RETAINED_HELPER_SOURCE_SHA256,
            'sha256':'0039f448059652d87fdfe49cf2de875a38bfe2224c2711c17cc2c837f9c7c88a','bytes':17888,
            'elf':{'sha256':'0039f448059652d87fdfe49cf2de875a38bfe2224c2711c17cc2c837f9c7c88a','bytes':17888}}
        runtime=SimpleNamespace(build_helper=lambda source,digest,toolchain,ops:(calls.append((source,digest))or helper))
        with self.assertRaisesRegex(build_entry.Refusal,'build_entry.retained_helper_source_pin'):
            build_entry.build_retained_helper(runtime,raw+b'\n',{},None)
        self.assertEqual(calls,[])
        self.assertIs(build_entry.build_retained_helper(runtime,raw,{},None),helper)
        self.assertEqual(len(calls),1)
        for field,value in (('sha256','a'*64),('bytes',17889),('sourceSha256','a'*64)):
            changed={**helper,field:value}
            with self.subTest(field=field),self.assertRaisesRegex(build_entry.Refusal,'build_entry.retained_helper_result_pin'):
                build_entry.retained_helper_result(changed)
        with self.assertRaises(build_entry.Refusal):build_entry.retained_helper_result({**helper,'elf':{'sha256':'a'*64,'bytes':17888}})
    def row(self,role,*,registered=None,defect=None):
        spec=fixture.EXTRA_TOOL_SPECS[role];ops=ToolOps(spec)
        if defect:setattr(ops,defect,True)
        name=spec['package'];version='1.0-1';path=registered or spec['packagePath']
        show={name:{'binaryName':name,'version':version,'architecture':'amd64'}}
        lists={name:{path}};indexed={(name,version,'amd64'):{'sha256':'d'*64}};aliases=[]
        result=build_entry.tool_row(role,spec['path'],ops,None,show,lists,indexed,aliases)
        return result,aliases

    def test_each_fixed_storage_tool_and_git_joins_registered_owner_signed_package(self):
        for role,spec in fixture.EXTRA_TOOL_SPECS.items():
            with self.subTest(role=role):
                result,aliases=self.row(role)
                self.assertEqual((result['role'],result['path'],result['package'],result['debSha256']),
                    (role,spec['path'],spec['package'],'d'*64))
                self.assertEqual(len(aliases),1)
                self.assertEqual(aliases[0]['packagePath'],spec['packagePath'])

    def test_direct_registered_paths_retain_owner_query_evidence(self):
        for role,spec in fixture.EXTRA_TOOL_SPECS.items():
            with self.subTest(role=role):
                _,aliases=self.row(role,registered=spec['path'])
                self.assertEqual(len(aliases),1)
                self.assertEqual(aliases[0]['packagePath'],spec['path'])

    def test_substituted_alias_or_wrong_owner_or_changed_tool_refuses(self):
        for role,spec in fixture.EXTRA_TOOL_SPECS.items():
            for defect in ('wrong_owner','changed_after_read'):
                with self.subTest(role=role,defect=defect),self.assertRaises(build_entry.Refusal):
                    self.row(role,defect=defect)
            if spec['packagePath']!=spec['path']:
                with self.subTest(role=role),self.assertRaises(build_entry.Refusal):
                    self.row(role,defect='changed_alias')

    def test_unlisted_tool_path_does_not_become_registered_alias(self):
        for role in fixture.EXTRA_TOOL_SPECS:
            with self.subTest(role=role),self.assertRaises(build_entry.Refusal):
                self.row(role,registered='/tmp/not-a-package-tool')

    def test_actual_native_command_gate_admits_only_fixed_extra_owner_aliases_after_metadata(self):
        ready=SimpleNamespace(metadata_ready=True);unverified=SimpleNamespace(metadata_ready=False)
        for path in ('/bin/mount','/bin/umount','/bin/findmnt','/sbin/blkid'):
            argv=('/usr/bin/dpkg-query','--search',path)
            with self.subTest(path=path):
                self.assertEqual(build_entry.NativeBuildOps._command_cap(ready,argv),(8192,8192))
                with self.assertRaisesRegex(build_entry.Refusal,'build_entry.metadata_not_verified'):
                    build_entry.NativeBuildOps._command_cap(unverified,argv)

    def test_actual_native_command_gate_refuses_nearby_or_unrelated_owner_paths(self):
        ready=SimpleNamespace(metadata_ready=True)
        for path in ('/bin/sh','/sbin/init','/bin/mount/child','/bin//mount','/sbin/blkid.extra',
                     '/bin/../usr/bin/mount','/sbin/../usr/sbin/blkid','/bin/findmnt-bad'):
            with self.subTest(path=path),self.assertRaisesRegex(build_entry.Refusal,'build_entry.owner_arg'):
                build_entry.NativeBuildOps._command_cap(ready,('/usr/bin/dpkg-query','--search',path))

    def test_actual_host_project_derivation_joins_both_real_fixture_factories(self):
        root=Path(__file__).resolve().parents[1]
        rows={row['path']:row for row in json.loads((root/'PUBLIC-SOURCE-MANIFEST.json').read_bytes())['files']}
        mission='e'*32
        # Only the already separately tested sticky-/tmp OS observation is
        # substituted. Source loading and native permit's actual path factory
        # are the real functions; no permit/native process is issued here.
        with mock.patch.object(host_context,'_public_project_root',return_value=Path('/tmp')):
            project=host_context._public_project_path(root,rows,mission)
        self.assertEqual(str(project),fixture.project_path(mission))
        image=fixture.image_argv(str(project/'integrated-seed'),str(project/'out/integrated-test.raw'))
        self.assertEqual(image[-2],str(project/'out/integrated-test.raw'))
        directory=str(project/'out');image_path=directory+'/ocv-test.raw'
        records={name:{'bytes':2*1024**3 if name=='ocv-test.raw' else 100,
            'sha256':'a'*64,'regular':True,'uid':0,'gid':0,'mode':0o444} for name in build_recipe.OUTPUT_FILES}
        table={'partitiontable':{'label':'gpt','device':image_path,'unit':'sectors','sectorsize':512,
            'partitions':[{'node':image_path+'1','start':2048,'size':4000000,'type':build_recipe.ROOT_TYPE,
                           'uuid':'11111111-2222-4333-8444-555555555555'}]}}
        run={'repository':host_context.REPOSITORY,'workflowRef':host_context.WORKFLOW_REF,
             'sourceCommit':'b'*40,'runId':'1','runAttempt':'1'}
        bound=build_recipe.bind_qemu_inputs(directory,records,build_recipe.canonical(table),source_sha256='a'*64,
            build_sha256='c'*64,kernel_version='6.1.0-50-amd64',run_identity=run)
        base=build_recipe.qemu_argv(bound,mission)
        argv=fixture.qemu_argv(base,directory=directory,
            test_record={'name':fixture.TEST_IMAGE_NAME,'bytes':fixture.TEST_IMAGE_BYTES,'sha256':'d'*64})
        self.assertEqual(argv.count('-drive'),2)
        self.assertTrue(any('file='+str(project/'out/integrated-test.raw') in item for item in argv))
        self.assertIn('_public_project_path',host_context.make_native_permit.__code__.co_names)
        self.assertEqual(host_context._ISSUED,{})

    def test_real_project_session_grammar_refuses_wrong_prefix_identity_or_child_path(self):
        for mission in ('e'*31,'E'*32,'e'*33,'../escape',True):
            with self.subTest(mission=mission),self.assertRaises(fixture.Refusal):fixture.project_path(mission)
        project=fixture.project_path('e'*32)
        for path in ('/tmp/ocv-host-'+'e'*32,'/tmp/ocv-'+'E'*32,project+'/child',project+'/../other',
                     '/private'+project,project.replace('/tmp/','/tmp//')):
            with self.subTest(path=path),self.assertRaises(fixture.Refusal):
                fixture.image_argv(path+'/integrated-seed',path+'/out/integrated-test.raw')
        with self.assertRaises(fixture.Refusal):
            fixture.image_argv(project+'/integrated-seed',fixture.project_path('f'*32)+'/out/integrated-test.raw')


if __name__=='__main__':unittest.main()

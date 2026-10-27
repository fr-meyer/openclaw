"""Pure injected contract tests. No command/compiler/mount or Linux execution."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

p = Path(__file__).with_name('build_recipe.py')
spec = importlib.util.spec_from_file_location('build_recipe', p)
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
H = 'a'*64
WORKFLOW = 'fr-meyer/openclaw/.github/workflows/authorized-beta-focused-validation.yml@refs/heads/retained-verifier-prerequisites'
IDENTITY = {'repository':'fr-meyer/openclaw','workflowRef':WORKFLOW,'sourceCommit':'b'*40,'runId':'1','runAttempt':'1'}
KV = '6.1.0-39-amd64'


def roots():
    return [{'name':n,'version':b.SYSTEMD_VERSION if n in ('systemd','systemd-sysv','libsystemd-shared','libsystemd0') else '1',
             'sha256':H} for n in sorted(b.REQUIRED_PACKAGES | {'linux-image-'+KV})]


def table():
    return {'partitiontable':{'label':'gpt','device':'/out/ocv-test.raw','unit':'sectors','sectorsize':512,
        'partitions':[{'node':'/out/ocv-test.raw1','start':2048,'size':4000000,'type':b.ROOT_TYPE,
                       'uuid':'11111111-2222-4333-8444-555555555555'}]}}


def artifacts():
    return {n:{'bytes':2*1024**3 if n=='ocv-test.raw' else 100,'sha256':H,'regular':True,
               'uid':0,'gid':0,'mode':0o444} for n in b.OUTPUT_FILES}


def binding():
    return b.bind_qemu_inputs('/out', artifacts(), b.canonical(table()), source_sha256=H,
                             build_sha256='c'*64,kernel_version=KV,run_identity=IDENTITY)


class FakeOps:
    def __init__(self):
        self.files={}
        self.calls=[]
        self.fail=False
        for n in ('runtime','tools','imports','apt'):
            self.files[b.CONTROL_ROOT+'/'+n+'.json']=(b'{"fixture":true}',0o444)
        self.files[b.SOURCE_ROOT+'/PUBLIC-SOURCE-MANIFEST.json']=(b'{"files":[]}',0o444)
        self.files[b.SOURCE_ROOT+'/native/static_entry.c']=(b'public source',0o444)
        self.files['/boot/vmlinuz-'+KV]=(b'public kernel',0o644)
        self.files[b.CONTROL_ROOT+'/static-entry']=(b'public fake ELF, never executable',0o555)
    def facts(self,p):
        if p not in self.files: raise FileNotFoundError(p)
        raw,mode=self.files[p]
        return {'regular':True,'uid':0,'gid':0,'mode':mode,'bytes':len(raw)}
    def read(self,p,cap):
        raw=self.files[p][0]
        if len(raw)>cap: raise ValueError('cap')
        return raw
    def run(self,argv,timeout):
        self.calls.append((argv,timeout))
        if not self.fail:self.files['/boot/initrd.img-'+KV]=(b'public initrd',0o600)
        return {'exitCode':0,'timedOut':self.fail,'captureComplete':not self.fail,'ownedChildExited':True,
                'ownershipRetained':False,'stdout':b'','stderr':b''}
    def write_once(self,p,raw,mode):
        if p in self.files:raise FileExistsError(p)
        self.files[p]=(raw,mode)
    def chmod(self,p,mode):self.files[p]=(self.files[p][0],mode)


def context(ops):
    return {'schema':'ocv-build-chroot-v1','sourceManifestSha256':b.sha(ops.files[b.SOURCE_ROOT+'/PUBLIC-SOURCE-MANIFEST.json'][0]),
            'buildContextSha256':H,'staticEntrySha256':b.sha(b'public source'),'runIdentity':IDENTITY.copy(),
            'kernel':{'package':'linux-image-'+KV,'version':'1','kernelVersion':KV,'path':'/boot/vmlinuz-'+KV,
                      'sha256':b.sha(b'public kernel'),'bytes':len(b'public kernel')},
            'controlHashes':{n:b.sha(ops.files[b.CONTROL_ROOT+'/'+n+'.json'][0]) for n in ('runtime','tools','imports','apt')},
            'outputDirectory':'/work/out'}


def compiler(ctx,ops):
    # Revalidate an already-compiled cached helper; never compile in these tests.
    raw=ops.read(b.CONTROL_ROOT+'/static-entry',1024**2)
    return {'path':b.CONTROL_ROOT+'/static-entry','bytes':len(raw),'sha256':b.sha(raw)}


class RecipeTests(unittest.TestCase):
    def test_exact_build_only_recipe(self):
        f=b.recipe_files(roots(),source_manifest_sha256=H,build_entry_sha256='c'*64,build_stage_context_sha256='e'*64)
        s=f['mkosi.conf'][0].decode()
        self.assertIn('Bootable=no\nBootloader=none',s)
        self.assertIn('PackageManagerTrees=pkgmngr',s)
        self.assertNotIn('LocalMirror',s)
        self.assertNotIn('Check-Valid-Until',s)
        self.assertIn("host/build_entry.py",f['mkosi.postinst.chroot'][0].decode())
        self.assertEqual(b.mkosi_argv('/project'),('/usr/bin/mkosi','--directory=/project','build'))
        self.assertEqual(len(b.recipe_symlinks()),1)
        self.assertIn('CacheDirectory=cache',s)
        shim=f['mkosi.postinst.chroot'][0].decode()
        self.assertTrue(shim.startswith('#!/bin/sh\nexec /usr/bin/python3.11 -I -S -B -'))
        self.assertIn('EXPECTED_CONTEXT = '+repr('e'*64),shim)
        self.assertIn('build_context_changed',shim)
        self.assertIn("scope['invoke'](EXPECTED_MANIFEST,EXPECTED_CONTEXT)",shim)
        unit=f['extra/etc/systemd/system/ocv-ci-proof.service'][0].decode()
        self.assertIn('Conflicts=serial-getty@ttyS0.service',unit)
        self.assertIn('Before=serial-getty@ttyS0.service',unit)
        self.assertFalse(any('serial-getty' in k for k in b.recipe_symlinks()))
    def test_literal_context_hash_required(self):
        with self.assertRaises(b.Refusal):b.recipe_files(roots(),source_manifest_sha256=H,
            build_entry_sha256='c'*64,build_stage_context_sha256='bad')
    def test_package_missing_or_changed_systemd(self):
        for name in b.REQUIRED_PACKAGES:
            with self.assertRaises(b.Refusal): b.package_specs([x for x in roots() if x['name']!=name])
        r=roots();next(x for x in r if x['name']=='systemd')['version']='255'
        with self.assertRaises(b.Refusal):b.package_specs(r)
    def test_package_injection_duplicates_and_floating_kernel(self):
        for mutate in ('newline','duplicate','kernel'):
            r=roots()
            if mutate=='newline':r[0]['version']='1\nToolsTree=yes'
            if mutate=='duplicate':r.append(copy.deepcopy(r[0]))
            if mutate=='kernel':r[-1]['name']='linux-image-amd64'
            with self.assertRaises(b.Refusal):b.package_specs(r)
    def test_partition_bound_and_no_guessed_uuid(self):
        x=binding()
        self.assertEqual(x['rootPartition']['partuuid'],'11111111-2222-4333-8444-555555555555')
        self.assertEqual(x['rootPartition']['sfdiskSha256'],b.sha(b.canonical(table())))
    def test_partition_bad_roster_type_bounds(self):
        for variant in ('extra','type','path','uuid','range','sector'):
            t=table();r=t['partitiontable']['partitions'][0]
            if variant=='extra':t['partitiontable']['partitions'].append(copy.deepcopy(r))
            if variant=='type':r['type']='wrong'
            if variant=='path':t['partitiontable']['device']='/dev/sda'
            if variant=='uuid':r['uuid']='00000000-0000-0000-0000-000000000000'
            if variant=='range':r['size']=2**50
            if variant=='sector':t['partitiontable']['sectorsize']=True
            with self.assertRaises(b.Refusal):b.root_partition(b.canonical(t),'/out/ocv-test.raw',2*1024**3)
    def test_duplicate_json_rejects(self):
        with self.assertRaises(b.Refusal):b.unique_json(b'{"partitiontable":{},"partitiontable":{}}')
    def test_argv_closed_no_network_or_share(self):
        a=b.qemu_argv(binding(),'d'*32)
        self.assertEqual(a.count('-nic'),1)
        self.assertEqual(a[a.index('-nic')+1],'none')
        for v in ('-netdev','-net','-virtfs','-fsdev','-chardev','-daemonize','-enable-kvm'):
            self.assertNotIn(v,a)
        self.assertEqual(a[a.index('-accel')+1],'tcg')
        self.assertEqual(a[a.index('-monitor')+1],'none')
        self.assertIn('ocv.build='+'c'*64,a[-1])
        self.assertEqual(a.count('-snapshot'),1)
        self.assertNotIn('snapshot=off',a[a.index('-drive')+1])
        self.assertEqual(a[a.index('-drive')+1],'file=/out/ocv-test.raw,format=raw,if=virtio')
        self.assertNotIn('-blockdev',a)
    def test_path_and_session_injection(self):
        for p in ('/out,a','/out/../etc','/out\n','relative','/'):
            with self.assertRaises(b.Refusal):b.mkosi_argv(p)
        with self.assertRaises(b.Refusal):b.qemu_argv(binding(),'bad')
    def test_artifact_identity_and_caps(self):
        for field,value in (('uid',1),('uid',False),('regular',False),('mode',0o666),('bytes',b.MAX_IMAGE+1)):
            a=artifacts();a['ocv-test.raw'][field]=value
            with self.assertRaises(b.Refusal):b.bind_qemu_inputs('/out',a,b.canonical(table()),source_sha256=H,
                       build_sha256='c'*64,kernel_version=KV,run_identity=IDENTITY)
    def test_qemu_rechecks_closed_partition_and_artifacts(self):
        for field,value in (('partuuid','bad'),('sectorBytes',True),('type','wrong')):
            v=binding();v['rootPartition'][field]=value
            with self.assertRaises(b.Refusal):b.qemu_argv(v,'d'*32)
        v=binding();v['artifacts']['kernel.bin']['bytes']=True
        with self.assertRaises(b.Refusal):b.qemu_argv(v,'d'*32)
    def test_publication_identity_pinned(self):
        ident=IDENTITY.copy();ident['workflowRef']=WORKFLOW.replace('retained-verifier-prerequisites','main')
        with self.assertRaises(b.Refusal):b.bind_qemu_inputs('/out',artifacts(),b.canonical(table()),source_sha256=H,
                       build_sha256='c'*64,kernel_version=KV,run_identity=ident)
    def test_run_identity_canonical_digit_strings_only(self):
        for key,value in (('runId',1),('runId','01'),('runId',True),('runId','+1'),('runAttempt',1),('runAttempt','2')):
            ident=IDENTITY.copy();ident[key]=value
            with self.assertRaises(b.Refusal):b.bind_qemu_inputs('/out',artifacts(),b.canonical(table()),source_sha256=H,
                build_sha256='c'*64,kernel_version=KV,run_identity=ident)
    def test_postinstall_one_initrd_and_write_build_last(self):
        ops=FakeOps();result=b.run_postinstall(context(ops),ops,compiler)
        self.assertEqual(ops.calls,[(('/usr/sbin/update-initramfs','-c','-k',KV),300)])
        self.assertEqual(result['schema'],'ocv-build-stage-result-v1')
        control=json.loads(ops.files[b.CONTROL_ROOT+'/build.json'][0])
        self.assertFalse(control['candidateImage']);self.assertTrue(control['fixtureOnly'])
        self.assertEqual(control['systemdVersion'],b.SYSTEMD_VERSION)
        self.assertEqual(b.sha(ops.files[b.CONTROL_ROOT+'/build.json'][0]),result['buildControlSha256'])
    def test_failure_no_control_and_no_retry(self):
        ops=FakeOps();ops.fail=True
        with self.assertRaises(b.Refusal):b.run_postinstall(context(ops),ops,compiler)
        self.assertEqual(len(ops.calls),1)
        self.assertNotIn(b.CONTROL_ROOT+'/build.json',ops.files)
    def test_missing_cached_helper_never_calls_compile_again(self):
        ops=FakeOps();del ops.files[b.CONTROL_ROOT+'/static-entry']
        def forbidden(*_):self.fail('must not recompile')
        with self.assertRaises(FileNotFoundError):b.run_postinstall(context(ops),ops,forbidden)
        self.assertEqual(ops.calls,[])
    def test_mismatch_prevents_compiler_and_initrd(self):
        ops=FakeOps();c=context(ops);c['controlHashes']['apt']='f'*64
        def forbidden(*_):self.fail('compiler called')
        with self.assertRaises(b.Refusal):b.run_postinstall(c,ops,forbidden)
        self.assertEqual(ops.calls,[])
    def test_existing_safe_initrd_updates_once(self):
        ops=FakeOps();ops.files['/boot/initrd.img-'+KV]=(b'old',0o600)
        result=b.run_postinstall(context(ops),ops,compiler)
        self.assertEqual(result['initrdAction'],'-u')
        self.assertEqual(ops.calls,[(('/usr/sbin/update-initramfs','-u','-k',KV),300)])
    def test_existing_unsafe_initrd_refuses(self):
        ops=FakeOps();ops.files['/boot/initrd.img-'+KV]=(b'old',0o666)
        with self.assertRaises(b.Refusal):b.run_postinstall(context(ops),ops,compiler)
        self.assertEqual(ops.calls,[])
    def test_source_not_immutable_refuses(self):
        ops=FakeOps();ops.files[b.SOURCE_ROOT+'/native/static_entry.c']=(b'public source',0o644)
        with self.assertRaises(b.Refusal):b.run_postinstall(context(ops),ops,compiler)
        self.assertEqual(ops.calls,[])


if __name__=='__main__': unittest.main()

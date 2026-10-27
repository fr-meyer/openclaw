"""Actual host/bootstrap derivations on public synthetic files; no native IO.

The injected command records are fixtures, not GPG/compiler/Linux evidence.
No native constructor, ARM patch, subprocess, mount, socket or cloud call runs.
"""
import copy
from contextlib import redirect_stderr
from dataclasses import replace
import datetime as dt
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

HERE=Path(__file__).resolve().parent
A=HERE.parent
B=next(p for p in (A/'bootstrap-r3',A/'bootstrap-r2',A/'bootstrap') if p.is_dir())
for p in (A/'build',A/'runtime',A/'consumer',B):sys.path.insert(0,str(p))
import source_expectation as m
import test_bootstrap as fixture
import guard
import issuer
import ci_profile as profile
import ci_archive_policy
import ci_metadata
import build_entry
import build_recipe
import package_inventory
import runtime_prepare


def prepared():
    io,program=fixture.setup_io()
    plan=guard.verify(io)
    data=issuer.prepare(plan,io,program)
    manifest,context=issuer.plan_native_job(plan,data,program,io.utc())
    bound={'sourceManifestSha256':plan.markers['ocv.source'],'buildControlSha256':plan.markers['ocv.build'],
           'runIdentity':copy.deepcopy(plan.build['runIdentity'])}
    return io,program,plan,data,manifest,context,bound


class SourceExpectationTests(unittest.TestCase):
    def setUp(self):self.io,self.program,self.plan,self.prep,self.native,self.context,self.bound=prepared()
    def derive(self,source=None,runtime=None,build=None,bound=None):
        return m.derive(self.plan.source if source is None else source,
          self.plan.controls['runtime'] if runtime is None else runtime,
          self.plan.build if build is None else build,self.bound if bound is None else bound,
          self.context['sessionId'],profile)
    def test_actual_issuer_and_host_derive_identical_code_context_and_consumer_pins(self):
        result=self.derive()
        self.assertEqual(result['code'],self.native['code'])
        for name,value in self.native['code'].items():self.assertEqual(value,self.context[name])
        self.assertEqual(result['profileSha256'],self.context['profileSha256'])
        self.assertEqual(result['code']['runtimeManifestSha256'],m.sha(m.canonical(self.native['files'])))
        self.assertNotEqual(result['code']['runtimeManifestSha256'],self.plan.build['runtimeManifestSha256'])
        self.assertEqual(set(result['code']['consumerCode']),{'ci_fixture.py','native_cases.py','hosted_export.py',
          'hosted_privacy.py','public-member-comparisons-v105-workboard.json'})
        self.assertFalse(self.plan.native_authority)
        with self.assertRaises(guard.Refusal):issuer.issue_native(self.plan,self.io,self.prep)
    def test_source_and_runtime_order_do_not_change_sorted_staging_hash(self):
        source=copy.deepcopy(self.plan.source);source['files'].reverse()
        runtime=copy.deepcopy(self.plan.controls['runtime']);runtime['files'].reverse()
        self.assertEqual(self.derive(),self.derive(source,runtime))
    def test_duplicate_rows_wrong_shape_missing_source_or_colliding_runtime_refuse(self):
        source=copy.deepcopy(self.plan.source);source['files'].append(source['files'][0])
        with self.assertRaises(m.Refusal):self.derive(source=source)
        source=copy.deepcopy(self.plan.source);source['files']=[r for r in source['files']if r['path']!='bootstrap/worker_entry.py']
        with self.assertRaises(KeyError):self.derive(source=source)
        for change in ('extra','duplicate','reserved-code'):
            runtime=copy.deepcopy(self.plan.controls['runtime'])
            if change=='extra':runtime['files'][0]['unknown']='not accepted'
            elif change=='duplicate':runtime['files'].append(copy.deepcopy(runtime['files'][0]))
            else:runtime['files'][0]['path']='code/static-entry'
            with self.subTest(change=change),self.assertRaises(m.Refusal):self.derive(runtime=runtime)
    def test_helper_profile_source_and_run_bindings_refuse_changed_expected_values(self):
        runtime=copy.deepcopy(self.plan.controls['runtime']);runtime['helper']['sha256']='0'*64
        with self.assertRaises(m.Refusal):self.derive(runtime=runtime)
        source=copy.deepcopy(self.plan.source)
        next(r for r in source['files']if r['path']=='native/CI-PROFILE.json')['sha256']='0'*64
        with self.assertRaises(m.Refusal):self.derive(source=source)
        for field in ('sourceManifestSha256','runIdentity'):
            bound=copy.deepcopy(self.bound)
            bound[field]='0'*64 if field=='sourceManifestSha256' else {**bound[field],'runId':'2'}
            with self.subTest(field=field),self.assertRaises(m.Refusal):self.derive(bound=bound)
    def test_changed_runtime_hash_is_bound_not_silently_replaced_by_wrapper_hash(self):
        runtime=copy.deepcopy(self.plan.controls['runtime']);runtime['files'][0]['sha256']='0'*64
        changed=self.derive(runtime=runtime)
        self.assertNotEqual(changed['code']['runtimeManifestSha256'],self.native['code']['runtimeManifestSha256'])
        self.assertEqual(changed['code']['workerSha256'],self.native['code']['workerSha256'])
        # The pure derivation consumes already-admitted manifests. The actual
        # guest byte check independently rejects this mismatching file hash.
        plan=replace(self.plan,controls={**self.plan.controls,'runtime':runtime})
        with self.assertRaises(guard.Refusal):issuer.prepare(plan,self.io,self.program)
    def test_expected_wrapper_reads_only_synthetic_artifacts_and_exact_properties(self):
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp).resolve();source=root/'source';out=root/'out';(source/'native').mkdir(parents=True);out.mkdir()
            (source/'PUBLIC-SOURCE-MANIFEST.json').write_bytes(m.canonical(self.plan.source))
            (source/'native/CI-PROFILE.json').write_bytes((fixture.N/'CI-PROFILE.json').read_bytes())
            (out/'runtime.json').write_bytes(self.io.files[guard.CONTROL+'/runtime.json'])
            (out/'build.json').write_bytes(self.io.files[guard.CONTROL+'/build.json'])
            result=m.expected(source,out,self.bound,self.context['sessionId'])
            props=profile.properties((source/'native/CI-PROFILE.json').read_bytes(),self.context['sessionId'],
                                     '/var/lib/ci-verifier/'+self.context['sessionId'])
            self.assertEqual(result,{**self.derive(),'propertiesSha256':m.sha(m.canonical(props))})
            (out/'runtime.json').write_bytes((out/'runtime.json').read_bytes()+b' ')
            with self.assertRaisesRegex(m.Refusal,'expect.runtime_control'):m.expected(source,out,self.bound,self.context['sessionId'])
    def test_expected_wrapper_rechecks_source_and_build_raw_bytes_against_bound_hashes(self):
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp).resolve();source=root/'source';out=root/'out';(source/'native').mkdir(parents=True);out.mkdir()
            paths={source/'PUBLIC-SOURCE-MANIFEST.json':m.canonical(self.plan.source),
              source/'native/CI-PROFILE.json':(fixture.N/'CI-PROFILE.json').read_bytes(),
              out/'runtime.json':self.io.files[guard.CONTROL+'/runtime.json'],
              out/'build.json':self.io.files[guard.CONTROL+'/build.json']}
            for path,raw in paths.items():path.write_bytes(raw)
            for path in (source/'PUBLIC-SOURCE-MANIFEST.json',out/'build.json'):
                with self.subTest(role=path.name):
                    path.write_bytes(paths[path]+b' ')
                    with self.assertRaises(m.Refusal):m.expected(source,out,self.bound,self.context['sessionId'])
                    path.write_bytes(paths[path])


class BuildFixture:
    """Concrete run_checked boundary, all command effects are finite fakes."""
    def __init__(self):
        self.io,self.program=fixture.setup_io();self.calls=[];self.kv='6.1.0-39-amd64'
        self.io.values['kernelVersion']=self.kv
        names=sorted(set(self.io.packages)|set(build_recipe.REQUIRED_PACKAGES)|{'dash','dpkg','linux-image-'+self.kv})
        self.packages={name:{'name':name,'version':build_recipe.SYSTEMD_VERSION if name.startswith(('systemd','libsystemd'))else'1',
          'architecture':'amd64','debSha256':m.sha(('synthetic archive '+name).encode())}for name in names}
        self.data={p:raw for p,raw in self.io.files.items()if p.startswith(('/usr/','/lib/','/lib64/'))}
        for path in (*build_entry.COMPILER.values(),*build_entry.TOOLS.values()):self.data.setdefault(path,('synthetic tool '+path).encode())
        self.data[runtime_prepare.LOADER]=self.data['/usr/lib/ld-linux-x86-64.so.2']
        self.data['/lib/x86_64-linux-gnu/libc.so.6']=b'public synthetic libc'
        self.data['/boot/vmlinuz-'+self.kv]=b'public synthetic kernel'
        self.owners={p:'gcc-12'if p in build_entry.COMPILER.values()else'python3.11-minimal'if p==runtime_prepare.PYTHON else
          'libpython3.11-minimal'if p.endswith('encodings/__init__.py')else'libpython3.11-stdlib'if p.startswith(runtime_prepare.STDLIB)else
          'systemd'if p in ('/usr/lib/systemd/systemd','/usr/bin/busctl','/usr/bin/systemctl','/usr/bin/systemd-run')else
          'gpgv'if p=='/usr/bin/gpgv'else'dpkg'if p=='/usr/bin/dpkg-query'else'selinux-utils'if p=='/usr/sbin/selinuxenabled'else
          'linux-image-'+self.kv if p.startswith('/boot/')else'libc6'for p in self.data}
        self.show=''.join(n+'\t'+r['version']+'\tamd64\tinstalled\n'for n,r in self.packages.items()).encode()
        self.lists={n:('\n'.join(['/.','/usr']+sorted(p for p,owner in self.owners.items()if owner==n))+'\n').encode()for n in names}
        # Exact pinned Bookworm systemd package paths; the execution path is
        # reached through Debian's merged-/usr aliases.
        self.lists['systemd']=self.lists['systemd'].replace(b'/usr/bin/systemctl\n',b'/bin/systemctl\n').replace(
          b'/usr/lib/systemd/systemd\n',b'/lib/systemd/systemd\n')
        self.lists['dash']+=(b'/bin/dash\n/bin/sh\npackage diverts others to: /bin/sh.distrib\n'
                            b'/usr/share/man/man1/sh.1.gz\n'
                            b'package diverts others to: /usr/share/man/man1/sh.distrib.1.gz\n')
        self.owners['/bin/systemctl']='systemd';self.owners['/lib/systemd/systemd']='systemd'
        self.index=''.join('Package: '+n+'\nVersion: '+r['version']+'\nArchitecture: amd64\nFilename: pool/main/f/fixture/'+n+'_1_amd64.deb\nSize: 12\nSHA256: '+r['debSha256']+'\n\n'for n,r in self.packages.items()).encode()
        release=('-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nOrigin: Debian\nCodename: bookworm\nVersion: fixture\nDate: Fri, 01 Jan 2010 00:00:00 UTC\nSHA256:\n '+m.sha(self.index)+' '+str(len(self.index))+' main/binary-amd64/Packages\n-----BEGIN PGP SIGNATURE-----\nsynthetic\n-----END PGP SIGNATURE-----\n').encode()
        self.io.put(build_entry.DATA+'/Packages',self.index);self.io.put(build_entry.DATA+'/InRelease',release)
        policy=ci_archive_policy.Fixture(m.sha(release),len(release),m.sha(self.index),len(self.index),
          'Fri, 01 Jan 2010 00:00:00 UTC','fixture',frozenset(['AB'*20]))
        class SyntheticAdmission(ci_metadata.Admission):
            def run(self):return self._run_literal_policy(policy)
        self.program.metadata=SimpleNamespace(Admission=SyntheticAdmission)
        self.signature={'schema':'synthetic-signature-input-only','actualCryptographyPerformed':False}
        self.header={'packageRoots':[{'name':n,'version':self.packages[n]['version'],'sha256':self.packages[n]['debSha256']}for n in sorted(build_recipe.REQUIRED_PACKAGES|{'linux-image-'+self.kv})],
          'kernelPackage':{'name':'linux-image-'+self.kv,'version':'1'},'keyringSha256':m.sha(self.io.files[build_entry.DATA+'/keyring.gpg']),
          'runIdentity':{'repository':'fr-meyer/openclaw','workflowRef':build_entry.WORKFLOW,'sourceCommit':'a'*40,'runId':'1','runAttempt':'1'}}
        self.source_sha=m.sha(self.io.files[guard.SOURCE+'/PUBLIC-SOURCE-MANIFEST.json'])
        for name in ('runtime','tools','imports','apt','build'):self.io.files.pop(guard.CONTROL+'/'+name+'.json',None)
    def metadata_inputs(self):return {'Packages':self.index}, {'firstStageLedgerSha256':'e'*64}, self.signature
    def now(self):return dt.datetime(2030,1,1,tzinfo=dt.timezone.utc)
    def read(self,path,cap):
        raw=self.io.files.get(path,self.data.get(path))
        if raw is None:raise FileNotFoundError(path)
        assert len(raw)<=cap;return raw
    def read_original(self,path,cap):
        canonical={'/bin/systemctl':'/usr/bin/systemctl',
                   '/lib/systemd/systemd':'/usr/lib/systemd/systemd'}.get(path,path)
        raw=self.data.get(canonical,self.io.files.get(canonical));assert raw is not None and len(raw)<=cap
        return {'bytes':raw,'sourcePath':canonical,'uid':0,'gid':0,'mode':0o755,'regular':True,'symlinkChainSha256':'c'*64}
    def stat_original(self,path):
        view=self.read_original(path,64*1024**2)
        return {'sourcePath':view['sourcePath'],'type':'regular','dev':1,'ino':101,'size':len(view['bytes']),'uid':0,'gid':0,
          'mode':0o755,'nlink':1,'mtimeNs':1,'ctimeNs':1,'aliasProofSha256':'c'*64}
    def facts(self,path):
        raw=self.io.files.get(path,self.data.get(path))
        if raw is None:raise FileNotFoundError(path)
        return {'regular':True,'uid':0,'gid':0,'mode':self.io.modes.get(path,0o644),'bytes':len(raw)}
    def run(self,argv,timeout):
        self.calls.append(tuple(argv));raw=b''
        if argv[:2]==('/usr/bin/dpkg-query','--show'):raw=self.show
        elif argv[:2]==('/usr/bin/dpkg-query','--listfiles'):raw=self.lists[argv[2]]
        elif argv[:2]==('/usr/bin/dpkg-query','--search'):raw=(self.owners[argv[2]]+': '+argv[2]+'\n').encode()
        elif argv[0]=='/usr/bin/ldd':raw=b'libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x1000)\n/lib64/ld-linux-x86-64.so.2 (0x2000)\n'
        elif argv[0]=='/usr/bin/gcc-12':pass  # Existing synthetic ELF fixture only; no compilation.
        elif argv[0]=='/usr/sbin/update-initramfs':self.io.put('/boot/initrd.img-'+self.kv,b'public synthetic initrd',0o600)
        else:raise AssertionError('unexpected synthetic command')
        return {'exitCode':0,'timedOut':False,'captureComplete':True,'ownedChildExited':True,'ownershipRetained':False,'stdout':raw,'stderr':b''}
    def write_once(self,path,raw,mode):
        if path in self.io.files:raise FileExistsError(path)
        self.io.put(path,raw,mode)
    def chmod(self,path,mode):self.io.modes[path]=mode
    def write_runtime(self,path,raw,mode):self.io.put('/work/out/runtime-root/'+path,raw,mode)
    def platform_facts(self):return {'platform':'linux','machine':'x86_64','euid':0}
    def build(self):
        result=build_entry.run_checked(self,self.header,self.source_sha,'d'*64,
          {'recipe':build_recipe,'runtime':runtime_prepare,'inventory':package_inventory,'archive':None,'policy':None})
        self.io.files.update(self.data)
        for path in self.data:self.io.modes.setdefault(path,0o755)
        self.io.put('/var/lib/dpkg/status',b'\n\n'.join(('Package: '+n+'\nStatus: install ok installed\nVersion: '+r['version']+'\nArchitecture: amd64').encode()for n,r in self.packages.items())+b'\n')
        self.io.cmdline=('console=ttyS0 ocv.source='+self.source_sha+' ocv.build='+m.sha(self.io.files[guard.CONTROL+'/build.json'])+' ocv.session='+self.io.session).encode()
        return result


class BuildGuestJoinTests(unittest.TestCase):
    def test_actual_build_transaction_refuses_changed_dash_diversion(self):
        f=BuildFixture()
        f.lists['dash']=f.lists['dash'].replace(b'/usr/share/man/man1/sh.distrib.1.gz',
                                                b'/tmp/unknown.1.gz')
        with self.assertRaisesRegex(runtime_prepare.Refusal,'inventory.filelist_path'):f.build()

    def test_real_filelist_rejection_keeps_guard_and_reports_first_public_line(self):
        raw=(b'/.\n/usr\n/usr/bin/sh\n'
             b'package diverts others to: /usr/bin/sh.distrib\n')
        output=io.StringIO()
        with redirect_stderr(output):
            with self.assertRaises(runtime_prepare.Refusal) as error:
                build_entry.parse_installed_filelist(package_inventory,'dash',raw)
        self.assertEqual(error.exception.code,'inventory.filelist_path')
        evidence=json.loads(output.getvalue())
        self.assertEqual((evidence['schema'],evidence['binaryName'],evidence['lineIndex']),
                         ('ocv-dpkg-filelist-refusal-v1','dash',3))
        self.assertEqual(evidence['line'],'package diverts others to: /usr/bin/sh.distrib')
        output=io.StringIO()
        with redirect_stderr(output):
            self.assertEqual(build_entry.parse_installed_filelist(package_inventory,'dash',b'/.\n/usr/bin/sh\n'),
                             {'/usr/bin/sh'})
        self.assertEqual(output.getvalue(),'')
        exact=(b'/.\n/bin/dash\n/bin/sh\n'
               b'package diverts others to: /bin/sh.distrib\n'
               b'/usr/share/man/man1/sh.1.gz\n'
               b'package diverts others to: /usr/share/man/man1/sh.distrib.1.gz\n')
        with redirect_stderr(output):
            self.assertEqual(build_entry.parse_installed_filelist(package_inventory,'dash',exact),
                             {'/bin/dash','/bin/sh','/usr/share/man/man1/sh.1.gz'})
        self.assertEqual(output.getvalue(),'')

    def test_pinned_bookworm_systemctl_alias_refuses_missing_owner_or_substitution(self):
        for defect,reason in (('missing','build_entry.tool_filelist'),
                              ('owner','build_entry.tool_owner'),
                              ('substituted','build_entry.tool_alias_identity')):
            with self.subTest(defect=defect):
                f=BuildFixture()
                if defect=='missing':
                    f.lists['systemd']=f.lists['systemd'].replace(b'/bin/systemctl\n',b'')
                elif defect=='owner':
                    f.owners['/bin/systemctl']='other'
                else:
                    original=f.stat_original
                    def switched(path):
                        row=original(path)
                        return dict(row,ino=999) if path=='/bin/systemctl' else row
                    f.stat_original=switched
                with self.assertRaisesRegex(build_entry.Refusal,reason):f.build()
    def test_actual_build_transaction_output_is_accepted_by_actual_bootstrap_prepare(self):
        f=BuildFixture();f.build();plan=guard.verify(f.io);data=issuer.prepare(plan,f.io,f.program)
        runtime=plan.controls['runtime'];apt=plan.controls['apt']
        signature_hash=m.sha(m.canonical(f.signature))
        inventory=json.loads(f.io.files[guard.CONTROL+'/package-inventory.json'])
        self.assertEqual(apt['sourceProofSha256'],runtime['sourceProofSha256'])
        self.assertEqual(runtime['sourceProofSha256'],m.sha(m.canonical(inventory['inputBinding'])))
        self.assertEqual(inventory['inputBinding']['signatureProofSha256'],signature_hash)
        self.assertNotEqual(signature_hash,runtime['sourceProofSha256'])
        self.assertFalse(plan.native_authority)
        with self.assertRaises(guard.Refusal):issuer.issue_native(plan,f.io,data)
        old=copy.deepcopy(apt);old['sourceProofSha256']=signature_hash
        broken=replace(plan,controls={**plan.controls,'apt':old})
        with self.assertRaisesRegex(guard.Refusal,'boot.apt_binding'):issuer.prepare(broken,f.io,f.program)


if __name__=='__main__':unittest.main()

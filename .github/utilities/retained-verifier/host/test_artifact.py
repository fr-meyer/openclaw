import hashlib
import copy
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import sys
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'apt'))
import artifact as a


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.source=self.root/'source';self.out=self.root/'out'
        self.source.mkdir();self.out.mkdir();(self.out/'apt-data').mkdir();(self.out/'runtime/usr/bin').mkdir(parents=True)
        raw=b'generic public source\n';(self.source/'example.py').write_bytes(raw)
        self.rows={'example.py':{'path':'example.py','bytes':len(raw),'sha256':a.sha(raw),'mode':0o444}}
        self.manifest=a.canonical({'schema':'ocv-public-source-v1','files':list(self.rows.values())})
        runtime=b'public fake runtime bytes';(self.out/'runtime/usr/bin/python3.11').write_bytes(runtime)
        helper=b'public fake helper';(self.out/'static-entry').write_bytes(helper)
        controls={name:b'{}'for name in a.CONTROLS}
        controls['runtime.json']=a.canonical({'files':[{'path':'usr/bin/python3.11','sourcePath':'/usr/bin/python3.11',
          'bytes':len(runtime),'sha256':a.sha(runtime),'mode':0o555}]})
        controls['build.json']=a.canonical({'helperSha256':a.sha(helper),
          'aptMetadataManifestSha256':'a'*64})
        for name,raw in controls.items():(self.out/name).write_bytes(raw)
        for name in a.APT_FILES:(self.out/'apt-data'/name).write_bytes(b'public synthetic '+name.encode())
        (self.out/'repair').mkdir()
        # Explicit synthetic hash-reference seam: no real .deb is fetched or
        # installed locally. The actual CI must satisfy the production pin.
        self.assertEqual(a.REPAIR_PACKAGE_SHA256,'8357d8bfdbde73ff658129c1a6d25a02b4a244bddb2cc444c5a46835e3b8a31f')
        package_raw=(b'public synthetic offline selinux-utils package'*3000)[:126432]
        pin=patch.object(a,'REPAIR_PACKAGE_SHA256',a.sha(package_raw));pin.start();self.addCleanup(pin.stop)
        (self.out/'repair/selinux-utils.deb').write_bytes(package_raw)
        tool={'role':'selinuxenabled','path':'/usr/sbin/selinuxenabled','bytes':14576,'sha256':a.REPAIR_TOOL_SHA256}
        package={'name':'selinux-utils','version':'3.4-1+b6','architecture':'amd64',
          'bytes':len(package_raw),'sha256':a.sha(package_raw),
          'filename':'pool/main/libs/libselinux/selinux-utils_3.4-1+b6_amd64.deb','origin':'main',
          'packagesSha256':a.sha((self.out/'apt-data/Packages').read_bytes()),
          'inReleaseSha256':a.sha((self.out/'apt-data/InRelease').read_bytes()),
          'depends':'libc6 (>= 2.34), libselinux1 (>= 3.1~)'}
        package['depends']=a.REPAIR_PACKAGE_DEPENDS
        signed=('Package: selinux-utils\nVersion: 3.4-1+b6\nArchitecture: amd64\nFilename: '+package['filename']+'\nSHA256: '+package['sha256']+'\nSize: '+str(package['bytes'])+'\nDepends: '+package['depends']+'\n').encode()
        (self.out/'apt-data/Packages').write_bytes(signed);package['packagesSha256']=a.sha(signed)
        self.repair={'schema':a.REPAIR_SCHEMA,'fixtureOnly':True,
          'privateVmInstallationPerformed':False,'package':package,'tool':tool,
          'sourceManifestSha256':a.sha(self.manifest),'aptMetadataManifestSha256':'a'*64}
        (self.out/'repair/manifest.json').write_bytes(a.canonical(self.repair))
        (self.out/'tools.json').write_bytes(a.canonical({'schema':'ocv-tools-v1','tools':[
          dict(tool,package='selinux-utils',version='3.4-1+b6',debSha256=package['sha256'])]}))

        (self.out/'ocv-test.raw').write_bytes(b'NEVER_EXPORT_OS_IMAGE')
        (self.out/'unknown-secret').write_bytes(b'UNRELATED_FILE')
    def pack(self,maximum=1048576):
        dest=self.root/'public.tar.gz'
        result=a.package(self.source,self.out,dest,source_rows=self.rows,manifest_raw=self.manifest,maximum=maximum)
        return result,dest
    def test_only_explicit_regular_public_payloads_no_os_or_ambient_files(self):
        result,p=self.pack()
        with tarfile.open(p,'r:gz')as archive:
            names=archive.getnames();self.assertTrue(all(row.isfile()for row in archive.getmembers()))
            self.assertNotIn('ocv-test.raw',names);self.assertNotIn('unknown-secret',names)
            self.assertIn('runtime/usr/bin/python3.11',names)
            self.assertIn('repair/selinux-utils.deb',names);self.assertIn('repair/manifest.json',names)
            for name in a.APT_FILES:self.assertIn('control/apt-data/'+name,names)
            manifest=json.loads(archive.extractfile('PUBLIC-TOOLING-MANIFEST.json').read())
            self.assertTrue(manifest['fixtureOnly']);self.assertFalse(manifest['candidateImage'])
            for row in manifest['files']:
                raw=archive.extractfile(row['path']).read();self.assertEqual(a.sha(raw),row['sha256'])
        self.assertFalse(result['OSImageIncluded']);self.assertLess(result['bytes'],1048576)
    def test_compressed_limit_refuses_and_never_claims_package(self):
        with self.assertRaisesRegex(a.Refusal,'compressed_cap'):self.pack(10)
    def test_changed_runtime_source_or_helper_fails(self):
        (self.out/'runtime/usr/bin/python3.11').write_bytes(b'changed')
        with self.assertRaisesRegex(a.Refusal,'runtime_hash'):self.pack()
    def test_symlink_payload_refuses(self):
        p=self.out/'static-entry';p.unlink();p.symlink_to(self.out/'unknown-secret')
        with self.assertRaisesRegex(a.Refusal,'artifact.path'):self.pack()
    def test_output_not_overwritten(self):
        _,p=self.pack();before=p.read_bytes()
        with self.assertRaisesRegex(a.Refusal,'destination'):self.pack()
        self.assertEqual(before,p.read_bytes())
    def test_paths_cannot_escape_archive_namespace(self):
        for name in ('../x','/x','a/../x',''):
            with self.assertRaises(a.Refusal):a.safe_name(name)

    def test_repair_manifest_payload_and_catalog_substitutions_refuse(self):
        original=(self.out/'repair/manifest.json').read_bytes()
        cases=[lambda v:v.update(privateVmInstallationPerformed=True),
          lambda v:v['package'].update(name='arbitrary-package'),
          lambda v:v['package'].update(version='3.4-1+b7'),
          lambda v:v['package'].update(architecture='arm64'),
          lambda v:v['package'].update(origin='security'),
          lambda v:v['package'].update(filename='../selinux-utils.deb'),
          lambda v:v['package'].update(packagesSha256='0'*64),
          lambda v:v['package'].update(inReleaseSha256='0'*64),
          lambda v:v['package'].update(bytes=True),
          lambda v:v['package'].update(sha256='f'*64),
          lambda v:v['package'].update(depends='x\nRAW'),
          lambda v:v['tool'].update(path='/usr/bin/arbitrary'),
          lambda v:v['tool'].update(sha256='f'*64),
          lambda v:v.update(sourceManifestSha256='f'*64),
          lambda v:v.update(aptMetadataManifestSha256='f'*64),
          lambda v:v.update(extra='undeclared')]
        for mutate in cases:
            with self.subTest(mutate=mutate):
                value=copy.deepcopy(self.repair);mutate(value)
                (self.out/'repair/manifest.json').write_bytes(a.canonical(value))
                with self.assertRaises(a.Refusal):self.pack()
                self.assertFalse((self.root/'public.tar.gz').exists())
        (self.out/'repair/manifest.json').write_bytes(original)
        (self.out/'repair/selinux-utils.deb').write_bytes(b'changed public package')
        with self.assertRaisesRegex(a.Refusal,'repair_payload_changed'):self.pack()

    def test_repair_same_output_index_substitution_is_not_a_signed_record_join(self):
        index=self.out/'apt-data/Packages';original=index.read_bytes()
        for old,new in ((self.repair['package']['filename'].encode(),b'pool/main/a/alternate.deb'),
                (self.repair['package']['sha256'].encode(),b'f'*64),
                (b'Size: 126432',b'Size: 126433'),
                (a.REPAIR_PACKAGE_DEPENDS.encode(),b'libc6 (>= 2.34)')):
            with self.subTest(new=new):
                changed=original.replace(old,new);self.assertNotEqual(changed,original);index.write_bytes(changed)
                value=copy.deepcopy(self.repair);value['package']['packagesSha256']=a.sha(changed)
                (self.out/'repair/manifest.json').write_bytes(a.canonical(value))
                with self.assertRaisesRegex(a.Refusal,'repair_signed_record'):self.pack()
                self.assertFalse((self.root/'public.tar.gz').exists())

    def test_repair_export_is_closed_and_uses_existing_caps(self):
        (self.out/'repair/unlisted.deb').write_bytes(b'UNLISTED')
        _,path=self.pack()
        with tarfile.open(path,'r:gz')as archive:
            names=archive.getnames();self.assertNotIn('repair/unlisted.deb',names)
            self.assertEqual({name for name in names if name.startswith('repair/')},
              {'repair/selinux-utils.deb','repair/manifest.json'})
        self.assertEqual(a.REPAIR_MANIFEST_CAP,8192);self.assertEqual(a.REPAIR_PACKAGE_CAP,1048576)

    def test_duplicate_missing_or_symlink_repair_inputs_refuse_without_output(self):
        p=self.out/'repair/manifest.json';original=p.read_bytes()
        p.write_bytes(original[:-1]+b',"fixtureOnly":true}')
        with self.assertRaisesRegex(a.Refusal,'repair_duplicate_key'):self.pack()
        p.write_bytes(original)
        data=self.out/'repair/selinux-utils.deb';data.unlink();data.symlink_to(self.out/'unknown-secret')
        with self.assertRaisesRegex(a.Refusal,'artifact.path'):self.pack()
        self.assertFalse((self.root/'public.tar.gz').exists())


if __name__=='__main__':unittest.main()

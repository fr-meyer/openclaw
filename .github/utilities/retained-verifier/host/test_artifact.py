import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
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
        controls['build.json']=a.canonical({'helperSha256':a.sha(helper)})
        for name,raw in controls.items():(self.out/name).write_bytes(raw)
        for name in a.APT_FILES:(self.out/'apt-data'/name).write_bytes(b'public synthetic '+name.encode())
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


if __name__=='__main__':unittest.main()

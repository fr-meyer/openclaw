import json
from pathlib import Path
import tempfile
import unittest
import ci_host as h


class Port:
    def __init__(self,fail=None):self.fail=fail;self.calls=[];self.failure=None;self.saved=None
    def call(self,name):
        self.calls.append(name)
        if self.fail==name:raise h.Refusal('test.'+name)
    def admit_source(self):self.call('source')
    def test_sources(self):self.call('tests')
    def install_host_tools(self):self.call('tools')
    def authenticate_metadata(self):self.call('metadata')
    def negative_bootstrap(self):self.call('negative')
    def build_once(self):self.call('build')
    def bind_image(self):self.call('bind');return {'expected':True}
    def boot_once(self):self.call('boot');return {'owned':True}
    def preserve_outer(self,value):self.call('preserve');self.captured=value
    def verify_outer(self,value,expected):self.call('verify');return {'status':'passed'}
    def package_public_artifact(self,proof):self.call('package')
    def preserve_failure(self,phase,error):self.failure=(phase,type(error).__name__)
    def save_final(self,value):self.saved=value


class HostTests(unittest.TestCase):
    def test_one_whole_sequence_and_no_replay(self):
        port=Port();controller=h.Controller(port);result=controller.run()
        self.assertEqual(result['status'],'passed');self.assertFalse(result['candidateQualified'])
        self.assertEqual(port.calls,['source','tests','tools','metadata','negative','build','bind','boot','preserve','verify','package'])
        with self.assertRaisesRegex(h.Refusal,'controller_once'):controller.run()
    def test_every_preboot_failure_prevents_boot(self):
        for phase in ('source','tests','tools','metadata','negative','build','bind'):
            port=Port(phase);result=h.Controller(port).run()
            self.assertEqual(result['status'],'refused');self.assertNotIn('boot',port.calls)
            self.assertIs(port.saved,result)
    def test_boot_failure_is_not_redispatched(self):
        port=Port('boot');result=h.Controller(port).run()
        self.assertEqual(result['status'],'refused');self.assertEqual(port.calls.count('boot'),1)
    def test_raw_custody_precedes_parser_and_parser_failure_stops_artifact(self):
        port=Port('verify');result=h.Controller(port).run()
        self.assertEqual(port.captured,{'owned':True});self.assertNotIn('package',port.calls)
        self.assertEqual(result['phase'],'independent-consumer')
    def test_unknown_or_false_proof_never_packages(self):
        for proof in (None,False,{}, {'status':'refused'}):
            port=Port();port.verify_outer=lambda *_:proof
            self.assertEqual(h.Controller(port).run()['status'],'refused');self.assertNotIn('package',port.calls)
    def test_package_failure_still_saves_cause(self):
        port=Port('package');result=h.Controller(port).run()
        self.assertEqual(port.failure,('artifact','Refusal'));self.assertEqual(result['status'],'refused')
    def test_duplicate_json_and_compression_caps_refuse(self):
        with self.assertRaisesRegex(h.Refusal,'json_duplicate'):h.decode(b'{"a":1,"a":2}')
        with self.assertRaisesRegex(h.Refusal,'xz_cap'):h.decompress_packages(b'x'*(16777216+1))
    def test_root_package_selection_is_exact_not_dependency_solver(self):
        rows={('a','1','amd64'):{'version':'1','debSha256':'a'*64},
              ('linux-image-6.1.test','2','amd64'):{'version':'2','debSha256':'b'*64}}
        selected=h.select_roots(rows,{'a'},'linux-image-6.1.test');self.assertEqual(len(selected),2)
        rows[('a','2','amd64')]={'version':'2','debSha256':'c'*64}
        with self.assertRaisesRegex(h.Refusal,'ambiguous'):h.select_roots(rows,{'a'},'linux-image-6.1.test')
    def test_read_rejects_symlink_and_changed_source_pin(self):
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp).resolve();file=root/'file';file.write_bytes(b'public');(root/'link').symlink_to(file)
            with self.assertRaisesRegex(h.Refusal,'file_path'):h.read_regular(root/'link',1024)
            (root/'PUBLIC-SOURCE-MANIFEST.json').write_bytes(b'{}')
            with self.assertRaisesRegex(h.Refusal,'manifest_pin'):h.bootstrap_source(root,'0'*64)


if __name__=='__main__':unittest.main()

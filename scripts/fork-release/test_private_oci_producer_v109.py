"""Synthetic byte inventories only; no candidate image or application execution."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'compatibility-test-view'))
SPEC=importlib.util.spec_from_file_location('v109_private_producer',ROOT/'private_oci_producer_v109.py')
p=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(p)

class ProducerTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='v109-producer-fixture-');self.root=Path(self.temp.name).resolve();self.old=os.umask(0o077)
  self.source='1'*40;self.tree='2'*40;self.workflow='3'*40;self.digest='sha256:'+'4'*64
  self.oci=self.root/'oci';self.oci.mkdir();(self.oci/'blobs'/'sha256').mkdir(parents=True)
  data=b'public synthetic bytes, not an image';(self.oci/'blobs'/'sha256'/hashlib.sha256(data).hexdigest()).write_bytes(data)
  (self.oci/'oci-layout').write_bytes(b'{"imageLayoutVersion":"1.0.0"}\n')
  (self.oci/'index.json').write_bytes(b'{"schemaVersion":2,"manifests":[]}\n')
  manifest={'schema':'openclaw.fork-release.v1','repository':'fr-meyer/openclaw','productionEligible':False,
   'source':{'commit':self.source,'tree':self.tree},'image':{'architecture':'amd64','extensions':'codex,workboard'}}
  self.manifest=self.root/'manifest.json';self.manifest.write_bytes(p.encoded(manifest))
  self.inventory=self.root/'inventory.json';self.inventory.write_bytes(p.encoded({'schema':'openclaw.fork-patch-inventory.v1',
   'repository':'fr-meyer/openclaw','manifestSha256':p.sha(self.manifest.read_bytes())}))
  self.metadata=self.root/'metadata.json';self.metadata.write_bytes(p.encoded({'containerimage.digest':self.digest}))
  self.resources=self.root/'resources.json';self.resources.write_bytes(p.encoded({'schema':'openclaw.hosted-resources.v1',
   'sourceSha':self.source,'toolingSha':self.workflow,'indexDigest':self.digest,'status':'passed'}))
  self.out=self.root/'output';self.receipt=self.root/'receipt.json'
 def tearDown(self):os.umask(self.old);self.temp.cleanup()
 def prepare(self,**overrides):
  args={'source_sha':self.source,'source_tree':self.tree,'workflow_sha':self.workflow,'run_id':'123','attempt':'1','built_at':'2020-01-01T00:00:00Z'};args.update(overrides)
  return p.prepare_from_build(self.manifest,self.inventory,self.metadata,self.resources,self.oci,self.out,self.receipt,**args)
 def test_explicit_new_source_opaque_archive(self):
  r=self.prepare();self.assertEqual(r['sourceSha'],self.source);self.assertEqual(r['sourceTree'],self.tree)
  self.assertFalse(r['qualified']);self.assertFalse(r['productionAuthorized']);self.assertFalse(r['publicExportAuthorized'])
  self.assertEqual(r['retentionValidation'],'opaque_byte_inventory');self.assertEqual(r['originAuthority'],'native_github_attestation_and_run_verification_required')
  self.assertEqual((self.out/'retained-oci.tar').stat().st_mode&0o777,0o600)
  self.assertEqual(p.sha((self.out/'retained-oci.tar').read_bytes()),r['archiveSha256'])
 def test_identity_does_not_default_to307(self):
  with self.assertRaises(p.Refusal):self.prepare(source_sha='30786562e236aab6a924981c62aa61b920132c76')
 def test_malformed_source(self):
  with self.assertRaises(p.Refusal):self.prepare(source_sha='x')
 def test_wrong_manifest(self):
  obj=json.loads(self.manifest.read_bytes());obj['source']['tree']='a'*40;self.manifest.write_bytes(p.encoded(obj))
  with self.assertRaises(p.Refusal):self.prepare()
 def test_wrong_metadata_digest(self):
  self.metadata.write_bytes(p.encoded({'containerimage.digest':'invalid'}))
  with self.assertRaises(p.Refusal):self.prepare()
 def test_wrong_resource_identity(self):
  obj=json.loads(self.resources.read_bytes());obj['sourceSha']='a'*40;self.resources.write_bytes(p.encoded(obj))
  with self.assertRaises(p.Refusal):self.prepare()
 def test_failed_resources_still_unqualified_forensic_retention(self):
  obj=json.loads(self.resources.read_bytes());obj['status']='failed';self.resources.write_bytes(p.encoded(obj))
  r=self.prepare();self.assertFalse(r['qualified']);self.assertFalse(r['productionAuthorized'])
 def test_existing_output_never_overwritten(self):
  self.out.mkdir();(self.out/'keep').write_bytes(b'original')
  with self.assertRaises(Exception):self.prepare()
  self.assertEqual((self.out/'keep').read_bytes(),b'original')
 def test_symlink_input_refused(self):
  old=self.root/'real-metadata';self.metadata.rename(old);self.metadata.symlink_to(old)
  with self.assertRaises(Exception):self.prepare()
 def test_archive_limit_refuses_without_deleting_inputs(self):
  before=self.manifest.read_bytes()
  with self.assertRaises(p.Refusal):self.prepare(limit=1)
  self.assertEqual(self.manifest.read_bytes(),before);self.assertFalse((self.out/'retained-oci.tar').exists())

if __name__=='__main__':unittest.main()

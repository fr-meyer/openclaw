"""Synthetic CI control tests; no provider, Docker or application calls."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import image_build_contract_v109 as c
import image_build_runner_v109 as r
from test_image_build_contract_v109 import armed,context,NOW

class RunnerTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='image-runner-synthetic-');self.base=Path(self.tmp.name).resolve()
 def tearDown(self):self.tmp.cleanup()
 def test_disarmed_never_reads_source_calls_api_or_child(self):
  with patch.object(r,'image_request',return_value=(c.encode(c.disarmed_request()),c.disarmed_request())),patch.object(r,'source_inputs',side_effect=AssertionError),patch.object(r.subprocess,'run',side_effect=AssertionError),patch.object(r,'outputs')as output:
   self.assertEqual(r.admission()['status'],'disarmed');output.assert_called_once_with({'enabled':'false'})
 def test_prepared_never_activates(self):
  req=armed();req['state']='PREPARED_BUILD';req['authorization']=None
  with patch.object(r,'image_request',return_value=(c.encode(req),req)),patch.object(r,'source_inputs',side_effect=AssertionError),patch.object(r,'outputs'):
   self.assertFalse(r.admission()['imageBuilt'])
 def test_no_arbitrary_main_command(self):
  with patch.object(sys,'argv',['runner','docker-run']),contextlib.redirect_stdout(io.StringIO())as out:
   self.assertEqual(r.main(),1);self.assertIn('image.fixed_command',out.getvalue())
 def test_private_custody_before_timeout_refusal_even_valid_json(self):
  api=r.GitHub(self.base/'api')
  with patch.object(r.subprocess,'run',side_effect=subprocess.TimeoutExpired('gh',30,output=b'{"valid":true}',stderr=b'private-synthetic')):
   with self.assertRaises(c.Refusal):api.get('actions/runs/123')
  self.assertEqual((api.path/'001.stdout.private').read_bytes(),b'{"valid":true}')
  self.assertEqual((api.path/'001.stderr.private').stat().st_mode&0o777,0o600)
  self.assertIsNone(json.loads((api.path/'001.frame.private.json').read_bytes())['exitCode'])
 def test_private_oversize_prefix_before_refusal(self):
  api=r.GitHub(self.base/'api');data=b'x'*(2097152+1)
  with patch.object(r.subprocess,'run',return_value=subprocess.CompletedProcess([],0,data,b'')):
   with self.assertRaises(c.Refusal):api.get('actions/runs/123')
  self.assertEqual((api.path/'001.stdout.private').stat().st_size,2097152)
  self.assertEqual(json.loads((api.path/'001.frame.private.json').read_bytes())['stdoutBytes'],len(data))
 def test_capability_not_in_github_child_environment(self):
  api=r.GitHub(self.base/'api');seen={}
  def child(argv,**kwargs):seen.update(kwargs['env']);return subprocess.CompletedProcess(argv,0,b'{}',b'')
  with patch.dict(os.environ,{'OCI_UPLOAD_ENVELOPE':'synthetic-private','OTHER_SECRET':'not-a-real-secret'}),patch.object(r.subprocess,'run',side_effect=child):api.get('actions/runs/123')
  self.assertNotIn('OCI_UPLOAD_ENVELOPE',seen);self.assertNotIn('OTHER_SECRET',seen)
 def test_admission_removes_cap_before_source_subprocesses(self):
  req=armed()
  def refused(_):self.assertNotIn('OCI_UPLOAD_ENVELOPE',os.environ);raise c.Refusal('synthetic.stop')
  with patch.dict(os.environ,{'OCI_UPLOAD_ENVELOPE':'synthetic'}),patch.object(r,'image_request',return_value=(b'{}',req)),patch.object(r,'context',return_value=context()),patch.object(r.contract,'validate_context',return_value=context()),patch.object(r,'source_inputs',side_effect=refused):
   with self.assertRaises(c.Refusal):r.admission()
 def test_read_refuses_symlink_or_multiple_link(self):
  p=self.base/'input';p.write_bytes(b'{}');link=self.base/'link';link.symlink_to(p)
  with self.assertRaises(OSError):r.read(link)
  os.link(p,self.base/'hard')
  with self.assertRaises(c.Refusal):r.read(p)
 def test_metadata_original_prefix_before_invalid_digest(self):
  (self.base/'v109-image').mkdir()
  with patch.dict(os.environ,{'RUNNER_TEMP':str(self.base),'ORIGINAL_BUILD_METADATA':'{"synthetic":true}','OCI_DIGEST':'bad'}),patch.object(r,'checked',return_value=(b'{}',armed(),context())):
   with self.assertRaises(c.Refusal):r.record_build()
  self.assertEqual((self.base/'v109-image/build-metadata.json').read_text(),'{"synthetic":true}')
 def test_result_public_closed_without_private_identity(self):
  where=self.base/'v109-private-retention';where.mkdir();ctx=context();req=armed()
  value={'status':'transferred','sourceSha':req['sourceSha'],'toolingSha':ctx['sha'],'runId':ctx['runId'],'attempt':'1','archiveSha256':'1'*64,'archiveBytes':100,'generation':'123456','objectIdentitySha256':'2'*64}
  (where/'transfer.json').write_bytes(c.encode(value));env={'RUNNER_TEMP':str(self.base),**{k:'success'for k in ('SOURCE_OUTCOME','BUILD_OUTCOME','RESOURCE_OUTCOME','ATTEST_OUTCOME','TRANSFER_OUTCOME')}}
  with patch.dict(os.environ,env),patch.object(r,'checked',return_value=(b'{}',req,ctx)):result=r.complete()
  raw=c.encode(result);self.assertLessEqual(len(raw),16384)
  self.assertEqual(set(result),{'schema','status','sourceSha','sourceTree','archiveSha256','archiveBytes','producer','generation','objectIdentitySha256','producerAttestationRequiredAtReceiver','embeddedSourceVerified','privacyPassed','qualified','nativeImageExecuted','productionAuthorized'})
  self.assertFalse(any(result[k]for k in ['embeddedSourceVerified','privacyPassed','qualified','nativeImageExecuted','productionAuthorized']))
  for private in [c.BUCKET,c.SIGNER,c.SECRET,c.expected_object(req['sourceSha'])]:self.assertNotIn(private.encode(),raw)
 def test_yaml_guards_no_image_execution_or_source_trigger(self):
  repository=ROOT.parents[1]
  workflow_path=repository/'.github/workflows/future-v109-image-build.yml'
  action_path=repository/'.github/actions/retain-private-oci-v109/action.yml'
  # Initial public source CI carries only this exact inert workflow fixture.
  if not workflow_path.is_file():workflow_path=ROOT/'fixtures/v109-image-build.yml'
  # The reviewed local preparation is flat; no arbitrary path search is allowed.
  if not workflow_path.is_file():workflow_path=ROOT/'future-v109-image-build.yml'
  if not action_path.is_file():action_path=ROOT/'retain-private-oci-v109.action.yml'
  workflow=workflow_path.read_text();action=action_path.read_text()
  self.assertEqual(workflow.count('actions: read'),2)
  for value in ['  push:','timeout-minutes: 90','cancel-in-progress: false','retention-days: 3','github-token: ""','OPENCLAW_PRIVATE_OCI_CAPABILITY_V109','DOCKER_BUILD_RECORD_UPLOAD: "false"']:
   self.assertIn(value,workflow)
  for value in ['pull_request:', 'workflow_dispatch:', 'docker load', 'docker run', 'image.mjs', 'gcloud', 'source-validation.yml']:
   self.assertNotIn(value,workflow)
  self.assertNotIn('upload-artifact',action);self.assertIn('push-to-registry: false',action)

if __name__=='__main__':unittest.main()

import copy
from datetime import datetime, timezone
import importlib.util
import io
import json
from pathlib import Path
import stat
import unittest
import zipfile

ROOT=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location('image_contract',ROOT/'image_build_contract_v109.py')
c=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(c)
NOW=datetime(2026,10,30,2,0,0,tzinfo=timezone.utc).timestamp()

def armed():
 r=c.disarmed_request();r.update(state='APPROVED_BUILD',preparationSourceSha='1'*40,previousPipelineHead='a'*40,
  sourceSha='3'*40,sourceTree='4'*40,sourceBindingsSha256='5'*64,sourceRequestSha256='6'*64,
  generationReceiptSha256='7'*64,manifestSha256='8'*64,inventorySha256='9'*64,builtAt='2026-10-30T01:00:00Z',
  sourceValidation={'runId':'123','attempt':1,'pipelineHead':'a'*40,'phase':'validation','artifactId':456,
    'artifactSha256':'b'*64,'resultSha256':'c'*64},
  authorization={'schema':'openclaw.v109.private-image-authorization.v1','approvedAt':'2026-10-30T00:00:00Z',
    'expiresAt':'2026-11-03T00:00:00Z','approvalScopeSha256':'d'*64,'actionTimeAccessApprovalSha256':'e'*64,
    'maximumPhysicalBuilds':1,'maximumBuildMinutes':90,'maximumFamilyMinutes':180,'maximumArchiveBytes':c.MAX_ARCHIVE,
    'maximumNewRunnerMinutes':2500,'moneyCeilingUSDIncludingAllowance':'2.25','producedImageExecutionAllowed':False,
    'publicImageExportAllowed':False,'cloudGrantFromRunnerAllowed':False})
 r['privateObject']['object']=c.expected_object(r['sourceSha']);return r

def context():
 return {'repository':c.REPOSITORY,'actor':c.ACTOR,'event':'push','ref':c.REF,'sha':'f'*40,'workflowSha':'f'*40,
  'runId':'789','attempt':1,'before':'a'*40,'after':'f'*40,'created':False,'deleted':False,'forced':False}

def source_fixture(r):
 v={'sourceSha':r['sourceSha'],'sourceTree':r['sourceTree'],'manifestSha256':r['manifestSha256'],
  'inventorySha256':r['inventorySha256'],'requestSha256':r['sourceRequestSha256'],
  'generationReceiptSha256':r['generationReceiptSha256'],'status':'passed','imageBuilt':False,
  'nativeImageExecuted':False,'productionAuthorized':False}
 raw=c.encode(v);bio=io.BytesIO()
 with zipfile.ZipFile(bio,'w')as z:z.writestr('source-validation.json',raw)
 zipraw=bio.getvalue();r['sourceValidation']['artifactSha256']=c.sha(zipraw);r['sourceValidation']['resultSha256']=c.sha(raw)
 run={'id':123,'run_attempt':1,'head_sha':'a'*40,'path':c.SOURCE_WORKFLOW,'event':'pull_request','head_branch':c.BRANCH,
  'display_title':c.SOURCE_NAME,'status':'completed','conclusion':'success',
  'repository':{'full_name':c.REPOSITORY,'private':False},'actor':{'login':c.ACTOR},'triggering_actor':{'login':c.ACTOR}}
 jobs={'total_count':17,'jobs':[{'id':i+1,'name':n,'status':'completed','conclusion':'success','run_id':123}
  for i,n in enumerate(['admission',*[f'source ({p})'for p in c.PROFILES],'final'])]}
 a={'total_count':1,'artifacts':[{'id':456,'name':'v109-source-validation-123-attempt1','expired':False,
  'size_in_bytes':len(zipraw),'digest':'sha256:'+c.sha(zipraw),'workflow_run':{'id':123,'head_sha':'a'*40}}]}
 return run,jobs,a,zipraw,lambda x:c.parse(x)

def history():
 runs={'total_count':2,'workflow_runs':[{'id':789,'path':c.WORKFLOW,'event':'push','head_branch':c.BRANCH,
  'run_attempt':1,'actor':{'login':c.ACTOR},'triggering_actor':{'login':c.ACTOR},'head_sha':'f'*40,'status':'in_progress'},
  {'id':780,'path':c.WORKFLOW,'event':'push','head_branch':c.BRANCH,'run_attempt':1,
   'actor':{'login':c.ACTOR},'triggering_actor':{'login':c.ACTOR},'head_sha':'0'*40,'status':'completed'}]}
 jobs={'780':{'total_count':2,'jobs':[{'id':1,'name':'image-admission','status':'completed','conclusion':'success','run_id':780},
  {'id':2,'name':'build-private-image','status':'completed','conclusion':'skipped','run_id':780,'steps':[]}]}}
 return runs,jobs

class ContractTests(unittest.TestCase):
 def refuses(self,fn,*a):
  with self.assertRaises(c.Refusal):fn(*a)
 def test_exact_extended96_and_actual_deadline(self):
  r=armed();r['authorization']['approvedAt']='2026-10-30T03:14:21Z';r['authorization']['expiresAt']='2026-11-03T03:14:21Z'
  now=c.utc('2026-11-02T04:00:00Z').timestamp();c.validate_request(r,True,now)
  self.assertEqual(c.AUTH_HOURS,96)
 def test_old72_or_widened96_refused(self):
  for end in ['2026-11-02T00:00:00Z','2026-11-03T00:00:01Z','2026-11-04T00:00:00Z']:
   r=armed();r['authorization']['expiresAt']=end;self.refuses(c.validate_request,r,True,NOW)
 def test_time_extension_does_not_widen_access_attempt_or_money(self):
  r=armed();self.assertEqual(r['privateObject']['putMaximumSeconds'],3600)
  self.assertEqual(r['privateObject']['uploadGrantMaximumSeconds'],7200)
  self.assertEqual(r['privateObject']['getMaximumSeconds'],900);self.assertEqual(r['privateObject']['readerGrantMaximumSeconds'],900)
  self.assertEqual(r['authorization']['maximumPhysicalBuilds'],1);self.assertEqual(r['authorization']['maximumNewRunnerMinutes'],2500)
  self.assertEqual(r['authorization']['moneyCeilingUSDIncludingAllowance'],'2.25')
 def test_prepared_is_not_authority(self):
  r=armed();r['state']='PREPARED_BUILD';r['authorization']=None;c.validate_request(r)
  self.refuses(c.validate_request,r,True,NOW)
  a=armed()['authorization'];active=c.arm_prepared(r,a,NOW)
  self.assertEqual(active['state'],'APPROVED_BUILD');self.assertIsNone(r['authorization'])
 def test_arm_requires_prepared_and_action_access(self):
  self.refuses(c.arm_prepared,c.disarmed_request(),armed()['authorization'],NOW)
  r=armed();r['state']='PREPARED_BUILD';r['authorization']=None
  a=armed()['authorization'];a['actionTimeAccessApprovalSha256']=None
  self.refuses(c.arm_prepared,r,a,NOW)
 def test_family_uses_actual_plus_current_full_caps(self):
  self.assertEqual(c.family_budget([5,70])['priorRunnerMinutes'],75)
  self.refuses(c.family_budget,[76]);self.refuses(c.family_budget,[True]);self.refuses(c.family_budget,[-1])
 def test_run_boolean_attempt_not_integer(self):
  r=armed();run,jobs,a,b,v=source_fixture(r);run['run_attempt']=True
  self.refuses(c.validate_source_snapshot,r,run,jobs,a,b,v)
 def test_disarmed_exact(self):c.validate_request(c.disarmed_request())
 def test_disarmed_cannot_execute(self):self.refuses(c.validate_request,c.disarmed_request(),True,NOW)
 def test_disarmed_no_fake_source(self):
  r=c.disarmed_request();r['sourceSha']='1'*40;self.refuses(c.validate_request,r)
 def test_approved_complete(self):c.validate_request(armed(),True,NOW)
 def test_old_source_object_refused(self):
  r=armed();r['privateObject']['object']=r['privateObject']['object'].replace('2026.10.9','2026.10.5');self.refuses(c.validate_request,r)
 def test_unknown_field(self):
  r=armed();r['command']='docker run';self.refuses(c.validate_request,r)
 def test_boolean_integer(self):
  r=armed();r['authorization']['maximumPhysicalBuilds']=True;self.refuses(c.validate_request,r)
 def test_missing_access_approval(self):
  r=armed();r['authorization']['actionTimeAccessApprovalSha256']=None;self.refuses(c.validate_request,r)
 def test_scope_cannot_widen(self):
  for k,v in [('publicImageExportAllowed',True),('producedImageExecutionAllowed',True),('cloudGrantFromRunnerAllowed',True),('maximumBuildMinutes',91)]:
   r=armed();r['authorization'][k]=v;self.refuses(c.validate_request,r)
 def test_expired_and_future_clock(self):
  self.refuses(c.validate_request,armed(),True,NOW-999999);self.refuses(c.validate_request,armed(),True,NOW+999999)
 def test_prelock_cannot_be_image_source(self):
  r=armed();r['preparationSourceSha']=r['sourceSha'];self.refuses(c.validate_request,r)
 def test_exact_push(self):c.validate_context(context(),armed(),NOW)
 def test_no_pull_request_merge_sha(self):
  x=context();x['event']='pull_request';self.refuses(c.validate_context,x,armed(),NOW)
 def test_context_wrong_actor_or_retry(self):
  for k,v in [('actor','other'),('attempt',2),('created',True),('forced',True),('workflowSha','a'*40),('before','f'*40)]:
   x=context();x[k]=v;self.refuses(c.validate_context,x,armed(),NOW)
 def test_source_actual_17_jobs_and_zip(self):
  r=armed();self.assertEqual(c.validate_source_snapshot(r,*source_fixture(r))['sourceSha'],r['sourceSha'])
 def test_source_failed_job(self):
  r=armed();run,jobs,a,b,v=source_fixture(r);jobs['jobs'][2]['conclusion']='failure';self.refuses(c.validate_source_snapshot,r,run,jobs,a,b,v)
 def test_no_source_partial_jobs(self):
  r=armed();run,jobs,a,b,v=source_fixture(r);jobs['jobs'].pop();self.refuses(c.validate_source_snapshot,r,run,jobs,a,b,v)
 def test_source_not_self_report(self):
  r=armed();run,jobs,a,b,v=source_fixture(r);run['conclusion']='failure';self.refuses(c.validate_source_snapshot,r,run,jobs,a,b,v)
 def test_source_artifact_pin_and_expiry(self):
  for kind in ['digest','expired','name','head']:
   r=armed();run,jobs,a,b,v=source_fixture(r)
   if kind=='head':a['artifacts'][0]['workflow_run']['head_sha']='e'*40
   else:a['artifacts'][0][kind]={'digest':'sha256:'+'0'*64,'expired':True,'name':'other'}[kind]
   self.refuses(c.validate_source_snapshot,r,run,jobs,a,b,v)
 def test_source_zip_extra_member(self):
  r=armed();run,jobs,a,b,v=source_fixture(r);z=io.BytesIO()
  with zipfile.ZipFile(z,'w')as zip:zip.writestr('source-validation.json',b'{}');zip.writestr('extra',b'x')
  b=z.getvalue();r['sourceValidation']['artifactSha256']=c.sha(b);a['artifacts'][0]['digest']='sha256:'+c.sha(b);self.refuses(c.validate_source_snapshot,r,run,jobs,a,b,v)
 def test_source_result_pin(self):
  r=armed();args=source_fixture(r);r['sourceValidation']['resultSha256']='0'*64;self.refuses(c.validate_source_snapshot,r,*args)
 def test_history_only_disarmed_prior(self):c.validate_image_history(armed(),context(),*history())
 def test_prior_build_consumed(self):
  runs,jobs=history();jobs['780']['jobs'][1]['conclusion']='failure';self.refuses(c.validate_image_history,armed(),context(),runs,jobs)
 def test_no_prior_unsettled_or_attempt2(self):
  for k,v in [('status','in_progress'),('run_attempt',2)]:
   runs,jobs=history();runs['workflow_runs'][1][k]=v;self.refuses(c.validate_image_history,armed(),context(),runs,jobs)
 def test_prior_unknown_job_refused(self):
  runs,jobs=history();jobs['780']['jobs'][1]['name']='other';self.refuses(c.validate_image_history,armed(),context(),runs,jobs)
 def test_prior_admission_refusal_not_auto_retry(self):
  runs,jobs=history();jobs['780']['jobs'][0]['conclusion']='failure';self.refuses(c.validate_image_history,armed(),context(),runs,jobs)
 def test_complete_history_and_current(self):
  runs,jobs=history();runs['total_count']=3;self.refuses(c.validate_image_history,armed(),context(),runs,jobs)
 def test_window_reserves_five_minutes(self):
  x=c.build_window(NOW+3600,NOW,'2026-11-02T00:00:00Z');self.assertEqual(x['timeoutMinutes'],55);self.assertEqual(x['archiveAttestUploadReserveSeconds'],300)
 def test_window_refuses_under45minutes(self):self.refuses(c.build_window,NOW+2699,NOW,'2026-11-02T00:00:00Z')
 def test_deadline_respected(self):self.refuses(c.build_window,NOW+3600,NOW,'2026-10-30T02:10:00Z')
 def test_capability_private_validation(self):
  r=armed();x=context();e={'schema':'openclaw.private-oci-capability.v1','sourceSha':r['sourceSha'],'workflowSha':x['sha'],
   **{k:r['privateObject'][k]for k in ['bucket','object','signer']},'url':'https://example.invalid/synthetic-not-a-capability'}
  def validator(url,plan,method,now):
   self.assertEqual(plan['archiveBytes'],1);self.assertEqual(method,'PUT');return '/synthetic',{},now+3600
  self.assertEqual(c.validate_envelope(c.encode(e),r,x,validator,NOW),NOW+3600)
  e['object']='other';self.refuses(c.validate_envelope,c.encode(e),r,x,validator,NOW)
 def test_plan_exact_create_only(self):
  r=armed();x=context();plan={'schema':'openclaw.private-oci-transfer-plan.v1','sourceSha':r['sourceSha'],'toolingSha':x['sha'],
   'runId':x['runId'],'attempt':'1','archiveSha256':'b'*64,'archiveBytes':100,
   **{k:r['privateObject'][k]for k in ['bucket','object','signer']},'generation':None}
  c.validate_transfer_plan(plan,r,x,'b'*64,100);plan['generation']='1';self.refuses(c.validate_transfer_plan,plan,r,x,'b'*64,100)
 def test_duplicate_json_never_defaults(self):self.refuses(c.parse,b'{"state":"DISARMED","state":"APPROVED_BUILD"}')

if __name__=='__main__':unittest.main()

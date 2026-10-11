"""Exercise batch invocation and per-owner attribution without running Vitest."""
import contextlib,copy,hashlib,inspect,io,json,os,shutil,subprocess,tempfile,unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
import sys
sys.path.insert(0,str(HERE))
import native

PATHS=["src/gateway/server.workboard-native.test.ts","extensions/workboard/src/gateway.test.ts"]

def file_report(source,path,failed=False):
 assertions=[{"fullName":path+" preserves producer contract","status":"failed"if failed else"passed","failureMessages":["real sibling assertion failed"]if failed else[]}]
 return {"name":str(source/path),"status":"failed"if failed else"passed","assertionResults":assertions}

def summary(files):
 assertions=[a for f in files for a in f["assertionResults"]]
 failed=sum(a["status"]=="failed"for a in assertions)
 return {"success":not failed,"numTotalTests":len(assertions),"numPassedTests":len(assertions)-failed,"numFailedTests":failed,"numPendingTests":0,"numTodoTests":0,"testResults":files}

class BatchEntrypoint(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name).resolve();self.source=self.root/"source";self.source.mkdir()
  self.env=patch.dict(os.environ,{"RUNNER_TEMP":str(self.root)},clear=True);self.env.start();self.addCleanup(self.env.stop)
  self.n=native.Native(self.source,self.root/"tooling");self.n.env["preserved"]="value"
  # The independently owned resource successor provides this required interface.
  # Preserve the baseline's real monotonic/cancellation check in this isolated lane.
  remaining=self.n.remaining;self.deadline_calls=[]
  def resource_remaining(end,cancel=True,phase="disk probe"):
   self.deadline_calls.append((end,phase))
   if "cancel"in inspect.signature(native.Native.remaining).parameters:return remaining(end,cancel=cancel,phase=phase)
   return remaining(end)
  self.n.remaining=resource_remaining

 def write_report_set(self,raw,failed=False,change=None):
  directory=Path(str(raw)+".reports-fixture");directory.mkdir()
  all_files=[];entries=[]
  for i,path in enumerate(PATHS,1):
   file=file_report(self.source,path,failed and i==1);all_files.append(file)
   parent=directory/str(i)/"1";parent.mkdir(parents=True)
   report=parent/"report.json";single=summary([file])
   config=f"test/vitest/vitest.fixture-{i}.config.ts";project_config=f"test/vitest/vitest.fixture-project-{i}.config.ts"
   for config_path in(config,project_config):
    target=self.source/config_path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text("export default {};\n")
   pool="threads"if i==1 else {"name":"forks-diagnostics"}
   project={"name":f"fixture-{i}","namePrefix":"fixture:","root":str(self.source),"config":str(self.source/project_config),"pool":pool}
   module={**project,"file":str(self.source/path),"taskId":f"task-{i}","pool":"threads"if i==1 else"forks-diagnostics"}
   command=["node","/native/vitest.mjs","run","--config",config,"--maxWorkers=1","--reporter=json",f"--outputFile.json={report}",f"--outputFile.blob={parent/'blob.json'}",f"--coverage.reportsDirectory={parent/'coverage'}","--reporter=blob",f"--reporter={self.source/'scripts/lib/vitest-report-capture.mts'}"]
   capture={"pid":100+i,"command":command,"root":str(self.source),"projects":[project],"processTimedOut":False,"modules":[module],"coverageDirectory":None,"coverageFiles":[],"coverageOnFailure":False,"passWithNoTests":False,"ignoreUnhandledErrors":False,"ended":{"reason":"failed"if single["numFailedTests"]else"passed","unhandledErrors":0,"suiteErrors":0,"failedModules":int(bool(single["numFailedTests"]))}}
   outcome={"code":int(bool(single["numFailedTests"])),"signal":None,"noOutputTimedOut":False,"exitedNormally":True,"groupJoined":True}
   entries.append({"invocation":i,"config":config,"args":["run","--config",config,"--maxWorkers=1","--reporter=json",f"--outputFile={raw}"],"includePatterns":[path],"state":"finished","acceptedAttempt":1,"attempts":[{"json":str(report),"blob":str(parent/"blob.json"),"outcome":outcome}]})
   if change:change("original",single,i);change("capture",capture,i)
   report.write_text(json.dumps(single));Path(str(report)+".capture.json").write_text(json.dumps(capture))
  report=summary(all_files);code=int(bool(report["numFailedTests"]))
  index={"requested":str(raw),"aggregate":str(raw),"complete":True,"error":"","publication":"","entries":entries,"merge":{"code":code,"signal":None,"noOutputTimedOut":False,"exitedNormally":True,"groupJoined":True}}
  if change:change("aggregate",report,0);change("index",index,0)
  raw.write_text(json.dumps(report));(directory/"index.json").write_text(json.dumps(index))
  return code,f"[test] native report set: {directory}\n"

 def invoke(self,failed=False,change=None,reason=None,unrun=False,result_change=None):
  captured={}
  def run(name,argv,seconds,owners):
   captured.update(name=name,argv=argv,seconds=seconds,owners=owners,env=dict(self.n.env))
   raw=Path(next(x.split("=",1)[1]for x in argv if x.startswith("--outputFile=")))
   code,text=(None,"")if unrun else self.write_report_set(raw,failed,change)
   result={"name":name,"argv":argv,"stages":owners,"exit":code,"reason":"NOT_RUN_AFTER_TIME_OR_CANCELLATION"if unrun else reason,"deadline":{"ownerEndMonotonic":min(self.n.end-15,native.time.monotonic()+seconds)},"descendantCleanup":{"leaderJoined":True,"rootSessionObserved":True,"sessionCensusComplete":True,"stillLiveGroups":0}}
   if result_change:result_change(result)
   self.n.c.append(result)
   if code is not None:self.n.reached.update(owners)
   if code:self.n.f.append(name)
   return result,text
  def cleanup(argv,**kwargs):
   self.assertEqual(argv[4],native.CACHE_DISPOSAL)
   self.assertEqual(argv[5],str(self.n.w))
   self.assertGreater(kwargs["timeout"],0)
   return real_cleanup(argv,**kwargs)
  old_env=dict(self.n.env)
  real_cleanup=native.subprocess.run
  with patch.object(self.n,"run",side_effect=run),patch.object(native.subprocess,"run",side_effect=cleanup),contextlib.redirect_stdout(io.StringIO()):self.n.test_many(PATHS)
  self.assertEqual(self.n.env,old_env)
  return self.n.c[-1],captured

 def test_complete_failed_sibling_does_not_mask_passed_owner(self):
  result,captured=self.invoke(failed=True)
  self.assertEqual(result["exit"],1)
  self.assertEqual([x["status"]for x in result["ownerResults"]],["FAIL","PASS"])
  self.assertEqual([x["execution"]for x in result["ownerResults"]],["COMPLETE","COMPLETE"])
  self.assertEqual(result["ownerResults"][0]["failedTests"],[PATHS[0]+" preserves producer contract"])
  self.assertEqual(result["ownerResults"][1]["tests"]["numPassedTests"],1)
  self.assertIn(result["name"],self.n.f)
  self.assertEqual(captured["argv"][-2:],PATHS)
  self.assertEqual(captured["env"]["OPENCLAW_TEST_PROJECTS_SERIAL"],"1")
  self.assertEqual(captured["env"]["OPENCLAW_NODE_TEST_PLAN_CONTINUE_ON_FAILURE"],"1")
  self.assertEqual(captured["env"]["OPENCLAW_VITEST_MAX_WORKERS"],"1")
  self.assertIn("--maxWorkers=1",captured["argv"])
  self.assertEqual(captured["seconds"],300)
  self.assertTrue(result["batchEvidence"]["reportSetComplete"])
  self.assertEqual(result["stages"],["vitest:"+p for p in PATHS])
  self.assertEqual(captured["owners"],(result["name"],),"command launch must not imply every selected owner ran")
  self.assertTrue(Path(next(x.split("=",1)[1]for x in result["argv"]if x.startswith("--outputFile="))).exists())
  self.assertTrue(result["batchReportCleanup"]["retained"])

 def test_complete_positive_owner_set_passes(self):
  result,_=self.invoke()
  self.assertEqual([x["stage"]for x in result["ownerResults"]],["vitest:"+p for p in PATHS])
  self.assertEqual([x["status"]for x in result["ownerResults"]],["PASS","PASS"])
  self.assertEqual(result["tests"]["numTotalTests"],2)
  self.assertEqual(len(result["batchEvidence"]["fileHashes"]),6)
  self.assertTrue(result["batchReportCleanup"]["removed"])
  self.assertEqual(self.n.reached,{"vitest:"+p for p in PATHS})
  self.assertTrue(all(end==result["deadline"]["ownerEndMonotonic"]for end,_ in self.deadline_calls))

 def test_unstarted_batch_records_every_owner_not_run_without_report_read(self):
  result,_=self.invoke(unrun=True)
  self.assertEqual([x["status"]for x in result["ownerResults"]],["NOT_RUN","NOT_RUN"])
  self.assertNotIn("reportFailure",result)

 def refused(self,change=None,reason=None):
  result,_=self.invoke(change=change,reason=reason)
  self.assertIn("batch report refused:",result["reportFailure"])
  self.assertEqual([x["status"]for x in result["ownerResults"]],["UNKNOWN","UNKNOWN"])
  self.assertTrue(all(x["execution"]in("UNKNOWN","COMPLETE")for x in result["ownerResults"]))
  self.assertIn(result["name"],self.n.f)
  self.assertNotIn("batchEvidence",result)
  self.assertTrue(result["batchReportCleanup"]["retained"])
  self.assertNotIn(result["name"],self.n.reached)
  return result

 def test_incomplete_native_publication_refuses_every_pass(self):
  def change(kind,data,i):
   if kind=="index":data["complete"]=False
  result=self.refused(change)
  self.assertEqual(self.n.reached,{"vitest:"+p for p in PATHS},"finished captures establish execution, while incomplete aggregate cannot establish PASS")
  self.assertEqual([x["execution"]for x in result["ownerResults"]],["COMPLETE","COMPLETE"])

 def test_outer_timeout_refuses_even_complete_json(self):self.refused(reason="command deadline exceeded")

 def test_incomplete_sibling_preserves_confirmed_failure_and_unknown_execution(self):
  def change(kind,data,i):
   if kind=="index":
    data.update(complete=False,aggregate="",error="later config never started")
    data["entries"][1].update(state="unstarted",attempts=[],acceptedAttempt=None)
  result,_=self.invoke(failed=True,change=change)
  self.assertEqual([x["status"]for x in result["ownerResults"]],["FAIL","NOT_RUN"])
  self.assertEqual([x["execution"]for x in result["ownerResults"]],["COMPLETE","NOT_RUN"])
  self.assertEqual(result["ownerResults"][0]["tests"]["numFailedTests"],1)
  self.n.planned=dict.fromkeys("vitest:"+p for p in PATHS);self.n.report_not_run()
  self.assertEqual(self.n.r["executedStages"],["vitest:"+PATHS[0]])
  self.assertEqual(self.n.r["notRun"],[{"stage":"vitest:"+PATHS[1],"reason":"NOT_RUN_SOURCE_REPORT_INVOCATION_UNSTARTED"}])
  self.assertTrue(result["batchReportCleanup"]["retained"])

 def test_missing_capture_report_set_refuses_single_config_direct_json(self):
  original=self.write_report_set
  def no_report_owner(raw,*args):
   code,_=original(raw,*args);return code,"ordinary single-config JSON only\n"
  with patch.object(self,"write_report_set",side_effect=no_report_owner):result=self.refused()
  self.assertIn("single-config attribution requires capture",result["reportFailure"])
  self.assertEqual(self.n.reached,set())

 def test_later_bad_capture_preserves_earlier_complete_failed_owner(self):
  for mode in("timeout","unhandled"):
   with self.subTest(mode=mode):
    def change(kind,data,i):
     if kind=="capture"and i==2:
      if mode=="timeout":data["processTimedOut"]=True
      else:data["ended"]["unhandledErrors"]=1
     elif kind=="index":data.update(complete=False,aggregate="",error="later capture refused")
    result,_=self.invoke(failed=True,change=change)
    self.assertEqual([x["status"]for x in result["ownerResults"]],["FAIL","UNKNOWN"])
    self.assertEqual([x["execution"]for x in result["ownerResults"]],["COMPLETE","UNKNOWN"])
    self.assertEqual(result["ownerResults"][0]["tests"]["numFailedTests"],1)
    self.assertEqual(self.n.reached,{"vitest:"+PATHS[0]})
    self.assertNotIn("batchEvidence",result)
    self.assertTrue(result["batchReportCleanup"]["retained"])

 def test_later_bad_capture_preserves_earlier_pass_as_unqualified_complete(self):
  for mode in("timeout","unhandled"):
   with self.subTest(mode=mode):
    def change(kind,data,i):
     if kind=="capture"and i==2:
      if mode=="timeout":data["processTimedOut"]=True
      else:data["ended"]["unhandledErrors"]=1
     elif kind=="index":data.update(complete=False,aggregate="",error="later capture refused")
    result,_=self.invoke(change=change)
    self.assertEqual([x["status"]for x in result["ownerResults"]],["UNKNOWN","UNKNOWN"])
    self.assertEqual([x["execution"]for x in result["ownerResults"]],["COMPLETE","UNKNOWN"])
    self.assertEqual(result["ownerResults"][0]["tests"]["numPassedTests"],1)
    self.assertEqual(self.n.reached,{"vitest:"+PATHS[0]})
    self.assertNotIn("batchEvidence",result)
    self.assertTrue(result["batchReportCleanup"]["retained"])

 def test_later_bad_capture_preserves_verified_unstarted_owner(self):
  for mode in("timeout","unhandled"):
   with self.subTest(mode=mode):
    def change(kind,data,i):
     if kind=="capture"and i==2:
      if mode=="timeout":data["processTimedOut"]=True
      else:data["ended"]["unhandledErrors"]=1
     elif kind=="index":
      data.update(complete=False,aggregate="",error="later capture refused")
      data["entries"][0].update(state="unstarted",attempts=[],acceptedAttempt=None)
    result,_=self.invoke(change=change)
    self.assertEqual([x["status"]for x in result["ownerResults"]],["NOT_RUN","UNKNOWN"])
    self.assertEqual([x["execution"]for x in result["ownerResults"]],["NOT_RUN","UNKNOWN"])
    self.assertEqual(self.n.reached,set())
    self.assertIn({"stage":"vitest:"+PATHS[0],"reason":"NOT_RUN_SOURCE_REPORT_INVOCATION_UNSTARTED"},self.n.u)
    self.assertNotIn("batchEvidence",result)
    self.assertTrue(result["batchReportCleanup"]["retained"])

 def test_cancellation_before_progress_commit_refuses_new_evidence(self):
  for mode in("complete","unstarted"):
   with self.subTest(mode=mode):
    self.n.cancel=False
    def change(kind,data,i):
     if mode=="unstarted"and kind=="index":data["entries"][0].update(state="unstarted",attempts=[],acceptedAttempt=None)
    invocation=native.batch_invocation_rows;require=native.need
    def validate(*args,**kwargs):
     owned=invocation(*args,**kwargs);self.n.cancel=True;return owned
    def require_then_cancel(condition,message):
     require(condition,message)
     if message=="batch unstarted invocation inconsistent":self.n.cancel=True
    with patch.object(native,"batch_invocation_rows",side_effect=validate if mode=="complete"else invocation),patch.object(native,"need",side_effect=require_then_cancel if mode=="unstarted"else require):
     result,_=self.invoke(failed=True,change=change)
    self.assertEqual([x["status"]for x in result["ownerResults"]],["UNKNOWN","UNKNOWN"])
    self.assertEqual([x["execution"]for x in result["ownerResults"]],["UNKNOWN","UNKNOWN"])
    self.assertEqual(self.n.reached,set())
    self.assertEqual(result["batchReportEvidence"]["unstartedStages"],[])
    self.assertNotIn("batchEvidence",result)
    self.assertTrue(result["batchReportCleanup"]["retained"])

 def test_original_deadline_missing_expired_or_cancelled_does_not_read_reports(self):
  for mode in("missing","expired","cancelled"):
   with self.subTest(mode=mode):
    self.n.cancel=False
    def change(result):
     if mode=="missing":result.pop("deadline")
     elif mode=="expired":result["deadline"]["ownerEndMonotonic"]=native.time.monotonic()-.1
     else:self.n.cancel=True
    result,_=self.invoke(result_change=change)
    self.assertEqual([x["status"]for x in result["ownerResults"]],["UNKNOWN","UNKNOWN"])
    self.assertEqual(self.n.reached,set())
    self.assertEqual(result["batchReportEvidence"],{})
    self.assertTrue(result["batchReportCleanup"]["retained"])

 def test_unknown_process_closure_retains_reports_without_execution_claim(self):
  for mode in("leaderJoined","rootSessionObserved","sessionCensusComplete","stillLiveGroups"):
   with self.subTest(mode=mode):
    def change(result):result["descendantCleanup"][mode]=None
    result,_=self.invoke(result_change=change)
    self.assertEqual([x["execution"]for x in result["ownerResults"]],["UNKNOWN","UNKNOWN"])
    self.assertEqual(self.n.reached,set())
    self.assertEqual(result["batchReportEvidence"],{})

 def test_native_invocation_or_merge_unjoined_completion_refuses(self):
  for mode in("invocation","merge"):
   with self.subTest(mode=mode):
    def change(kind,data,i):
     if kind=="index":
      outcome=data["merge"]if mode=="merge"else data["entries"][0]["attempts"][0]["outcome"]
      outcome["groupJoined"]=False
    result=self.refused(change)
    self.assertNotIn("PASS",[x["status"]for x in result["ownerResults"]])

 def test_deadline_expires_during_read_keeps_originals_and_has_no_pass(self):
  original=self.n.remaining
  def expire(end,**kwargs):
   if len(self.deadline_calls)>=4:raise subprocess.TimeoutExpired("same owner deadline",0)
   return original(end,**kwargs)
  with patch.object(self.n,"remaining",side_effect=expire):result,_=self.invoke()
  self.assertEqual([x["status"]for x in result["ownerResults"]],["UNKNOWN","UNKNOWN"])
  self.assertEqual(self.n.reached,set())
  self.assertTrue(result["batchReportCleanup"]["retained"])

 def test_deadline_expires_before_cleanup_retains_reports_and_removes_pass(self):
  original=self.n.remaining
  def expire(end,**kwargs):
   if kwargs.get("phase")=="batch report cleanup":raise subprocess.TimeoutExpired("same owner cleanup deadline",0)
   return original(end,**kwargs)
  with patch.object(self.n,"remaining",side_effect=expire):result,_=self.invoke()
  self.assertEqual([x["status"]for x in result["ownerResults"]],["UNKNOWN","UNKNOWN"])
  self.assertTrue(self.n.cancel)
  self.assertFalse(result["batchReportCleanup"]["removed"])
  self.assertTrue(Path(result["batchReportCleanup"]["directory"]).is_dir())
  self.assertNotIn("batchEvidence",result)

 def test_oversized_report_set_refuses_with_bounded_read(self):
  original=self.write_report_set
  def oversized(raw,*args):
   code,text=original(raw,*args);directory=Path(text.split(": ",1)[1].strip())
   (directory/"index.json").write_bytes(b" "*(4*1024**2+1));return code,text
  with patch.object(self,"write_report_set",side_effect=oversized):result=self.refused()
  self.assertIn("oversized",result["reportFailure"])

 def test_malformed_index_and_boolean_completion_metadata_refuse(self):
  for mode in("entry","attempt","invocation","acceptedAttempt","outcome","endedCount"):
   with self.subTest(mode=mode):
    def change(kind,data,i):
     if kind=="index":
      entry=data["entries"][0]
      if mode=="entry":data["entries"][0]=[]
      elif mode=="attempt":entry["attempts"][0]=[]
      elif mode=="invocation":entry["invocation"]=True
      elif mode=="acceptedAttempt":entry["acceptedAttempt"]=True
      elif mode=="outcome":entry["attempts"][0]["outcome"]["code"]=False
     elif kind=="capture"and i==1 and mode=="endedCount":data["ended"]["unhandledErrors"]=False
    self.refused(change)

 def test_contradictory_worker_target_output_and_project_identity_refuse(self):
  for mode in("captureWorker","indexWorker","targets","blob","root","config","projectRoot","modulePool","captureOutput","reporter"):
   with self.subTest(mode=mode):
    def change(kind,data,i):
     if kind=="index":
      entry=data["entries"][0]
      if mode=="indexWorker":entry["args"]=[x.replace("maxWorkers=1","maxWorkers=8")for x in entry["args"]]
      elif mode=="targets":entry["includePatterns"]=["src/unrequested.test.ts"]
      elif mode=="blob":entry["attempts"][0]["blob"]="/tmp/unowned-blob.json"
      elif mode=="config":entry["config"]="/tmp/unowned.config.ts"
     elif kind=="capture"and i==1:
      if mode=="captureWorker":data["command"]=[x.replace("maxWorkers=1","maxWorkers=8")for x in data["command"]]
      elif mode=="root":data["root"]="/tmp/unowned-source"
      elif mode=="projectRoot":data["projects"][0]["root"]="/tmp/unowned-source"
      elif mode=="modulePool":data["modules"][0]["pool"]="unrelated-pool"
      elif mode=="captureOutput":data["command"]=[x.replace("--outputFile.json=","--outputFile.json=/tmp/unowned/")for x in data["command"]]
      elif mode=="reporter":data["command"].append("--reporter=/tmp/unowned-custom-reporter.mts")
    result=self.refused(change)
    self.assertEqual(self.n.reached,set())

 def test_explicit_argv_targets_and_child_project_config_are_supported(self):
  def change(kind,data,i):
   if kind=="index":
    for entry,path in zip(data["entries"],PATHS):entry["includePatterns"]=None;entry["args"].append(path)
  result,_=self.invoke(change=change)
  self.assertEqual([x["status"]for x in result["ownerResults"]],["PASS","PASS"])

 def test_resource_successor_interface_is_required_and_real_budgeted_run_supplies_bound(self):
  native.Native.remaining(self.n,self.n.end,cancel=True,phase="batch report interface")
  pid=123456789;alive=[True];polls=[None,1]
  def poll():
   value=polls.pop(0)if polls else 1
   if value is not None:alive[0]=False
   return value
  child=SimpleNamespace(pid=pid,poll=poll,wait=lambda **kwargs:1)
  root={"pid":pid,"parent":1,"group":pid,"session":pid,"start":1,"state":"S"}
  def record(value,dead=False):return root if dead or alive[0]else None
  def census(argv,**kwargs):return ""if "sid"in argv[-1]else f"{pid} 1 0\n"
  def launch(argv,**kwargs):
   raw=Path(next(x.split("=",1)[1]for x in argv if x.startswith("--outputFile=")))
   _,text=self.write_report_set(raw,failed=True);kwargs["stdout"].write(text.encode());return child
  with patch.object(native.subprocess,"Popen",side_effect=launch),patch.object(native.subprocess,"check_output",side_effect=census),patch.object(native,"process",side_effect=record),patch.object(native.time,"sleep"),patch.object(self.n,"disk"),patch.object(self.n,"dispose_cache"),patch.object(self.n,"source_snapshot"),contextlib.redirect_stdout(io.StringIO()):self.n.test_many(PATHS)
  result=self.n.c[-1]
  self.assertEqual(result["exit"],1)
  self.assertTrue(native.batch_closed(result))
  self.assertEqual([x["status"]for x in result["ownerResults"]],["FAIL","PASS"])
  bound=result["deadline"]["ownerEndMonotonic"]
  self.assertTrue(all(end==bound for end,phase in self.deadline_calls if phase.startswith("batch report")))

 def test_unhandled_error_or_suite_error_refuses(self):
  for field in("unhandledErrors","suiteErrors"):
   with self.subTest(field=field):
    def change(kind,data,i):
     if kind=="capture"and i==1:data["ended"][field]=1
    self.refused(change)

 def test_exact_report_destination_and_original_path_required(self):
  for field in("requested","aggregate","original"):
   with self.subTest(field=field):
    def change(kind,data,i):
     if kind=="index":
      if field=="original":data["entries"][0]["attempts"][0]["json"]="/tmp/unowned-report.json"
      else:data[field]="/tmp/unowned-report.json"
    self.refused(change)

 def test_capture_module_overlap_or_unknown_file_refuses(self):
  for field in("taskId","file"):
   with self.subTest(field=field):
    def change(kind,data,i):
     if kind=="capture"and i==2:data["modules"][0][field]="task-1"if field=="taskId"else str(self.source/"src/unknown.test.ts")
    self.refused(change)

 def test_skip_missing_file_and_false_native_counts_refuse(self):
  for mode in("skip","missing","overlap","counts"):
   with self.subTest(mode=mode):
    def change(kind,data,i):
     if kind=="aggregate":
      if mode=="skip":data["testResults"][0]["assertionResults"][0]["status"]="pending"
      elif mode=="missing":data["testResults"].pop()
      elif mode=="overlap":data["testResults"].append(copy.deepcopy(data["testResults"][0]))
      else:data["numPassedTests"]=True
    self.refused(change)

 def test_single_target_keeps_existing_single_owner_entrypoint(self):
  with patch.object(self.n,"test")as test:self.n.test_many([PATHS[0]])
  test.assert_called_once_with(PATHS[0])

 def test_unsafe_set_or_symlink_index_is_not_read(self):
  for mode in("directory","index"):
   with self.subTest(mode=mode):
    original=self.write_report_set
    def substituted(raw,*args):
     code,text=original(raw,*args);directory=Path(text.split(": ",1)[1].strip())
     if mode=="directory":return code,"[test] native report set: /tmp/unowned-reports\n"
     target=directory/"index.json";rawindex=target.read_bytes();target.unlink();outside=self.root/"outside-index.json";outside.write_bytes(rawindex);target.symlink_to(outside)
     return code,text
    with patch.object(self,"write_report_set",side_effect=substituted):self.refused()

 def test_execute_groups_positive_owners_once_and_keeps_inventory_and_negative_isolated(self):
  mf=json.loads((HERE/"manifest.json").read_text())
  pins=json.loads((HERE/"native-inputs.json").read_text())
  tooling=self.n.t;tooling.mkdir()
  for path,want in pins["fixtures"].items():
   for base,data in((tooling,b"fixture"),(self.source,b"fixture-base")):
    if base==self.source and path not in pins["fixtureBaseHashes"]:continue
    file=base/path;file.parent.mkdir(parents=True,exist_ok=True);file.write_bytes(data)
  cli=self.source/"extensions/workboard/src/cli.ts";cli.write_bytes(b"fixed")
  event={"repository":{"private":False}};single=[];batches=[]
  paths=[f"path-{i}"for i in range(42)]
  def fake_read(path):
   if str(path).endswith("native-inputs.json"):return pins
   if str(path).endswith("manifest.json"):return mf
   return event
  def fake_git(root,*args):
   if args==("rev-parse","HEAD"):return ("a"*40 if root==tooling else mf["source"]["commit"]).encode()
   if "--name-only"in args:return "\n".join(paths).encode()
   if args[:1]==("status",):return b""
   return b"source-patch"
  def fake_sha(data):
   if data==b"fixed":return native.NEW
   if data==b"source-patch":return native.PATCH
   if data==b"manifest":return pins["manifestSha256"]
   if data==b"fixture":return next(iter(pins["fixtures"].values()))
   if data==b"fixture-base":return next(iter(pins["fixtureBaseHashes"].values()))
   if data==b"{}"or data.startswith(b'{"'):return pins["dependencyFingerprint"]
   return hashlib.sha256(data).hexdigest()
  # Admission is separately source-pinned; this test exercises dispatch ownership.
  for field in("dependencyPaths",):pins[field]=[]
  firstfixture=next(iter(pins["fixtures"].values()));firstbase=next(iter(pins["fixtureBaseHashes"].values()))
  pins["fixtures"]={p:firstfixture for p in pins["fixtures"]};pins["fixtureBaseHashes"]={p:firstbase for p in pins["fixtureBaseHashes"]}
  for path,want in getattr(native,"BATCH_REPORT_SOURCES",{}).items():
   file=self.source/path;file.parent.mkdir(parents=True,exist_ok=True);file.write_bytes(path.encode())
  if hasattr(native,"BATCH_REPORT_SOURCES"):
   expected=native.BATCH_REPORT_SOURCES;original_sha=fake_sha
   def fake_sha(data):
    key=data.decode(errors="ignore")
    return expected[key]if key in expected else original_sha(data)
  manifest=tooling/"scripts/fork-release/manifest.json";manifest.parent.mkdir(parents=True);manifest.write_bytes(b"manifest")
  (manifest.parent/"native-inputs.json").write_text(json.dumps(pins))
  def run(name,*args,**kwargs):
   if name=="changed-plan":return {"exit":0,"reason":None},"[check:changed:dry-run] would run: pnpm tsgo:core\n"
   return {"exit":0,"reason":None,"plannerReached":1,"plannerCommands":[{"status":0}]},""
  def test_one(path,old=False):
   single.append((path,old,cli.read_bytes(),dict(self.n.expected)))
  def test_many(paths):batches.append(list(paths))
  env={"GITHUB_REPOSITORY":"fr-meyer/openclaw","GITHUB_REF":native.REF,"GITHUB_EVENT_NAME":"push","GITHUB_ACTOR":"fr-meyer","GITHUB_RUN_ATTEMPT":"1","GITHUB_RUN_ID":"fixture-run","GITHUB_SHA":"a"*40,"GITHUB_WORKFLOW_SHA":"a"*40,"GITHUB_EVENT_PATH":"event"}
  fake_version="24.21.0/linux/x64\n"
  def check_output(argv,**kwargs):return b""if argv[0]=="git"else fake_version
  with patch.dict(os.environ,env),patch.object(native,"read",side_effect=fake_read),patch.object(native,"git",side_effect=fake_git),patch.object(native,"sha",side_effect=fake_sha),patch.object(native,"before",return_value=b"old"),patch.object(native.shutil,"disk_usage",return_value=type("Free",(),{"free":12*native.GIB})()),patch.object(native.subprocess,"check_output",side_effect=check_output),patch.object(self.n,"source_snapshot",return_value={"complete":True,"unexpectedPaths":[]}),patch.object(self.n,"disk"),patch.object(self.n,"run",side_effect=run),patch.object(self.n,"test",side_effect=test_one),patch.object(self.n,"node_contracts"),patch.object(self.n,"test_many",side_effect=test_many,create=True):
   package=self.source/"package.json";package.write_text(json.dumps({"packageManager":pins["packageManager"]}))
   # read(package.json) must keep the pinned package-manager admission live.
   saved_read=fake_read
   def read_with_package(path):return {"packageManager":pins["packageManager"]}if str(path).endswith("package.json")else saved_read(path)
   with patch.object(native,"read",side_effect=read_with_package),patch.object(native.SandboxAccounting,"admit"):
    self.n.execute()
  self.assertEqual(len(self.n.planned),44)
  self.assertEqual(len(single),2,"all positive owners must share source-owned batches")
  self.assertEqual(single[0][0],native.CI_INVENTORY)
  self.assertEqual(single[0][3],{},"inventory must run before overlays")
  self.assertTrue(single[1][1]);self.assertEqual(single[1][2],b"old")
  self.assertEqual(cli.read_bytes(),b"fixed");self.assertEqual(self.n.expected,{})
  positives=[p for batch in batches for p in batch]
  expected={stage[len("vitest:"):]for stage in self.n.planned if stage.startswith("vitest:")and stage!="vitest:"+native.CI_INVENTORY}
  self.assertEqual(len(positives),len(set(positives)))
  self.assertEqual(set(positives),expected)
  self.assertEqual([len(x)for x in batches],[8,8,8,4])

class OfflineInclusion(unittest.TestCase):
 @staticmethod
 def ids(suite):
  ids=[]
  for child in suite:ids.extend(OfflineInclusion.ids(child)if isinstance(child,unittest.TestSuite)else[child.id()])
  return ids

 def expected(self):
  import test_native,test_native_batches,test_native_sandbox
  modules=(test_native,test_native_batches,test_native_sandbox);expected=[]
  for module in modules:
   for value in vars(module).values():
    if isinstance(value,type)and issubclass(value,unittest.TestCase):
     expected.extend(f"{module.__name__}.{value.__name__}.{name}"for name in unittest.TestLoader().getTestCaseNames(value))
  return expected

 def assert_inventory(self,suite):
  ids=self.ids(suite)
  self.assertEqual(len(ids),len(set(ids)),"native and batch controls must load once")
  self.assertEqual(set(ids),set(self.expected()))

 def test_explicit_native_module_includes_all_batch_controls_once(self):
  import test_native
  self.assert_inventory(unittest.TestLoader().loadTestsFromModule(test_native))

 def test_discovery_includes_all_native_and_batch_controls_once(self):
  self.assert_inventory(unittest.TestLoader().discover(str(HERE),pattern="test_native*.py"))

if __name__=="__main__":unittest.main()

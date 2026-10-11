"""Offline proof of the aggregate cap, exclusion refusals and custody retention."""
import contextlib,io,json,os,subprocess,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import native
from native_sandbox import IMAGE,SandboxAccounting,covering_roots,private_record
from test_native import NativeFixture,HERE

class SandboxAccountingTests(NativeFixture):
 def setUp(self):
  super().setUp();self.a=SandboxAccounting(self.n)
  self.engine_root=self.root/"engine";self.engine_root.mkdir()
  self.content_root=self.root/"content";self.content_root.mkdir()
  self.a.roots=[self.engine_root,self.content_root];self.a.engine_id="engine-one"
  socket=patch.object(self.a,"socket_identity",return_value={"path":"/run/docker.sock","device":1,"inode":2});socket.start()
  self.addCleanup(patch.stopall)

 def record(self,phase="held",**extra):
  self.a.record.write_text(json.dumps({"format":1,"engineId":"engine-one","phase":phase,**extra}))
  self.a.record.chmod(0o600)

 def disk_scan(self,used=100,stderr="",code=0):
  roots=covering_roots([self.source,self.n.w,*self.a.roots])
  return subprocess.CompletedProcess([],code,"".join(f"{used if root==self.engine_root else 0}\t{root}\n"for root in roots),stderr)

 def test_full_engine_and_containerd_roots_are_charged_with_no_cross_mount_exclusion(self):
  self.n.sandbox=self.a
  with patch.object(native.subprocess,"run",return_value=self.disk_scan(used=10*native.GIB+1))as command:
   with self.assertRaisesRegex(RuntimeError,"budget exceeded"):self.n.disk()
  args=command.call_args.args[0]
  self.assertEqual(args[1],"-s")
  self.assertIn(str(self.engine_root),args);self.assertIn(str(self.content_root),args)
  self.assertEqual(self.n.r["lastDiskSnapshot"]["taskBytes"],10*native.GIB+1)
  self.assertNotIn(str(self.engine_root),json.dumps(self.n.r))
  self.assertTrue(self.n.r["diskAccounting"]["sampledNotQuota"])

 def test_aliases_and_nested_content_roots_are_charged_once_without_baseline_subtraction(self):
  self.a.roots=[self.engine_root,self.engine_root,self.engine_root/"nested"]
  self.n.sandbox=self.a
  with patch.object(native.subprocess,"run",return_value=self.disk_scan(used=123))as command:self.n.disk()
  self.assertEqual(command.call_args.args[0].count(str(self.engine_root)),1)
  self.assertEqual(self.n.r["lastDiskSnapshot"]["taskBytes"],123)

 def test_permission_and_partial_traversal_errors_refuse_without_retry_or_path_disclosure(self):
  self.n.sandbox=self.a
  for code,stderr in((1,"Permission denied: "+str(self.engine_root)),(0,"cannot access staging")):
   with self.subTest(code=code),patch.object(native.subprocess,"run",return_value=self.disk_scan(stderr=stderr,code=code))as command:
    with self.assertRaisesRegex(RuntimeError,"footprint unreadable"):self.n.disk()
    self.assertEqual(command.call_count,1)
  self.assertNotIn(str(self.engine_root),json.dumps(self.n.r))

 def test_unknown_containerd_root_is_refused_before_any_allocation(self):
  info=self.info()
  processes={1:("one",["dockerd"]),2:("two",["containerd"])}
  with patch("native_sandbox.os.uname",return_value=SimpleNamespace(sysname="Linux")),patch.object(self.a,"engine",return_value=json.dumps(info))as engine,patch.object(self.a,"processes",return_value=processes),patch.object(self.a,"daemon_temp",return_value=self.engine_root),patch.object(Path,"read_text",return_value="1 2 3 4 5 6 - overlay lower\n"):
   with self.assertRaisesRegex(RuntimeError,"content root unknown"):self.a.admit(self.n.end)
  self.assertEqual(engine.call_count,1)
  self.assertFalse(self.a.admission.exists());self.assertFalse(self.a.record.exists())

 def info(self,**extra):return {"ID":"engine-one","OSType":"linux","Architecture":"x86_64","LoggingDriver":"local","Driver":"overlay2","DockerRootDir":str(self.engine_root),"ServerVersion":"28.0.4","DriverStatus":[["Backing Filesystem","extfs"],["Supports d_type","true"]],**extra}

 def engine_admission(self,info=None,disk=None):
  processes={1:("one",["dockerd"]),2:("two",["containerd","--root",str(self.content_root)])}
  self.n.r["lastDiskSnapshot"]={"taskBytes":100,"roots":[{"freeBytes":6*native.GIB}]}
  def sample(owned,end):self.n.r["sandboxMemoryAccounting"]={"totalBytes":100}
  def read(path,*args,**kwargs):return "MemAvailable: 2097152 kB\n"if path==Path("/proc/meminfo")else"1 2 3 4 5 6 - overlay lower\n"
  def engine(args,end):return json.dumps(info or self.info())if args[0]=="info"else"--input --quiet"
  with patch("native_sandbox.os.uname",return_value=SimpleNamespace(sysname="Linux")),patch.object(self.a,"engine",side_effect=engine)as command,patch.object(self.a,"processes",return_value=processes),patch.object(self.a,"daemon_temp",return_value=self.engine_root),patch.object(Path,"read_text",read),patch.object(self.a,"sample",side_effect=sample),patch.object(self.n,"disk",side_effect=disk)as scan:
   self.a.admit(self.n.end)
  return command,scan

 def test_early_full_accounting_admission_pins_roots_before_any_image_operation(self):
  command,scan=self.engine_admission()
  self.assertEqual(self.a.roots,covering_roots([self.engine_root,self.content_root]));scan.assert_called_once()
  self.assertTrue(all(call.args[0][:2]!=["image","inspect"]for call in command.call_args_list))
  self.assertEqual(self.n.r["sandboxAdmission"]["status"],"engine-accounting-readable");self.assertFalse(self.a.admission.exists());self.assertFalse(self.a.image_record.exists())

 def test_unreadable_engine_footprint_refuses_under_existing_authority_without_retry(self):
  for error in(PermissionError("private root"),RuntimeError("engine/task footprint unreadable")):
   with self.subTest(error=type(error).__name__):
    self.a.env["DOCKER_CONFIG"]=str(self.n.w/type(error).__name__)
    with self.assertRaisesRegex(RuntimeError,"ENGINE_ACCOUNTING_UNREADABLE_UNDER_EXISTING_RUNNER_AUTHORITY"):self.engine_admission(disk=error)
    self.assertFalse(self.a.admission.exists());self.assertFalse(self.a.image_record.exists())

 def test_unreviewed_snapshotter_or_loader_version_refuses_before_traversal_and_network(self):
  for extra in({"Driver":"overlayfs"},{"ServerVersion":"29.0.0"},{"DriverStatus":[["driver-type","io.containerd.snapshotter.v1"]]}):
   with self.subTest(extra=extra):
    self.a.env["DOCKER_CONFIG"]=str(self.n.w/str(len(list(self.n.w.iterdir()))))
    with self.assertRaisesRegex(RuntimeError,"LOADER_CONTRACT_UNREVIEWED"):self.engine_admission(self.info(**extra))
    self.assertFalse(self.a.image_record.exists())

 def test_import_disk_reserve_refuses_before_image_transfer(self):
  def disk():self.n.r["lastDiskSnapshot"]={"taskBytes":8*native.GIB,"roots":[{"freeBytes":6*native.GIB}]}
  with self.assertRaisesRegex(RuntimeError,"IMAGE_STAGING_AND_IMPORT_RESERVE_UNAVAILABLE"):self.engine_admission(disk=disk)
  self.assertFalse(self.a.image_record.exists())

 def test_daemon_temp_follows_reviewed_initial_env_and_ignores_mutated_tmpdir(self):
  temporary=self.root/"daemon-temp";temporary.mkdir();default=self.engine_root/"tmp";default.mkdir()
  for raw,want in((b"PATH=/usr/bin\0TMPDIR=/wrong\0",default),(os.fsencode("DOCKER_TMPDIR="+str(temporary))+b"\0TMPDIR=/wrong\0",temporary)):
   with patch.object(Path,"open",return_value=io.BytesIO(raw)):self.assertEqual(self.a.daemon_temp(1,self.engine_root),want)
  with patch.object(Path,"open",return_value=io.BytesIO(b"DOCKER_TMPDIR=/one\0DOCKER_TMPDIR=/two\0")):
   with self.assertRaisesRegex(RuntimeError,"TEMP_AMBIGUOUS"):self.a.daemon_temp(1,self.engine_root)

 def test_final_image_disk_probe_shares_phase_deadline_and_restores_outer_owner(self):
  from native_sandbox import CONFIG
  self.a.socket=self.a.socket_identity();self.n.r["sandboxAdmission"]={"status":"engine-accounting-readable"}
  self.a.image_record.write_text(json.dumps({"format":1,"phase":"confirmed","engineId":"engine-one","image":IMAGE,"runtimeImage":CONFIG,"registryOriginVerified":True,"imported":True,"transport":{}}));self.a.image_record.chmod(0o600)
  end=self.n.work_end-10;previous=self.n.command_end
  def disk():self.assertEqual(self.n.command_end,min(previous,end))
  with patch.object(self.n,"run",return_value=({"exit":0,"reason":None},"")),patch.object(self.n,"disk",side_effect=disk)as scan,patch.object(self.a,"sample")as sample:
   self.a.prepare_image(end)
  scan.assert_called_once();self.assertEqual(sample.call_args.args[1],end);self.assertEqual(self.n.command_end,previous)

 def memory(self,groups,contents,owned):
  processes={1:("one",["dockerd"]),2:("two",["containerd"])};self.a.identities=processes
  def read(path,*args,**kwargs):
   if path==Path("/proc/self/statm"):return "100 1"
   return str(contents[path])
  with patch.object(self.a,"engine",return_value="engine-one\n"),patch.object(self.a,"processes",return_value=processes),patch("native_sandbox.cgroup",side_effect=lambda pid:groups[pid]),patch.object(Path,"read_text",read),patch.object(Path,"resolve",lambda p:p):
   self.a.sample(owned,self.n.end)

 def test_encompassing_cgroups_include_daemon_container_cache_and_tmpfs_without_double_counting(self):
  root=Path("/sys/fs/cgroup/engine");task=Path("/sys/fs/cgroup/task")
  self.memory({1:root,2:root/"containerd",3:root/"guest",os.getpid():task},{root/"memory.current":12*native.GIB-os.sysconf("SC_PAGE_SIZE")},{3:{"rss":200*native.GIB}})
  self.assertEqual(self.n.r["sandboxMemoryAccounting"]["totalBytes"],12*native.GIB)
  self.assertEqual(self.n.r["sandboxMemoryAccounting"]["chargedCgroups"],1)
  self.assertFalse(self.n.r["sandboxMemoryAccounting"]["baselineSubtracted"])

 def test_disjoint_process_rss_and_daemon_cgroup_memory_share_the_same_cap(self):
  a=Path("/sys/fs/cgroup/docker");b=Path("/sys/fs/cgroup/containerd");task=Path("/sys/fs/cgroup/task")
  with self.assertRaisesRegex(RuntimeError,"aggregate.*budget exceeded"):
   self.memory({1:a,2:b,3:task,os.getpid():task},{a/"memory.current":6*native.GIB,b/"memory.current":6*native.GIB},{3:{"rss":1}})
  self.assertGreater(self.n.r["peakAggregateMemoryBytes"],12*native.GIB)

 def test_unread_or_malformed_cgroup_charge_is_unknown_not_zero(self):
  root=Path("/sys/fs/cgroup/engine")
  for charge in("unknown","-1"):
   with self.subTest(charge=charge),self.assertRaisesRegex(RuntimeError,"memory accounting unreadable"):
    self.memory({1:root,2:root,os.getpid():root},{root/"memory.current":charge},{})

 def test_partial_creation_without_physical_id_is_not_accounted_as_an_empty_sandbox(self):
  self.record("creating")
  processes={1:("one",["dockerd"]),2:("two",["containerd"])};self.a.identities=processes
  with patch.object(self.a,"engine",return_value="engine-one\n"),patch.object(self.a,"processes",return_value=processes),patch("native_sandbox.cgroup",return_value=Path("/sys/fs/cgroup/engine")):
   with self.assertRaisesRegex(RuntimeError,"partial allocation footprint unknown"):self.a.sample({},self.n.end)

 def test_failed_retirement_retains_command_cache_after_all_owned_processes_have_joined(self):
  self.record("held",id="a"*64);self.n.sandbox=self.a
  cache=self.n.w/"vitest-1";cache.mkdir();st=cache.stat();parent=self.n.w.stat()
  result={"descendantCleanup":{"stillLiveGroups":0,"leaderJoined":True,"sessionCensusComplete":True,"rootSessionObserved":True},"reason":None}
  with patch.object(native.subprocess,"run")as removal:self.n.dispose_cache(cache,(st.st_dev,st.st_ino),(parent.st_dev,parent.st_ino),result)
  removal.assert_not_called();self.assertTrue(cache.exists());self.assertFalse(result["cacheCleanup"]["removed"])
  self.assertIn("retirement unconfirmed",result["reason"])

 def test_private_recovery_is_not_public_and_insecure_record_modes_refuse(self):
  self.record("held",id="a"*64,workspace="/private/work",entry={"containerName":"native-private","sessionKey":"private-session"})
  text=self.a.sanitize("a"*64+" /private/work native-private private-session engine-one")
  for value in("a"*64,"/private/work","native-private","private-session","engine-one"):self.assertNotIn(value,text)
  self.a.record.chmod(0o644)
  with self.assertRaisesRegex(RuntimeError,"private runtime record admission"):private_record(self.a.record)

 def test_cancelled_supervisor_waits_within_the_fixture_reserve_and_keeps_retirement_with_its_owner(self):
  self.record("allocated",id="a"*64);self.n.sandbox=self.a;self.n.cancel=True
  for owner_end,want in((300,120),(100,40)):
   process=SimpleNamespace(poll=lambda:None,wait=lambda **kwargs:None)
   self.n.p=process
   with self.subTest(owner_end=owner_end),patch.object(process,"wait",side_effect=subprocess.TimeoutExpired("fixture",want))as wait,patch.object(native.time,"monotonic",return_value=0),patch.object(native,"kill")as kill,patch.object(native.subprocess,"run")as engine:
    self.n.runtime_closure(owner_end)
   self.assertEqual(wait.call_args.kwargs["timeout"],want)
   kill.assert_not_called();engine.assert_not_called()
   self.assertEqual(private_record(self.a.record)["phase"],"allocated")

 def test_confirmed_retirement_does_not_spend_another_runtime_closure_window(self):
  self.record("retired");self.n.sandbox=self.a
  process=SimpleNamespace(poll=lambda:None,wait=lambda **kwargs:None);self.n.p=process
  with patch.object(process,"wait")as wait:self.n.runtime_closure(self.n.end)
  wait.assert_not_called()

 def test_socket_replacement_refuses_before_contacting_another_engine(self):
  self.a.socket={"path":"/run/docker.sock","device":1,"inode":3}
  with patch.object(native.subprocess,"run")as command:
   with self.assertRaisesRegex(RuntimeError,"socket changed"):self.a.engine(["info"],self.n.end)
  command.assert_not_called()

 def test_accounting_exception_is_redacted_before_receipt_reason_and_stdout(self):
  private="/private/engine-root"
  redact=lambda text:text.replace(private,"[private native runtime]")
  child=SimpleNamespace(pid=99999991,status=None)
  child.poll=lambda:child.status
  def joined(**kwargs):child.status=0;return 0
  child.wait=joined
  root={"pid":child.pid,"group":child.pid,"session":child.pid,"start":1}
  def killed(*args):child.status=0
  def sample(*args):raise PermissionError(13,"Permission denied",private+"/memory.current")
  self.n.started,self.n.end,self.n.work_end=0,1000,805
  self.n.sandbox=SimpleNamespace(sample=sample,observation=lambda:{"phase":"retired"},sanitize=redact)
  capture=io.StringIO()
  with contextlib.redirect_stdout(capture),patch.object(native.time,"monotonic",return_value=0),patch.object(native.subprocess,"Popen",return_value=child),patch.object(native.subprocess,"check_output",return_value=f"{child.pid} 1 1\n"),patch.object(native,"process",side_effect=lambda *args,**kwargs:root if child.status is None or kwargs.get("dead") else None),patch.object(native,"identity",side_effect=lambda *args:(child.pid,1)if child.status is None else None),patch.object(native,"kill",side_effect=killed),patch.object(self.n,"closure_groups",return_value=set()),patch.object(self.n,"dispose_cache"),patch.object(self.n,"source_snapshot"),patch.object(native,"PRIVATE_REDACTOR",redact):
   result,_=self.n.run("privacy-control",["fake-never-executed-command"])
  self.assertNotIn(private,result["reason"])
  self.assertNotIn(private,json.dumps(self.n.r))
  self.assertNotIn(private,capture.getvalue())
  self.assertIn("[private native runtime]",result["reason"])

 def test_final_receipt_boundary_redacts_all_nested_errors_or_withholds_unknown_recovery(self):
  self.record("held",id="a"*64,workspace="/private/work")
  value={"failures":[PermissionError(13,"denied","/sys/fs/cgroup/unrecorded/memory.current").__str__()],"commands":[{"reason":"a"*64+" /private/work engine-one"}]}
  with patch.object(native,"PRIVATE_REDACTOR",self.a.sanitize):
   text=json.dumps(native.public_data(value))
  for private in("a"*64,"/private/work","engine-one","/sys/fs/cgroup/unrecorded"):
   self.assertNotIn(private,text)
  self.a.record.chmod(0o644)
  with patch.object(native,"PRIVATE_REDACTOR",self.a.sanitize):
   text=json.dumps(native.public_data(value))
  self.assertNotIn("/sys/fs/cgroup/unrecorded",text)
  self.assertIn("diagnostic withheld",text)

 def test_final_mount_proof_checks_selected_graph_paths_and_keeps_shared_layers(self):
  paths=["/engine/selected/merged","/engine/selected/diff","/engine/selected/work"]
  self.record("retired",id="a"*64,mountPaths=paths)
  processes={1:("10",["dockerd"]),2:("20",["containerd"])}
  original=Path.read_text
  for mounted in(True,False):
   def read(file,*args,**kwargs):
    if str(file).startswith("/proc/"):return paths[0]if mounted else"/engine/shared-image/diff"
    return original(file,*args,**kwargs)
   with self.subTest(mounted=mounted),patch.object(self.a,"sample"),patch.object(self.a,"processes",return_value=processes),patch.object(Path,"read_text",read):
    if mounted:
     with self.assertRaisesRegex(RuntimeError,"mounts still present"):self.a.assert_retired(self.n.end)
     self.assertNotIn("sandboxRetirement",self.n.r)
    else:self.a.assert_retired(self.n.end)
  self.assertTrue(self.n.r["sandboxRetirement"]["mountsSettled"])

class SandboxFixtureControls(unittest.TestCase):
 def test_executable_fixture_failure_controls_are_included_by_the_native_self_test_owner(self):
  result=subprocess.run(["node","--experimental-strip-types","--test",str(HERE/"test_native_sandbox.mjs")],capture_output=True,text=True,timeout=5)
  self.assertEqual(result.returncode,0,result.stdout+result.stderr)
  self.assertRegex(result.stdout,r"(?:# |ℹ )tests 16")

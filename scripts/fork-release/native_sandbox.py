"""Sampled external-engine accounting for the one existing native fixture owner."""
import json,os,re,stat,subprocess,time,tomllib
from pathlib import Path
from release import need
from native_image import CONFIG,STAGING,UNPACKED

IMAGE="docker.io/library/python@sha256:f040863673aea2570c3ff6a5c3fb4c673a016cbc5375005ad145915922b6b78a"
HOST="unix:///var/run/docker.sock"
ENGINES={"dockerd","containerd","containerd-shim-runc-v2"}
IMAGE_RESERVE=3*1024**3

def covering_roots(roots):
 """Charge encompassing roots once; never subtract pre-existing host content."""
 roots=sorted(set(roots),key=lambda p:(len(p.parts),str(p)))
 return [p for i,p in enumerate(roots)if not any(p.is_relative_to(q)for q in roots[:i])]

def cgroup(pid):
 text=Path(f"/proc/{pid}/cgroup").read_text()
 match=re.fullmatch(r"0::(/[^\n]*)\n",text)
 need(match is not None and ".."not in Path(match[1]).parts,"unified process cgroup unavailable")
 return Path("/sys/fs/cgroup")/match[1].lstrip("/")

def private_record(path):
 st=path.lstat()
 need(stat.S_ISREG(st.st_mode)and path.resolve()==path and st.st_size<=65536 and st.st_uid==os.getuid()and stat.S_IMODE(st.st_mode)==0o600,"private runtime record admission differs")
 value=json.loads(path.read_bytes())
 need(isinstance(value,dict)and value.get("format")==1,"private runtime record malformed")
 return value

class SandboxAccounting:
 def __init__(self,native):
  self.n=native;self.roots=[];self.root_marks={};self.identities={};self.engine_id=None;self.groups=set();self.socket=None
  self.record=native.w/"native-sandbox-recovery.json"
  self.admission=native.w/"native-sandbox-admission.json"
  self.image_record=native.w/"native-image-custody.json"
  self.image_staging=native.w/"native-image-staging"
  self.env={**native.env,"DOCKER_HOST":HOST,"DOCKER_CONFIG":str(native.w/"docker-config")}

 def socket_identity(self):
  path=Path("/var/run/docker.sock").resolve(strict=True);st=path.stat()
  need(stat.S_ISSOCK(st.st_mode),"local Docker socket unavailable")
  need(st.st_dev<2**53 and st.st_ino<2**53,"socket identity exceeds fixture integer precision")
  return {"path":str(path),"device":st.st_dev,"inode":st.st_ino}

 def engine(self,args,end):
  if self.socket:need(self.socket_identity()==self.socket,"admitted engine socket changed")
  result=subprocess.run(["docker","--host",HOST,*args],text=True,capture_output=True,env=self.env,timeout=min(5,self.n.remaining(end,cancel=False,phase="engine observation")))
  self.n.remaining(end,cancel=False,phase="engine observation")
  if self.socket:need(self.socket_identity()==self.socket,"admitted engine socket changed")
  need(not result.returncode and not result.stderr and len(result.stdout)<=65536,"native engine observation unavailable")
  return result.stdout

 def processes(self,end):
  result={}
  for directory in Path("/proc").iterdir():
   self.n.remaining(end,cancel=False,phase="engine census")
   if not directory.name.isdecimal():continue
   try:
    argv=(directory/"cmdline").read_bytes().split(b"\0")
    if not argv or Path(os.fsdecode(argv[0])).name not in ENGINES:continue
    need(len(argv)<=256 and sum(map(len,argv))<=8192,"engine process command exceeds bound")
    fields=(directory/"stat").read_text().rsplit(") ",1)[1].split()
    result[int(directory.name)]=(fields[19],[os.fsdecode(x)for x in argv if x])
   except FileNotFoundError:continue
  need(result and any(Path(v[1][0]).name=="dockerd"for v in result.values())and any(Path(v[1][0]).name=="containerd"for v in result.values()),"complete local engine census unavailable")
  return result

 def daemon_temp(self,pid,root):
  # Moby 28.0.4 daemon.go prepareTempDir uses initial DOCKER_TMPDIR, else
  # DockerRootDir/tmp, then canonicalizes it and sets the daemon's TMPDIR.
  # /proc/environ does not prove later setenv values: never infer from TMPDIR.
  with Path(f"/proc/{pid}/environ").open("rb")as source:data=source.read(65537)
  need(len(data)<=65536 and data.endswith(b"\0"),"ENGINE_INITIAL_ENVIRONMENT_UNREADABLE_OR_UNBOUNDED")
  selected=[]
  for entry in data[:-1].split(b"\0"):
   need(b"="in entry,"ENGINE_INITIAL_ENVIRONMENT_MALFORMED")
   key,value=entry.split(b"=",1)
   if key==b"DOCKER_TMPDIR":selected.append(os.fsdecode(value))
  need(len(selected)<=1,"ENGINE_IMPORT_TEMP_AMBIGUOUS")
  chosen=Path(selected[0])if selected and selected[0]else root/"tmp"
  need(chosen.is_absolute(),"ENGINE_IMPORT_TEMP_RELATIVE_UNSUPPORTED")
  return chosen.resolve(strict=True)

 def admit(self,end):
  previous=self.n.command_end;self.n.command_end=min(previous,end)
  try:self._admit(end)
  except OSError:raise RuntimeError("ENGINE_ACCOUNTING_UNREADABLE_UNDER_EXISTING_RUNNER_AUTHORITY; no acquisition or dependency installation")from None
  except RuntimeError as error:
   if "footprint unreadable"in str(error):raise RuntimeError("ENGINE_ACCOUNTING_UNREADABLE_UNDER_EXISTING_RUNNER_AUTHORITY; no acquisition or dependency installation")from None
   raise
  finally:self.n.command_end=previous

 def _admit(self,end):
  need(os.uname().sysname=="Linux" and not self.record.exists()and not self.admission.exists(),"fresh Linux native runtime admission required")
  self.socket=self.socket_identity()
  config=Path(self.env["DOCKER_CONFIG"]);config.mkdir(mode=0o700)
  need(not list(config.iterdir()),"ambient Docker configuration refused")
  info=json.loads(self.engine(["info","--format","{{json .}}"],end))
  need(isinstance(info,dict)and isinstance(info.get("ID"),str)and info["ID"]and info.get("OSType")=="linux" and info.get("Architecture")in("x86_64","amd64"),"local engine identity/platform unavailable")
  status=info.get("DriverStatus")
  need(info.get("ServerVersion")=="28.0.4"and info.get("Driver")=="overlay2"and isinstance(status,list)and all(isinstance(x,list)and len(x)==2 and all(isinstance(y,str)for y in x)for x in status)and ["Supports d_type","true"]in status and any(x[0]=="Backing Filesystem"for x in status)and not any(x[0]=="driver-type"for x in status),"ENGINE_LOADER_CONTRACT_UNREVIEWED; requires Moby 28.0.4 classic overlay2")
  need(info.get("LoggingDriver")in("json-file","local"),"engine logging accounting unsupported")
  self.engine_id=info["ID"]
  root=Path(info["DockerRootDir"]);roots=[root]
  self.identities=self.processes(end)
  for pid,(_,argv)in self.identities.items():
   if Path(argv[0]).name=="dockerd":roots.append(self.daemon_temp(pid,root))
   # Full engine process mount visibility is a prerequisite, before allocation.
   mounts=Path(f"/proc/{pid}/mountinfo").read_text()
   need(mounts and len(mounts)<=1024**2 and all(" - "in line for line in mounts.splitlines()),"ENGINE_MOUNT_ACCOUNTING_UNREADABLE")
   if Path(argv[0]).name!="containerd":continue
   def option(name):
    matches=[argv[i+1]for i,x in enumerate(argv[:-1])if x==name]+[x.split("=",1)[1]for x in argv if x.startswith(name+"=")]
    need(len(matches)<=1,"ambiguous containerd root/config")
    return matches[0]if matches else None
   explicit=option("--root");configuration=option("--config")or option("-c")
   if configuration:
    with Path(configuration).open("rb")as source:raw=source.read(65537)
    need(len(raw)<=65536,"containerd configuration exceeds bound")
    data=tomllib.loads(raw.decode())
   else:data={}
   selected=explicit or data.get("root")
   need(isinstance(selected,str)and selected.startswith("/"),"containerd content root unknown; no default guess")
   roots.append(Path(selected))
  # Admission proves readability, full traversal and reserve before allocation.
  self.roots=covering_roots(roots)
  for root in self.roots:
   st=root.lstat()
   need(root.is_absolute()and root.resolve()==root and stat.S_ISDIR(st.st_mode),"engine storage root unavailable/aliased")
   self.root_marks[root]=(st.st_dev,st.st_ino)
  self.n.sandbox=self
  self.n.disk()
  snapshot=self.n.r["lastDiskSnapshot"]
  need(snapshot["taskBytes"]+IMAGE_RESERVE<=10*1024**3 and all(x["freeBytes"]>=2*1024**3+IMAGE_RESERVE for x in snapshot["roots"]),"ENGINE_IMAGE_STAGING_AND_IMPORT_RESERVE_UNAVAILABLE")
  self.sample({},end)
  need(self.n.r["sandboxMemoryAccounting"]["totalBytes"]+1024**3<=12*1024**3,"ENGINE_IMAGE_MEMORY_RESERVE_UNAVAILABLE")
  available=re.search(r"^MemAvailable:\s+([0-9]+) kB$",Path("/proc/meminfo").read_text(),re.M)
  need(available and int(available[1])*1024>=1024**3,"ENGINE_IMAGE_HOST_MEMORY_RESERVE_UNAVAILABLE")
  help_=self.engine(["image","load","--help"],end)
  need("--input"in help_ and "--quiet"in help_,"ENGINE_IMAGE_LOAD_CLI_UNAVAILABLE")
  self.n.env.update(DOCKER_HOST=HOST,DOCKER_CONFIG=str(config))
  self.n.r["sandboxAdmission"]={"status":"engine-accounting-readable","image":IMAGE,"runtimeImage":CONFIG,"storageRoots":len(self.roots),"sampledNotQuota":True,"allocationLimit":1,"imageAcquired":False,"admissionReserveBytes":IMAGE_RESERVE,"imageStagingMaximumBytes":STAGING,"unpackedImageMaximumBytes":UNPACKED,"loaderContract":"Moby 28.0.4 classic overlay2"}

 def prepare_image(self,end):
  config=Path(self.env["DOCKER_CONFIG"])
  self.n.remaining(end,phase="pinned image preparation")
  self.n.env["OPENCLAW_NATIVE_IMAGE_END_MS"]=str(int((time.time()+max(0,end-time.monotonic()))*1000))
  # Native.run reserves its existing 120s runtime and 60s process closure.
  result,_=self.n.run("pinned-image-prepare",["python3","-I","-S",str(self.n.t/"scripts/fork-release/native_image.py"),"--state",str(self.image_record),"--staging",str(self.image_staging),"--engine-id",self.engine_id,"--socket-device",str(self.socket["device"]),"--socket-inode",str(self.socket["inode"])],max(0,end-time.monotonic())+180)
  need(result.get("exit")==0 and not result.get("reason"),"PINNED_IMAGE_PREPARATION_UNCONFIRMED; no dependency installation or fixture allocation")
  value=private_record(self.image_record)
  need(value.get("phase")=="confirmed"and value.get("engineId")==self.engine_id and value.get("image")==IMAGE and value.get("runtimeImage")==CONFIG and value.get("registryOriginVerified")is True,"PINNED_IMAGE_CUSTODY_UNCONFIRMED")
  self.n.remaining(end,phase="pinned image admission")
  previous=self.n.command_end;self.n.command_end=min(previous,end)
  try:self.n.disk();self.sample({},end)
  finally:self.n.command_end=previous
  owners=[{"pid":pid,"start":start,"kind":Path(argv[0]).name}for pid,(start,argv)in self.identities.items()if Path(argv[0]).name in("dockerd","containerd")]
  need(len(owners)<=128,"engine owner admission exceeds bound")
  value={"format":1,"host":HOST,"engineId":self.engine_id,"image":IMAGE,"runtimeImage":CONFIG,"socket":self.socket,"owners":owners}
  with self.admission.open("x")as output:os.chmod(self.admission,0o600);json.dump(value,output)
  self.n.env.update(DOCKER_HOST=HOST,DOCKER_CONFIG=str(config),OPENCLAW_NATIVE_SANDBOX_RECORD=str(self.record),OPENCLAW_NATIVE_SANDBOX_ADMISSION=str(self.admission))
  self.n.r["sandboxAdmission"].update(status="admitted",imageAcquired=private_record(self.image_record).get("imported"),transport=private_record(self.image_record).get("transport"),imageDisposition="retained and accounted until ephemeral runner teardown")
  self.n.remaining(end,phase="pinned image admission completed")

 def observation(self):
  if not self.record.exists():return None
  value=private_record(self.record)
  need(value.get("engineId")==self.engine_id and value.get("phase")in("armed","creating","allocated","retiring","retired","held"),"runtime recovery identity differs")
  return value

 def sanitize(self,text):
  value=self.observation()
  strings=[self.engine_id,str(self.record),str(self.admission),str(self.image_record),str(self.image_staging),str(self.n.w/"docker-config"),*(str(p)for p in self.roots)]
  strings.extend(str(p)for p in self.groups)
  strings.extend(arg for _,argv in self.identities.values()for arg in argv if arg.startswith("/"))
  if value:
   strings.extend(value.get("mountPaths",[]))
   strings.extend(x.get("source")for x in value.get("binds",[])if isinstance(x,dict))
   strings.extend(value.get(k)for k in("id","workspace","cgroup","engineId"))
   strings.extend(value.get("entry",{}).get(k)for k in("containerName","sessionKey","workspaceDir","configHash"))
  for private in sorted((x for x in strings if isinstance(x,str)and x),key=len,reverse=True):text=text.replace(private,"[private native runtime]")
  text=re.sub(r"/sys/fs/cgroup(?:/[^\s:'\"]*)?","[private native cgroup]",text)
  return re.sub(r"/proc/[0-9]+(?:/[^\s:'\"]+)?","[private engine process]",text)

 def sample(self,owned,end):
  for path,mark in self.root_marks.items():
   st=path.lstat();need(path.resolve()==path and (st.st_dev,st.st_ino)==mark,"engine storage root changed")
  need(self.engine(["info","--format","{{.ID}}"],end).strip()==self.engine_id,"engine changed during accounting")
  processes=self.processes(end)
  # Daemons are observed, never signalled. Replacements invalidate admission.
  for pid,(start,argv)in self.identities.items():
   if Path(argv[0]).name in("dockerd","containerd"):
    need(processes.get(pid)==(start,argv),"engine daemon identity changed")
  groups=[cgroup(pid)for pid in processes]
  value=self.observation()
  if value and value.get("phase")in("creating","held")and not value.get("id"):
   need(False,"partial allocation footprint unknown; custody retained")
  if value and value.get("phase")!="retired" and value.get("id"):
   need(re.fullmatch(r"[a-f0-9]{64}",value["id"]),"runtime physical ID malformed")
   inspected=json.loads(self.engine(["inspect",value["id"]],end))
   need(isinstance(inspected,list)and len(inspected)==1 and inspected[0].get("Id")==value["id"],"runtime accounting identity differs")
   state=inspected[0].get("State",{});pid=state.get("Pid")
   need(type(pid)is int and pid>=0,"runtime process accounting unavailable")
   if pid:groups.append(cgroup(pid));self.groups.add(groups[-1])
   elif self.groups:groups.extend(p for p in self.groups if p.exists())
   log=Path(inspected[0].get("LogPath",""))
   need(log.is_absolute()and log.resolve()==log and any(log.is_relative_to(root)for root in self.roots),"runtime logging footprint unavailable")
   scan=subprocess.run(["du","-s","--block-size=1","--no-dereference",str(log.parent)],text=True,capture_output=True,env=self.env,timeout=min(5,self.n.remaining(end,cancel=False,phase="runtime log accounting")))
   match=re.fullmatch(r"([0-9]+)\t"+re.escape(str(log.parent))+r"\n",scan.stdout)
   need(not scan.returncode and not scan.stderr and match is not None,"runtime log footprint unreadable")
   need(int(match[1])<=2*1024**2,"runtime log/metadata stop threshold exceeded")
   self.n.r["sandboxLogAccounting"]={"sampledNotQuota":True,"bytes":int(match[1]),"stopBytes":2*1024**2,"rotationsIncluded":True}
  groups=covering_roots(groups)
  charge=0
  for group in groups:
   self.n.remaining(end,cancel=False,phase="aggregate memory accounting")
   need(group.resolve()==group and group.is_relative_to(Path("/sys/fs/cgroup")),"cgroup accounting path differs")
   text=(group/"memory.current").read_text().strip()
   need(text.isdecimal(),"cgroup memory accounting unreadable")
   charge+=int(text)
  task=0
  for pid,entry in owned.items():
   if not any(cgroup(pid).is_relative_to(group)for group in groups):task+=entry["rss"]
  if not any(cgroup(os.getpid()).is_relative_to(group)for group in groups):
   task+=int(Path("/proc/self/statm").read_text().split()[1])*os.sysconf("SC_PAGE_SIZE")
  total=charge+task
  self.n.r["peakAggregateMemoryBytes"]=max(total,self.n.r.get("peakAggregateMemoryBytes",0))
  self.n.r["sandboxMemoryAccounting"]={"sampledNotQuota":True,"chargedCgroups":len(groups),"engineProcesses":len(processes),"cgroupBytes":charge,"uncoveredTaskRssBytes":task,"totalBytes":total,"capBytes":12*1024**3,"baselineSubtracted":False}
  need(total<=12*1024**3,"aggregate native/engine/container memory budget exceeded")

 def assert_retired(self,end):
  if self.image_record.exists():
   image=private_record(self.image_record)
   need(image.get("engineId")==self.engine_id and image.get("image")==IMAGE and image.get("runtimeImage")==CONFIG,"IMAGE_CUSTODY_IDENTITY_UNKNOWN; retain")
   need(image.get("phase")in("confirmed","failed-before-import")and not(image.get("phase")=="failed-before-import"and image.get("issued")is not False),"IMAGE_IMPORT_UNCONFIRMED; cache/staging custody retained")
  elif self.image_staging.exists():need(False,"IMAGE_CUSTODY_RECORD_MISSING; retain staging")
  value=self.observation()
  if value is None:return
  need(value["phase"]=="retired","runtime retirement unconfirmed; cache/workspace custody retained")
  self.sample({},end)
  if value.get("id"):
   paths=value.get("mountPaths")
   need(isinstance(paths,list)and 3<=len(paths)<=128 and all(isinstance(p,str)and p.startswith("/")and p!="/"and len(p)<=4096 for p in paths),"runtime physical mount custody unavailable; retain")
   tokens=[value["id"],*(p.replace("\\","\\134").replace(" ","\\040").replace("\t","\\011")for p in paths)]
   for pid in self.processes(end):
    self.n.remaining(end,cancel=False,phase="runtime mount settlement")
    text=Path(f"/proc/{pid}/mountinfo").read_text()
    need(not any(token in text for token in tokens),"runtime mounts still present; custody retained")
  for group in self.groups:
   if group.exists():need("populated 0"in(group/"cgroup.events").read_text().splitlines(),"runtime process group still populated; custody retained")
  self.n.r["sandboxRetirement"]={"status":"confirmed","physicalGenerations":1 if value.get("id")else 0,"registryOwner":"existing sandbox manager","mountsSettled":True,"processesSettled":True}

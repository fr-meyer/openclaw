"""Sampled external-engine accounting for the one existing native fixture owner."""
import json,os,re,stat,subprocess,time,tomllib
from pathlib import Path
from release import need

IMAGE="docker.io/library/python@sha256:f040863673aea2570c3ff6a5c3fb4c673a016cbc5375005ad145915922b6b78a"
HOST="unix:///var/run/docker.sock"
ENGINES={"dockerd","containerd","containerd-shim-runc-v2"}

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
  self.n=native;self.roots=[];self.identities={};self.engine_id=None;self.groups=set();self.socket=None
  self.record=native.w/"native-sandbox-recovery.json"
  self.admission=native.w/"native-sandbox-admission.json"
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

 def admit(self,end):
  need(os.uname().sysname=="Linux" and not self.record.exists()and not self.admission.exists(),"fresh Linux native runtime admission required")
  self.socket=self.socket_identity()
  config=Path(self.env["DOCKER_CONFIG"]);config.mkdir(mode=0o700)
  need(not list(config.iterdir()),"ambient Docker configuration refused")
  info=json.loads(self.engine(["info","--format","{{json .}}"],end))
  need(isinstance(info,dict)and isinstance(info.get("ID"),str)and info["ID"]and info.get("OSType")=="linux" and info.get("Architecture")in("x86_64","amd64"),"local engine identity/platform unavailable")
  need(info.get("LoggingDriver")in("json-file","local") and info.get("Driver")in("overlay2","overlayfs"),"engine logging/storage accounting unsupported")
  self.engine_id=info["ID"]
  root=Path(info["DockerRootDir"]);roots=[root]
  self.identities=self.processes(end)
  for _,argv in self.identities.values():
   if Path(argv[0]).name!="containerd":continue
   def option(name):
    matches=[argv[i+1]for i,x in enumerate(argv[:-1])if x==name]+[x.split("=",1)[1]for x in argv if x.startswith(name+"=")]
    need(len(matches)<=1,"ambiguous containerd root/config")
    return matches[0]if matches else None
   explicit=option("--root");configuration=option("--config")or option("-c")
   data=tomllib.loads(Path(configuration).read_text())if configuration else {}
   selected=explicit or data.get("root")
   need(isinstance(selected,str)and selected.startswith("/"),"containerd content root unknown; no default guess")
   roots.append(Path(selected))
  # Admission proves readability, full traversal and reserve before allocation.
  self.roots=covering_roots(roots)
  for root in self.roots:
   st=root.lstat()
   need(root.is_absolute()and root.resolve()==root and stat.S_ISDIR(st.st_mode),"engine storage root unavailable/aliased")
  image=json.loads(self.engine(["image","inspect",IMAGE],end))
  names={IMAGE,IMAGE.removeprefix("docker.io/"),IMAGE.removeprefix("docker.io/library/")}
  need(isinstance(image,list)and len(image)==1 and names.intersection(image[0].get("RepoDigests",[]))and image[0].get("Os")=="linux"and image[0].get("Architecture")=="amd64","pinned image is absent; acquisition requires reviewed runtime authority")
  self.n.sandbox=self
  self.n.disk()
  need(self.n.r["lastDiskSnapshot"]["taskBytes"]+128*1024**2<=10*1024**3,"native engine metadata admission reserve unavailable")
  self.sample({},end)
  owners=[{"pid":pid,"start":start,"kind":Path(argv[0]).name}for pid,(start,argv)in self.identities.items()if Path(argv[0]).name in("dockerd","containerd")]
  need(len(owners)<=128,"engine owner admission exceeds bound")
  value={"format":1,"host":HOST,"engineId":self.engine_id,"image":IMAGE,"socket":self.socket,"owners":owners}
  with self.admission.open("x")as output:os.chmod(self.admission,0o600);json.dump(value,output)
  self.n.env.update(DOCKER_HOST=HOST,DOCKER_CONFIG=str(config),OPENCLAW_NATIVE_SANDBOX_RECORD=str(self.record),OPENCLAW_NATIVE_SANDBOX_ADMISSION=str(self.admission))
  self.n.r["sandboxAdmission"]={"status":"admitted","image":IMAGE,"storageRoots":len(self.roots),"sampledNotQuota":True,"allocationLimit":1,"imageAcquired":False}

 def observation(self):
  if not self.record.exists():return None
  value=private_record(self.record)
  need(value.get("engineId")==self.engine_id and value.get("phase")in("armed","creating","allocated","retiring","retired","held"),"runtime recovery identity differs")
  return value

 def sanitize(self,text):
  value=self.observation()
  strings=[self.engine_id,str(self.record),str(self.admission),str(self.n.w/"docker-config"),*(str(p)for p in self.roots)]
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

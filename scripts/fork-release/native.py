#!/usr/bin/env python3
"""One pinned native proof, owned by the existing contracts-only hosted job."""
import argparse,contextlib,json,os,re,shlex,shutil,signal,stat,subprocess,time
from pathlib import Path
from release import need,sha256 as sha,read_json as read

GIB=1024**3
REF="refs/heads/release-pipeline/contracts/v2026.9.9-native-0e6cd516"
BASE="c3f9123d4bea1e6cc8b21c8742fc71e0385f7ca6"
PATCH="0e6cd51631e67ee83ffe91bf556f91c8d7fbbf38789d63657707b3d8e8336c83"
OLD="86f65061b021070c260cff5bbe7c263bc62e3aeeec7204079b95b78fde4b8714"
NEW="27adbbe4703cc7d08816f30bff88338823669bf0cef6fe4c63c57c22f5bf764f"
CASE="rejects exact dispatch when an older Gateway only supports untargeted methods"
TYPES=("tsgo:core","tsgo:extensions","tsgo:core:test","tsgo:extensions:test")
GATEWAY=("src/gateway/server-plugins.lifecycle.test.ts","src/gateway/server-methods.plugin-gateway-dispatch.test.ts","src/gateway/server.startup-websocket-race.test.ts")

def git(root,*args):return subprocess.check_output(["git","-C",str(root),*args],timeout=30)
def process(pid):
 try:
  f=Path(f"/proc/{pid}/stat").read_text().rsplit(") ",1)[1].split()
  return None if f[0] in ("Z","X") else {"pid":pid,"parent":int(f[1]),"group":int(f[2]),"session":int(f[3]),"start":int(f[19]),"state":f[0]}
 except FileNotFoundError:return None

def identity(pid):
 p=process(pid)
 return (p["group"],p["start"]) if p else None

def kill(group,sig):
 try:os.killpg(group,sig)
 except ProcessLookupError:pass

def good(r):return not r["exit"]and not r["reason"]

def clean(text):
 text=re.sub(r"\x1b\[[0-9;]*[a-zA-Z]","",text)
 text=re.sub(r"(?i)(authorization\s*[:=]\s*)[^\r\n]+",r"\1[REDACTED]",text)
 text=re.sub(r"(?i)(bearer\s+|(?:token|password|secret|api[_-]?key)\s*[:=]\s*)[^\s,;]+",r"\1[REDACTED]",text)
 text=re.sub(r"(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]{20,})","[REDACTED]",text)
 return re.sub(r"-----BEGIN [^-]+PRIVATE KEY-----.*?-----END [^-]+PRIVATE KEY-----","[REDACTED]",text,flags=re.S)

def before(data):
 cur=b'      const method = cardId\n        ? "workboard.cards.dispatchWithTarget"\n        : options.maxStarts === undefined'
 prev=b'      const method =\n        options.maxStarts === undefined && !cardId'
 need(sha(data)==NEW and data.count(cur)==1,"CLI reverse input differs")
 old=data.replace(cur,prev)
 need(sha(old)==OLD,"predecessor CLI differs")
 return old

class Native:
 def __init__(self,source,tooling):
  self.s,self.t=source.resolve(),tooling.resolve()
  tmp=Path(os.environ["RUNNER_TEMP"]).resolve()
  self.o,self.w=tmp/"fork-native-evidence",tmp/"fork-native-work"
  self.o.mkdir(exist_ok=True);self.w.mkdir(exist_ok=True)
  self.r={"productionEligible":False,"commands":[],"failures":[],"notRun":[],"peakRssBytes":0,"peakTaskBytes":0}
  self.c,self.f,self.u=(self.r[k]for k in("commands","failures","notRun"))
  self.end,self.p,self.cancel=time.monotonic()+110*60,None,False
  self.command_end,self.known=self.end,{}
  self.planned,self.reached={},set()
  self.env={k:os.environ[k]for k in("PATH","LANG","TZ","GITHUB_WORKSPACE")if k in os.environ}
  self.env.update(CI="1",GITHUB_ACTIONS="true",HOME=str(self.w/"home"),COREPACK_HOME=str(self.w/"corepack"),COREPACK_NPM_REGISTRY="https://registry.npmjs.org",npm_config_registry="https://registry.npmjs.org/",NODE_OPTIONS="--max-old-space-size=6144",OPENCLAW_VITEST_MAX_WORKERS="1",XDG_CACHE_HOME=str(self.w/"cache"))
  Path(self.env["HOME"]).mkdir(exist_ok=True)
  empty=self.w/"empty-npmrc";empty.touch()
  self.env.update(npm_config_userconfig=str(empty),npm_config_globalconfig=str(empty))

 def stop(self,*_):
  self.cancel=True
  if self.p and self.p.poll()is None:kill(self.p.pid,signal.SIGTERM)

 def remaining(self,end):
  need(not self.cancel,"disk probe cancelled")
  left=end-time.monotonic()
  if left<=0:raise subprocess.TimeoutExpired("quiesced disk probe",30)
  return left

 def owned(self,end):
  text=subprocess.check_output(["ps","-e","-o","pid=,ppid=,pgid=,sid=,rss="],text=True,timeout=min(10,self.remaining(end)))
  self.remaining(end)
  rows={}
  for row in text.splitlines():
   self.remaining(end)
   parts=row.split();need(len(parts)==5 and all(x.isdecimal()for x in parts),"malformed process snapshot")
   pid,parent,group,session,rss=map(int,parts)
   # Unrelated kernel threads legitimately have PGID/SID zero; owned commands cannot.
   need(pid>0 and pid not in rows,"malformed process identity")
   rows[pid]=(parent,group,session,rss)
  root=self.p.pid if self.p else None
  owned={root}if root else set();live={}
  for pid,want in list(self.known.items()):
   self.remaining(end)
   p=process(pid)
   if p and (p["group"],p["start"])==want:live[pid]=p;owned.add(pid)
  sessions={root}if root else set()
  sessions.update(p["session"]for p in live.values())
  while True:
   self.remaining(end)
   children={pid for pid,(parent,_,session,_)in rows.items()if parent in owned or session in sessions}
   if children<=owned:break
   owned|=children
  result={}
  for pid in owned:
   self.remaining(end)
   p=process(pid)
   if not p:continue
   need(p["group"]>0 and p["session"]>0,"malformed owned process identity")
   need(pid!=os.getpid() and p["group"]!=os.getpgrp(),"owned process escaped into supervisor group")
   need(pid in rows and rows[pid][1:3]==(p["group"],p["session"]),"process snapshot changed identity")
   self.known[pid]=(p["group"],p["start"])
   result[pid]={**p,"rss":rows[pid][3]*1024}
  rss=sum(p["rss"]for p in result.values())
  self.r["peakRssBytes"]=max(rss,self.r["peakRssBytes"])
  need(rss<=12*GIB,"owned disk probe RSS budget exceeded")
  return result

 def stopped(self,pid,want,end):
  self.remaining(end)
  p=process(pid)
  if not p:return True
  need((p["group"],p["start"])==want,"paused process changed identity")
  try:threads=list(Path(f"/proc/{pid}/task").iterdir())
  except FileNotFoundError:return process(pid)is None
  for thread in threads:
   self.remaining(end)
   try:state=(thread/"stat").read_text().rsplit(") ",1)[1].split()[0]
   except FileNotFoundError:continue
   if state not in ("T","t","Z","X"):return False
  return p["state"]in("T","t")

 @contextlib.contextmanager
 def quiesced(self,end):
  handles={};last=None;started=time.monotonic()
  try:
   if self.p or self.known:
    need(hasattr(os,"pidfd_open")and hasattr(signal,"pidfd_send_signal"),"Linux pidfd signaling required for owned disk probe")
    while True:
     self.remaining(end);owned=self.owned(end);self.remaining(end)
     # Stop the fresh command root first; pidfds keep signals bound to the opened process.
     for pid in sorted(owned,key=lambda pid:(pid!=self.p.pid if self.p else True,pid)):
      self.remaining(end)
      p=owned[pid];want=(p["group"],p["start"])
      if pid in handles:
       need(handles[pid][1]==want,"paused PID reused during disk probe");continue
      need(len(handles)<2048,"owned disk probe process bound exceeded")
      try:fd=os.pidfd_open(pid)
      except ProcessLookupError:continue
      handles[pid]=(fd,want,False)
      current_identity=identity(pid)
      if current_identity is None:continue
      need(current_identity==want,"process changed before disk pause")
      self.remaining(end)
      if p["state"]not in("T","t"):
       # Mark before signaling so every possibly stopped process is resumed even on failure.
       handles[pid]=(fd,want,True)
       try:signal.pidfd_send_signal(fd,signal.SIGSTOP)
       except ProcessLookupError:pass
     current={(pid,p["group"],p["start"])for pid,p in owned.items()}
     if current==last and all(self.stopped(pid,(p["group"],p["start"]),end)for pid,p in owned.items()):break
     last=current;time.sleep(min(.02,self.remaining(end)))
   self.remaining(end);yield
   if self.p or self.known:
    final=self.owned(end)
    need({(pid,p["group"],p["start"])for pid,p in final.items()}<=last and all(self.stopped(pid,(p["group"],p["start"]),end)for pid,p in final.items()),"owned writers changed during disk scan")
   self.remaining(end)
  finally:
   errors=[]
   for pid,(fd,_,resume)in handles.items():
    try:
     if resume:signal.pidfd_send_signal(fd,signal.SIGCONT)
    except ProcessLookupError:pass
    except Exception as error:errors.append(f"resume {pid}: {error}")
    finally:
     try:os.close(fd)
     except OSError as error:errors.append(f"close {pid}: {error}")
   finished=time.monotonic()
   self.r["diskPauseSeconds"]=round(self.r.get("diskPauseSeconds",0)+finished-started,3)
   if errors:raise RuntimeError("owned disk resume failed: "+clean("; ".join(errors))[:4096])
   if finished>=end:raise subprocess.TimeoutExpired("quiesced disk probe including resume",30)

 def disk(self):
  end=min(time.monotonic()+30,self.end,self.command_end)
  roots=[Path(os.environ["GITHUB_WORKSPACE"]),self.w];marks=[]
  for root in roots:
   need(root.is_absolute()and root.resolve()==root,"disk root must be canonical without symlinks")
   s=root.lstat();need(stat.S_ISDIR(s.st_mode),"disk root must be a directory")
   marks.append((s.st_dev,s.st_ino))
  need(not roots[0].is_relative_to(roots[1])and not roots[1].is_relative_to(roots[0])and self.s.is_relative_to(roots[0]),"disk roots overlap or source escapes workspace")
  self.r["diskAccounting"]={"mode":"owned-process-quiesced-strict-du","unreadEntryAllowanceBytes":0,"unknownFootprint":"unbounded; refuse","sampledNotQuota":True}
  with self.quiesced(end):
   argv=["du","-sx","--block-size=1","--no-dereference",*(str(p)for p in roots)]
   scan=subprocess.run(argv,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={**self.env,"LC_ALL":"C"},timeout=self.remaining(end))
   need(not scan.returncode and not scan.stderr,f"disk scan failed (exit {scan.returncode}): {clean(scan.stderr)[:4096]}")
   rows=scan.stdout.splitlines();counts=[]
   need(len(rows)==len(roots),"disk scan missing root totals")
   for row,root,mark in zip(rows,roots,marks):
    match=re.fullmatch(r"([0-9]+)\t"+re.escape(str(root)),row)
    need(match is not None,"disk scan malformed root total")
    s=root.lstat();need(root.resolve()==root and stat.S_ISDIR(s.st_mode)and(s.st_dev,s.st_ino)==mark,"disk root replaced during scan")
    counts.append(int(match[1]))
   used=sum(counts);self.r["peakTaskBytes"]=max(used,self.r["peakTaskBytes"])
   need(used<=10*GIB and all(shutil.disk_usage(root).free>=2*GIB for root in roots),"disk/reserve budget exceeded")
  self.r["diskSnapshots"]=self.r.get("diskSnapshots",0)+1

 def plan(self,mf,pins):
  stages=["corepack","install","changed-plan","changed-checks",*(x.replace(":","-")for x in TYPES),"source-build","cli-before"]
  gates=dict.fromkeys(mf["gates"]["patchLifecycle"]+mf["gates"]["producerConsumer"]+list(GATEWAY)+[x for x in pins["fixtures"]if x.endswith(".test.ts")])
  self.planned=dict.fromkeys(stages+["vitest:"+x for x in gates]+["node:"+x for x in mf["gates"]["node"]])

 def report_not_run(self):
  covered={x for item in self.u for x in item.get("stages",[item.get("stage")])}
  self.u.extend({"stage":x,"reason":"NOT_RUN_AFTER_PREREQUISITE_FAILURE"}for x in self.planned if x not in self.reached and x not in covered)
  self.r["plannedStages"]=list(self.planned);self.r["executedStages"]=[x for x in self.planned if x in self.reached]

 def run(self,name,argv,seconds=300,want=False,owners=()):
  r={"name":name,"argv":argv,"stages":list(owners or(name,))};self.c.append(r)
  if self.cancel or seconds<=0 or time.monotonic()>=self.end:
   r.update(exit=None,reason="NOT_RUN_AFTER_TIME_OR_CANCELLATION")
   self.f.append(name);self.u.append(r);return r,""
  start=time.monotonic();end=min(self.end,start+seconds)
  env={**self.env,"OPENCLAW_VITEST_FS_MODULE_CACHE_PATH":str(self.w/f"vitest-{len(self.c)}")}
  raw=self.w/"command.log";reason=None;next_disk=0;self.known={};known=self.known;self.command_end=end
  with raw.open("wb")as output:
   self.p=subprocess.Popen(argv,cwd=self.s,env=env,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
   self.reached.update(r["stages"])
   try:
    while self.p.poll()is None:
     rows=[tuple(map(int,x.split()))for x in subprocess.check_output(["ps","-e","-o","pid=,ppid=,rss="],text=True,timeout=min(10,self.remaining(end))).splitlines()]
     owned={self.p.pid}|{pid for pid,want in known.items()if identity(pid)==want}
     while True:
      child={pid for pid,parent,_ in rows if parent in owned}
      if child<=owned:break
      owned|=child
     for pid in owned:
      v=identity(pid)
      if v:
       need(v[0]!=os.getpgrp(),"owned process escaped into supervisor group")
       known[pid]=v
     rss=sum(rss*1024 for pid,_,rss in rows if pid in owned)
     self.r["peakRssBytes"]=max(rss,self.r["peakRssBytes"])
     now=time.monotonic()
     need(not self.cancel and now<end and rss<=12*GIB,"timeout/cancellation/RSS budget")
     if now>=next_disk:self.disk();next_disk=now+10
     time.sleep(1)
   except Exception as error:reason=str(error);self.cancel=True
   finally:
    groups=lambda:{v[0]for pid,v in known.items()if identity(pid)==v}
    if reason:
     for group in groups()|{self.p.pid}:kill(group,signal.SIGTERM)
     try:self.p.wait(timeout=10)
     except subprocess.TimeoutExpired:kill(self.p.pid,signal.SIGKILL)
    status=self.p.wait()
    if groups():
     reason=reason or "unjoined descendants"
     for group in groups():kill(group,signal.SIGTERM)
     end=time.monotonic()+10
     while groups()and time.monotonic()<end:time.sleep(.1)
     for group in groups():kill(group,signal.SIGKILL)
    r["descendantCleanup"]={"captured":len(known),"stillLiveGroups":len(groups())}
    self.p=None;self.known={};self.command_end=self.end
  total=raw.stat().st_size;reached=0
  with raw.open("rb")as stream:
   head=stream.read(16384);stream.seek(max(16384,total-49152));tail=stream.read(49152)
   stream.seek(0);carry=b""
   while chunk:=stream.read(65536):
    data=carry+chunk
    reached+=sum(m.end()>len(carry)for m in re.finditer(rb"\n\n\[check:changed\] (?!lanes=)[^\n]+\n",data))
    carry=data[-256:]
  raw.unlink()
  text=(head+(b"\n[BOUNDED LOG; MIDDLE OMITTED]\n" if total>65536 else b"")+tail).decode("utf-8","replace")
  log=f"{len(self.c):02}-{name}.log";(self.o/log).write_text(clean(text))
  r.update(exit=status,reason=reason,seconds=round(time.monotonic()-start,3),log=log,outputBytes=total,logTruncated=total>65536,plannerReached=reached)
  if(status or reason)and not want:self.f.append(name)
  print(f"native {name}: exit={status}; {reason or 'completed'}\n{clean(text)}",flush=True)
  return r,text

 def test(self,path,old=False):
  name="cli-before" if old else f"test-{len(self.c)}"
  raw=self.w/f"{name}.json"
  argv=["node","--import","./scripts/tsx.mjs","scripts/test-projects.mts","--maxWorkers=1","--reporter=json",f"--outputFile={raw}",path]
  if old:argv+=["--testNamePattern",CASE]
  r,_=self.run(name,argv,600 if path in GATEWAY else 300,want=old,owners=("cli-before" if old else "vitest:"+path,))
  try:
   need(raw.exists()and raw.stat().st_size<=4*1024**2,"native report missing/oversized")
   report=read(raw)
   r["tests"]={k:report.get(k)for k in("numTotalTests","numPassedTests","numFailedTests","numPendingTests","numTodoTests")}
   aa=[a for suite in report["testResults"]for a in suite["assertionResults"]]
   failures=[{"name":clean(a["fullName"]),"messages":[clean(m)for m in a["failureMessages"]]}for a in aa if a["status"]=="failed"]
   d=json.dumps(failures);r["failedTests"]=[clean(x["name"])for x in failures];r["failureDetails"]=d[:65536];r["failureDetailsTruncated"]=len(d)>65536
   if old:
    sel=[a for a in aa if a["fullName"].endswith(CASE)]
    need(r["exit"]and not r["reason"]and len(failures)==len(sel)==1 and sel[0]["status"]=="failed" and any(re.search(r"promise resolved.*instead of rejecting",clean(m),re.S)for m in sel[0]["failureMessages"]),"Commander predecessor not proven")
    r["expectedFailureProven"]=True
   else:need(good(r)and report["numTotalTests"]>0 and not report["numPendingTests"]and not report.get("numTodoTests",0),"owner failed/empty/skipped")
  except(KeyError,ValueError,RuntimeError)as error:
   r["reportFailure"]=str(error);self.f.append(name)
  finally:raw.unlink(missing_ok=True)

 def node_contracts(self,paths):
  end=min(self.end,time.monotonic()+600)
  for i,path in enumerate(paths):
   name=f"node-contract-{i+1}"
   r,text=self.run(name,["node","--test","--test-concurrency=1",path],max(0,end-time.monotonic()),owners=("node:"+path,))
   if r["exit"]is None:continue
   r["tests"]={k:int(v)for k,v in re.findall(r"^# (tests|pass|fail|skipped) (\d+)$",text,re.M)}
   if not(r["tests"].get("tests",0)>0 and r["tests"].get("skipped")==0):
    r["reportFailure"]="Node contracts empty/skipped"
    if name not in self.f:self.f.append(name)

 def execute(self):
  p,t=self.s,self.t
  pins=read(t/"scripts/fork-release/native-inputs.json");event=read(os.environ["GITHUB_EVENT_PATH"])
  sha_t=os.environ["GITHUB_SHA"];m=t/"scripts/fork-release/manifest.json";mf=read(m);s=mf["source"];self.plan(mf,pins)
  need(os.environ["GITHUB_REPOSITORY"]=="fr-meyer/openclaw" and not event["repository"]["private"],"public fork required")
  need(os.environ["GITHUB_REF"]==REF and os.environ["GITHUB_EVENT_NAME"]=="push" and os.environ["GITHUB_ACTOR"]=="fr-meyer" and os.environ["GITHUB_RUN_ATTEMPT"]=="1","ref/event/actor/attempt")
  need(re.fullmatch(r"[0-9a-f]{40}",sha_t)and git(t,"rev-parse","HEAD").decode().strip()==sha_t==os.environ["GITHUB_WORKFLOW_SHA"],"T/workflow differs")
  need(not mf["productionEligible"]and sha(m.read_bytes())==pins["manifestSha256"]and s["commit"]==pins["sourceCommit"]and s["tree"]==pins["sourceTree"],"S/tree/M differs")
  need(git(p,"rev-parse","HEAD").decode().strip()==s["commit"],"S checkout differs")
  need(sha(git(p,"diff","--no-ext-diff","--binary","--full-index",BASE,s["commit"]))==PATCH,"reviewed patch differs")
  paths=git(p,"diff","--name-only",BASE,s["commit"]).decode().splitlines();need(len(paths)==41,"owner count differs")
  hh={f:sha((p/f).read_bytes())for f in pins["dependencyPaths"]}
  need(sha(json.dumps(hh,sort_keys=True,separators=(",",":")).encode())==pins["dependencyFingerprint"],"dependency fingerprint")
  self.r.update(sourceSha=s["commit"],sourceTree=s["tree"],toolingSha=sha_t,manifestSha256=pins["manifestSha256"],inputsSha256=sha((t/"scripts/fork-release/native-inputs.json").read_bytes()),runId=os.environ["GITHUB_RUN_ID"],attempt=1,fileHashes=hh,fixtureHashes=pins["fixtures"])
  need(shutil.disk_usage(p).free>=12*GIB,"initial free space <12 GiB");self.disk()
  version=lambda*a:subprocess.check_output(a,cwd=p,env=self.env,text=True,timeout=90).strip()
  need(version("node","-p","process.versions.node+'/'+process.platform+'/'+process.arch")=="24.21.0/linux/x64","Node runtime differs")
  need(read(p/"package.json")["packageManager"]==pins["packageManager"],"packageManager differs")
  rt,_=self.run("corepack",["bash","-euc",'corepack enable; test "$(corepack pnpm --version)" = "12.5.1"; test "$(corepack pnpm config get registry)" = "https://registry.npmjs.org/"'])
  need(good(rt),"pnpm/official registry differs")
  ins,_=self.run("install",["corepack","pnpm","install","--frozen-lockfile","--store-dir",str(self.w/"store")],900)
  need(good(ins),"install failed; dependents unrun")
  over=[];cli=p/"extensions/workboard/src/cli.ts";fixed=cli.read_bytes()
  try:
   for path,want in pins["fixtures"].items():
    need(re.fullmatch(r"(?:src/gateway|test/helpers)/[A-Za-z0-9_./-]+\.ts",path)and ".." not in path.split("/"),"invalid test overlay")
    data=(t/path).read_bytes();old=(p/path).read_bytes()if(p/path).exists()else None
    need(sha(data)==want and(old is None or sha(old)==pins["fixtureBaseHashes"].get(path)),"fixture/base differs")
    (p/path).parent.mkdir(parents=True,exist_ok=True);(p/path).write_bytes(data);over.append((p/path,old))
   planner=["node","scripts/check-changed.mjs","--base",BASE,"--head",s["commit"],"--",*paths,*pins["fixtures"]]
   dry,plan=self.run("changed-plan",planner[:2]+["--dry-run"]+planner[2:]);need(good(dry),"owner plan failed")
   plan=[shlex.split(l.split("would run: ",1)[1])for l in plan.splitlines()if l.startswith("[check:changed:dry-run] would run: ")];need(plan,"empty plan")
   check,_=self.run("changed-checks",planner,3600)
   reached=len(plan)if good(check)else check["plannerReached"]
   need(reached<=len(plan),"ambiguous planner count")
   for i,command in enumerate(plan[reached:]):
    guard=command[0]=="pnpm" and(command[1].startswith(("check:","lint:tmp:","lint:auth:","lint:webhook:","lint:plugins:","lint:extensions:no-","plugin-sdk:","plugins:","deps:","config:","sqlite:","runtime-sidecars:"))or command[1]=="dup:check:coverage")or command[0]=="node" and any(x.startswith("scripts/check-")for x in command[1:])
    if guard:self.run(f"remaining-guard-{i}",["corepack",*command]if command[0]=="pnpm" else command)
    elif not any(command[:2]==["pnpm",x]for x in TYPES):self.u.append({"argv":command,"reason":"NOT_RUN_AFTER_PLANNER_FAILURE"})
   for owner in TYPES:
    if any(c[:2]==["pnpm",owner]for c in plan[:reached]):self.reached.add(owner.replace(":","-"))
    else:self.run(owner.replace(":","-"),["corepack","pnpm",owner],1800)
   self.run("source-build",["corepack","pnpm","build"],3300)
   cli.write_bytes(before(fixed))
   try:self.test("extensions/workboard/src/cli.test.ts",old=True)
   finally:cli.write_bytes(fixed);need(sha(cli.read_bytes())==NEW,"CLI restore failed")
   gates=dict.fromkeys(mf["gates"]["patchLifecycle"]+mf["gates"]["producerConsumer"]+list(GATEWAY)+[x for x in pins["fixtures"]if x.endswith(".test.ts")])
   for path in gates:self.test(path)
   self.node_contracts(mf["gates"]["node"])
  finally:
   cli.write_bytes(fixed)
   for path,old in over:
    if old is None:path.unlink(missing_ok=True)
    else:path.write_bytes(old)
   self.r["cliRestoredSha256"]=sha(cli.read_bytes())
  need(not git(p,"status","--porcelain","--untracked-files=no").strip(),"tracked source changed")

def main():
 ap=argparse.ArgumentParser();ap.add_argument("command",choices=("run","finalize"));ap.add_argument("--source",type=Path,required=True);ap.add_argument("--tooling",type=Path,required=True)
 args=ap.parse_args();n=Native(args.source,args.tooling);rcp=n.o/"receipt.json"
 if args.command=="run":
  for sig in(signal.SIGTERM,signal.SIGINT):signal.signal(sig,n.stop)
  try:n.execute()
  except Exception as error:n.r["failures"].append(clean(str(error)))
  finally:
   n.report_not_run()
   n.r["complete"]=not n.r["failures"]and not n.r["notRun"]
   rcp.write_text(json.dumps(n.r,indent=2)+"\n")
  return 0 if n.r["complete"]else 1
 if not rcp.exists():
  n.plan(read(n.t/"scripts/fork-release/manifest.json"),read(n.t/"scripts/fork-release/native-inputs.json"))
  n.f.append("native unrun; inspect earlier steps");n.report_not_run()
  n.r.update(complete=False,toolingSha=os.environ.get("GITHUB_SHA"),runId=os.environ.get("GITHUB_RUN_ID"));r=n.r
 else:r=read(rcp)
 files=list(n.o.iterdir())
 need(all(p.is_file()and not p.is_symlink()and(p.name=="receipt.json" or re.fullmatch(r"\d+-[a-z0-9-]+\.log",p.name))for p in files),"unexpected evidence input")
 r["artifact"]={"retentionDays":3,"maximumBytes":20971520,"modeledGrossUsd":0.00053,"incrementalGithubCapUsd":0.01}
 rcp.write_text(json.dumps(r,indent=2))
 need(sum(p.stat().st_size for p in n.o.iterdir())<=20*1024**2-65536,"evidence >20 MiB with margin")
 if "GITHUB_STEP_SUMMARY" in os.environ:
  with open(os.environ["GITHUB_STEP_SUMMARY"],"a")as summary:summary.write(f"Native complete: {r['complete']}; failures: {len(r['failures'])}. Source-only evidence ≤20 MiB/3 days.\n")
 return 0

if __name__=="__main__":raise SystemExit(main())

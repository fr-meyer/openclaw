#!/usr/bin/env python3
"""One pinned native proof, owned by the existing contracts-only hosted job."""
import argparse,contextlib,json,os,re,shlex,shutil,signal,stat,subprocess,sys,time
from pathlib import Path
from release import need,sha256 as sha,read_json as read
from native_sandbox import SandboxAccounting,covering_roots

GIB=1024**3
NATIVE_SECONDS=110*60
OWNER_CLOSURE_SECONDS=60 # 20 process settlement, 30 cache disposal, 10 provenance.
RUNTIME_CLOSURE_SECONDS=120
TERMINAL_SECONDS=15 # Final provenance and receipt, inside the native envelope.
REF="refs/heads/release-pipeline/contracts/v2026.9.9-native-0e6cd516"
BASE="c3f9123d4bea1e6cc8b21c8742fc71e0385f7ca6"
PATCH="dc6d97a82b17fccc3227ae9dc38dad7f6d6c736220361f43da2a1b7e42883559"
OLD="86f65061b021070c260cff5bbe7c263bc62e3aeeec7204079b95b78fde4b8714"
NEW="27adbbe4703cc7d08816f30bff88338823669bf0cef6fe4c63c57c22f5bf764f"
CASE="rejects exact dispatch when an older Gateway only supports untargeted methods"
TYPES=("tsgo:core","tsgo:extensions","tsgo:core:test","tsgo:extensions:test")
CI_INVENTORY="test/scripts/ci-node-test-plan.test.ts"
GATEWAY=("src/gateway/server-plugins.lifecycle.test.ts","src/gateway/server-methods.plugin-gateway-dispatch.test.ts","src/gateway/server.startup-websocket-race.test.ts")

class DeadlineExpired(subprocess.TimeoutExpired):
 def __init__(self,phase,owner):
  super().__init__(phase,0);self.owner=owner
 def __str__(self):return self.cmd+" deadline exhausted ("+self.owner+")"

BATCH_REPORT_SOURCES={'scripts/lib/vitest-report-owner.mts': '410da09739951fe12e9b7708df8766096f63bdd0f712ac2eea63b4825a23e194', 'scripts/test-projects-run.mts': '6e24064ade7b54e30889f6e4770cdb6af01a0c1598c87c602037aef38819ecd1', 'scripts/test-report-utils.mts': '7aac41abb5bf8b3a18340d6fdc376a5db2fff657ff14b7f7b634824d1251939b', 'scripts/lib/vitest-report-capture.mts': 'efed891ab104940d6342fa902306809dc714083be53b73a1970d22a12a10a2a2'}

def batch_native_rows(paths,source,native,check):
 """Read native per-file assertions without inventing or merging a report."""
 check();need(isinstance(native,dict)and type(native.get("success"))is bool,"batch native summary missing")
 files=native.get("testResults");need(isinstance(files,list)and 0<len(files)<=len(paths),"batch file report empty/oversized")
 found={};inventory=[];totals=dict.fromkeys(("numTotalTests","numPassedTests","numFailedTests","numPendingTests","numTodoTests"),0)
 for file in files:
  check();need(isinstance(file,dict),"batch file malformed")
  key=batch_filename(paths,source,file.get("name"));need(key not in found,"batch overlapping file")
  assertions=file.get("assertionResults");need(isinstance(assertions,list)and assertions,"batch owner empty")
  counts=dict.fromkeys(totals,0);failures=[];truncated=False
  for assertion in assertions:
   check();need(isinstance(assertion,dict)and assertion.get("status")in("passed","failed"),"batch assertion skipped/todo/unknown")
   full=assertion.get("fullName");messages=assertion.get("failureMessages")
   need(isinstance(full,str)and full and isinstance(messages,list)and all(isinstance(x,str)for x in messages),"batch assertion malformed")
   failed=assertion["status"]=="failed";need(failed or not messages,"batch passing assertion has errors")
   counts["numTotalTests"]+=1;counts["numFailedTests"if failed else"numPassedTests"]+=1
   inventory.append((key,full,assertion["status"]))
   if failed:
    truncated|=len(full)>4096 or len(messages)>128 or any(len(x)>65536 for x in messages)
    if len(failures)<128:failures.append({"name":clean(full)[:4096],"messages":[clean(x)[:65536]for x in messages[:128]]})
  need(file.get("status")==("failed"if counts["numFailedTests"]else"passed"),"batch file status inconsistent")
  details=json.dumps(failures)
  found[key]={"stage":"vitest:"+key,"status":"FAIL"if counts["numFailedTests"]else"PASS","execution":"COMPLETE","tests":counts,"failedTests":[x["name"]for x in failures],"failureDetails":details[:65536],"failureDetailsTruncated":truncated or len(details)>65536 or counts["numFailedTests"]>128}
  for field,value in counts.items():totals[field]+=value
 need(all(type(native.get(k))is int and native[k]==v for k,v in totals.items()),"batch native counters inconsistent")
 need(native["success"]==(totals["numFailedTests"]==0),"batch native success inconsistent")
 runtime=native.get("numRuntimeErrorTestSuites",0);need(type(runtime)is int and runtime==0,"batch runtime errors")
 check();return found,sorted(inventory),totals

def batch_filename(paths,source,name):
 need(isinstance(name,str)and name,"batch file name missing")
 p=Path(name)
 if p.is_absolute():
  need(p.is_relative_to(source),"batch file outside source");p=p.relative_to(source)
 need(str(p)in paths and not any(x in name.split("/")for x in(".","..")),"batch unknown file")
 return str(p)

def batch_options(args,name):
 need(isinstance(args,list)and args and all(isinstance(x,str)and x for x in args),"batch native command missing/malformed")
 values=[]
 for i,arg in enumerate(args):
  if arg=="--":break
  if arg=="--"+name:
   need(i+1<len(args)and not args[i+1].startswith("--"),"batch option value missing");values.append(args[i+1])
  elif arg.startswith("--"+name+"="):values.append(arg.split("=",1)[1])
 return values

def batch_source_file(source,name):
 need(isinstance(name,str)and name and not any(x in name.split("/")for x in(".","..")),"batch configuration path malformed")
 p=Path(name);p=p if p.is_absolute()else source/p
 need(p.is_relative_to(source)and p.resolve()==p and p.is_file(),"batch configuration outside/missing source")
 return str(p)

def batch_entry_paths(paths,source,entry,raw):
 need(isinstance(entry,dict),"batch entry malformed")
 config=batch_source_file(source,entry.get("config"));args=entry.get("args")
 need(isinstance(args,list)and args and args[0]=="run","batch invocation is not native run")
 configs=batch_options(args,"config")
 need(len(configs)==1 and batch_source_file(source,configs[0])==config,"batch configuration argument differs")
 need(batch_options(args,"maxWorkers")==["1"]and not batch_options(args,"max-workers"),"batch worker policy differs")
 need(batch_options(args,"outputFile")==[str(raw)]and not batch_options(args,"output-file")and not batch_options(args,"outputFile.json"),"batch invocation output request differs")
 need(batch_options(args,"reporter")==["json"]and not batch_options(args,"reporters"),"batch native reporter request differs")
 patterns=entry.get("includePatterns")
 argv_targets=[x for x in args[1:]if x.endswith((".test.ts",".test.mts"))]
 need(all(x in paths for x in argv_targets),"batch unrequested argv target")
 selected=patterns if patterns is not None else argv_targets
 need(isinstance(selected,list)and selected and all(isinstance(x,str)and x in paths for x in selected)and len(selected)==len(set(selected)),"batch include target differs/empty")
 need(not argv_targets or set(argv_targets)==set(selected),"batch argv/include target mismatch")
 return selected

def batch_pool_name(pool):
 if isinstance(pool,dict):
  need(set(pool)=={"name"},"batch custom pool metadata malformed");pool=pool["name"]
 need(isinstance(pool,str)and pool and len(pool)<=4096,"batch native pool missing")
 return pool

def batch_invocation_rows(paths,source,entry,original,capture,check):
 check();need(isinstance(entry,dict)and entry.get("state")=="finished","batch invocation unfinished")
 attempts=entry.get("attempts");need(isinstance(attempts,list)and len(attempts)==1 and isinstance(attempts[0],dict),"batch attempt missing/repeated")
 attempt=attempts[0];outcome=attempt.get("outcome")
 need(isinstance(outcome,dict)and("error"not in attempt or attempt["error"]=="")and type(outcome.get("code"))is int and outcome["code"]in(0,1)and outcome.get("signal")is None and outcome.get("noOutputTimedOut")is False and outcome.get("exitedNormally")is True and outcome.get("groupJoined")is True,"batch invocation interrupted/unjoined")
 owned,cases,_=batch_native_rows(paths,source,original,check)
 need(isinstance(capture,dict)and capture.get("processTimedOut")is False,"batch capture missing/timed out")
 need(capture.get("root")==str(source)and type(capture.get("pid"))is int and capture["pid"]>0,"batch capture root/process differs")
 command=capture.get("command");json_file=attempt.get("json");blob_file=attempt.get("blob")
 need(batch_options(command,"maxWorkers")==["1"]and not batch_options(command,"max-workers"),"batch captured worker policy differs")
 need(batch_options(command,"outputFile.json")==[json_file]and batch_options(command,"outputFile.blob")==[blob_file]and not batch_options(command,"outputFile")and not batch_options(command,"output-file"),"batch capture output differs")
 configs=batch_options(command,"config")
 need(len(configs)==1 and batch_source_file(source,configs[0])==batch_source_file(source,entry.get("config")),"batch capture configuration differs")
 reporters=batch_options(command,"reporter")
 need(len(reporters)==3 and set(reporters)=={"json","blob",str(source/"scripts/lib/vitest-report-capture.mts")}and not batch_options(command,"reporters"),"batch capture reporter differs")
 need(all(type(capture.get(k))is bool for k in("coverageOnFailure","passWithNoTests","ignoreUnhandledErrors")),"batch native capture policy malformed")
 coverage=capture.get("coverageDirectory");coverage_files=capture.get("coverageFiles")
 need(isinstance(coverage_files,list)and all(isinstance(x,str)and x and not Path(x).is_absolute()and ".."not in x.split("/")for x in coverage_files),"batch coverage metadata malformed")
 need(coverage in(None,str(Path(json_file).parent/"coverage"))and(coverage is not None or not coverage_files),"batch coverage directory differs")
 projects=capture.get("projects");need(isinstance(projects,list)and 0<len(projects)<=len(owned),"batch capture projects missing")
 def project_key(project):
  need(isinstance(project,dict)and isinstance(project.get("name"),str)and project["name"]and isinstance(project.get("namePrefix"),str)and project.get("root")==str(source),"batch project root/name differs")
  return(project["name"],project["namePrefix"],project["root"],batch_source_file(source,project.get("config")),batch_pool_name(project.get("pool")))
 identities=[project_key(project)for project in projects];need(len(identities)==len(set(identities)),"batch project identity overlap")
 ended=capture.get("ended");failed=sum(x["status"]=="FAIL"for x in owned.values())
 need(isinstance(ended,dict)and ended.get("reason")==("failed"if failed else"passed")and all(type(ended.get(k))is int and ended[k]==v for k,v in(("unhandledErrors",0),("suiteErrors",0),("failedModules",failed))),"batch completion unhandled/suite/error mismatch")
 need(outcome["code"]==int(bool(failed)),"batch invocation exit inconsistent")
 modules=capture.get("modules");need(isinstance(modules,list)and len(modules)==len(owned),"batch module inventory missing")
 names=[];tasks=[]
 for module in modules:
  check();need(isinstance(module,dict),"batch module malformed")
  need(project_key(module)in identities,"batch module project/config/root/pool differs")
  names.append(batch_filename(paths,source,module.get("file")));task=module.get("taskId")
  need(isinstance(task,str)and task and task not in tasks,"batch task identity overlapping/missing");tasks.append(task)
 need(len(names)==len(set(names))and set(names)==set(owned),"batch module ownership differs")
 check();return owned,cases,tasks

def batch_closed(result):
 closure=result.get("descendantCleanup",{})
 return all(closure.get(k)is True for k in("leaderJoined","rootSessionObserved","sessionCensusComplete"))and type(closure.get("stillLiveGroups"))is int and closure["stillLiveGroups"]==0

def batch_owner_results(paths,source,result,report,index,originals,captures,check=lambda:None):
 """Attribute only one complete source-owned native report set."""
 check();need(2<=len(paths)<=8 and len(paths)==len(set(paths)),"batch targets empty/duplicate/oversized")
 need(type(result.get("exit"))is int and result["exit"]in(0,1)and not result.get("reason")and batch_closed(result),"batch process incomplete")
 need(isinstance(index,dict)and index.get("complete")is True and index.get("error")==""and index.get("publication")=="","batch native report set incomplete")
 entries=index.get("entries");need(isinstance(entries,list)and 2<=len(entries)<=len(paths)and len(entries)==len(originals)==len(captures),"batch invocation set missing")
 merged,inventory,totals=batch_native_rows(paths,source,report,check);need(set(merged)==set(paths),"batch selected owner missing")
 seen=set();task_ids=set();original_inventory=[]
 for i,(entry,original,capture)in enumerate(zip(entries,originals,captures),1):
  check();need(isinstance(entry,dict)and type(entry.get("invocation"))is int and entry["invocation"]==i and type(entry.get("acceptedAttempt"))is int and entry["acceptedAttempt"]==1,"batch invocation incomplete/repeated")
  owned,cases,tasks=batch_invocation_rows(paths,source,entry,original,capture,check)
  need(not seen.intersection(owned)and not task_ids.intersection(tasks),"batch invocation/task overlap")
  seen.update(owned);task_ids.update(tasks);original_inventory.extend(cases)
 need(seen==set(paths)and sorted(original_inventory)==inventory,"batch aggregate lost/replaced assertions")
 merge=index.get("merge")
 need(isinstance(merge,dict)and type(merge.get("code"))is int and merge["code"]==result["exit"]==int(bool(totals["numFailedTests"]))and merge.get("signal")is None and merge.get("noOutputTimedOut")is False and merge.get("exitedNormally")is True and merge.get("groupJoined")is True,"batch aggregate exit incomplete/inconsistent")
 check();return [merged[path]for path in paths]

def positive_batches(paths):
 need(len(paths)==len(set(paths))and CI_INVENTORY not in paths,"batch target inventory differs")
 return [paths[i:i+8]for i in range(0,len(paths),8)]

def git(root,*args):return subprocess.check_output(["git","-C",str(root),*args],timeout=30)
def process(pid,*,dead=False):
 try:
  f=Path(f"/proc/{pid}/stat").read_text().rsplit(") ",1)[1].split()
  return None if not dead and f[0] in ("Z","X") else {"pid":pid,"parent":int(f[1]),"group":int(f[2]),"session":int(f[3]),"start":int(f[19]),"state":f[0]}
 except FileNotFoundError:return None

def identity(pid):
 p=process(pid)
 return (p["group"],p["start"]) if p else None

def kill(group,sig):
 try:os.killpg(group,sig)
 except ProcessLookupError:pass

def good(r):return not r["exit"]and not r["reason"]

PRIVATE_REDACTOR=None

def clean(text):
 if PRIVATE_REDACTOR:
  try:text=PRIVATE_REDACTOR(text)
  except Exception:text="native runtime diagnostic withheld: private recovery unavailable"
 text=re.sub(r"\x1b\[[0-9;]*[a-zA-Z]","",text)
 text=re.sub(r"(?i)(authorization\s*[:=]\s*)[^\r\n]+",r"\1[REDACTED]",text)
 text=re.sub(r"(?i)(bearer\s+|(?:token|password|secret|api[_-]?key)\s*[:=]\s*)[^\s,;]+",r"\1[REDACTED]",text)
 text=re.sub(r"(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]{20,})","[REDACTED]",text)
 return re.sub(r"-----BEGIN [^-]+PRIVATE KEY-----.*?-----END [^-]+PRIVATE KEY-----","[REDACTED]",text,flags=re.S)

def public_data(value):
 """All public receipt strings cross the same private-runtime boundary."""
 if isinstance(value,str):return clean(value)
 if isinstance(value,list):return [public_data(x)for x in value]
 if isinstance(value,dict):return {k:public_data(v)for k,v in value.items()}
 return value

def node_summary(text,reporter="tap"):
 """Admit one complete terminal Node footer; spec is historical evidence only."""
 need(reporter in("tap","spec"),"unknown Node reporter")
 need("[BOUNDED LOG; MIDDLE OMITTED]"not in text,"Node report truncated")
 fields=("tests","suites","pass","fail","cancelled","skipped","todo","duration_ms")
 lines=clean(text).splitlines()
 while lines and not lines[-1]:lines.pop()
 rows=[(i,line)for i,line in enumerate(lines)if re.match(r"^(?:#|ℹ) (?:"+"|".join(fields)+r")(?:\s|$)",line)]
 need(len(rows)==len(fields)and [i for i,_ in rows]==list(range(len(lines)-len(fields),len(lines))),"Node footer incomplete/duplicate/nonterminal")
 prefix="#"if reporter=="tap"else "ℹ";totals={}
 for (_,line),field in zip(rows,fields):
  number=r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?"if field=="duration_ms"else r"(?:0|[1-9][0-9]*)"
  match=re.fullmatch(re.escape(prefix)+" "+field+" ("+number+")",line)
  need(match is not None,"Node footer malformed/reordered/wrong reporter")
  if field!="duration_ms":totals[field]=int(match.group(1))
 need(totals["tests"]>0 and totals["pass"]==totals["tests"]and all(totals[k]==0 for k in("fail","cancelled","skipped","todo")),"Node owner failed/empty/skipped/cancelled/todo")
 return totals

def before(data):
 cur=b'      const method = cardId\n        ? "workboard.cards.dispatchWithTarget"\n        : options.maxStarts === undefined'
 prev=b'      const method =\n        options.maxStarts === undefined && !cardId'
 need(sha(data)==NEW and data.count(cur)==1,"CLI reverse input differs")
 old=data.replace(cur,prev)
 need(sha(old)==OLD,"predecessor CLI differs")
 return old

def planner_progress(stream,*,require_summary=False,end=None):
 """Count named execution headers; summary rows prove failed-plan completion."""
 commands=[];pending=None;blank=False;summary=False;results=[]
 while True:
  if end is not None and time.monotonic()>=end:raise DeadlineExpired("planner log","owner")
  raw=stream.readline(65537)
  if not raw:break
  need(len(raw)<=65536,"planner log line oversized")
  line=clean(raw.decode("utf-8","replace")).rstrip("\r\n")
  if pending is not None and line.startswith("$ "):commands[pending]["argv"]=shlex.split(line[2:])
  pending=None
  # runCommand emits a blank line and a named header, including in-process
  # guards without a shell argv. printPlan reasons have no separating blank.
  if line=="[check:changed] summary":
   need(not summary,"duplicate planner summary");summary=True
  elif line.startswith("[check:changed] FAILED"):require_summary=True
  elif blank and line.startswith("[check:changed] ")and not line.startswith(("[check:changed] lanes=","[check:changed] FAILED")):
   need(not summary,"planner command after summary")
   need(len(commands)<128,"ambiguous planner commands")
   commands.append({"name":line[len("[check:changed] "):],"argv":None,"status":None});pending=len(commands)-1
  elif summary:
   row=re.fullmatch(r"\s*[0-9.]+(?:ms|s)\s+(ok|failed:[0-9]+)\s+(.+)",line)
   if row:
    need(len(results)<len(commands),"incomplete planner summary")
    results.append((row[2],0 if row[1]=="ok"else int(row[1].split(":")[1])))
  blank=not line
 need(len(commands)<=128 and len({c["name"]for c in commands})==len(commands),"ambiguous planner commands")
 need(not require_summary or summary and commands,"failed planner missing summary")
 if summary:
  need([name for name,_ in results]==[c["name"]for c in commands],"incomplete planner summary")
  for command,(_,status)in zip(commands,results):command["status"]=status
 return commands

# Only the supervisor-created per-command cache is eligible. Descriptor-relative
# rmtree never follows interior symlinks; failed joins retain the directory.
CACHE_DISPOSAL="""import os,shutil,stat,sys
root,name,dev,ino,parentdev,parentino=sys.argv[1:]
assert shutil.rmtree.avoids_symlink_attacks
fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 s=os.fstat(fd);assert(s.st_dev,s.st_ino)==(int(parentdev),int(parentino))
 s=os.stat(name,dir_fd=fd,follow_symlinks=False)
 assert stat.S_ISDIR(s.st_mode)and(s.st_dev,s.st_ino)==(int(dev),int(ino))
 shutil.rmtree(name,dir_fd=fd)
finally:os.close(fd)
"""

class Native:
 def __init__(self,source,tooling):
  self.s,self.t=source.resolve(),tooling.resolve()
  tmp=Path(os.environ["RUNNER_TEMP"]).resolve()
  self.o,self.w=tmp/"fork-native-evidence",tmp/"fork-native-work"
  self.o.mkdir(exist_ok=True);self.w.mkdir(exist_ok=True)
  self.r={"productionEligible":False,"commands":[],"failures":[],"notRun":[],"peakRssBytes":0,"peakTaskBytes":0}
  self.c,self.f,self.u=(self.r[k]for k in("commands","failures","notRun"))
  self.started=time.monotonic()
  self.end,self.p,self.cancel=self.started+NATIVE_SECONDS,None,False
  self.work_end=self.end-OWNER_CLOSURE_SECONDS-RUNTIME_CLOSURE_SECONDS-TERMINAL_SECONDS
  self.sandbox=None
  self.probe=None
  self.command_end,self.known=self.end,{}
  self.captured_sessions=set()
  self.planned,self.reached={},set();self.expected={}
  self.env={k:os.environ[k]for k in("PATH","LANG","TZ","GITHUB_WORKSPACE")if k in os.environ}
  self.env.update(CI="1",GITHUB_ACTIONS="true",HOME=str(self.w/"home"),COREPACK_HOME=str(self.w/"corepack"),COREPACK_NPM_REGISTRY="https://registry.npmjs.org",npm_config_registry="https://registry.npmjs.org/",NODE_OPTIONS="--max-old-space-size=6144",OPENCLAW_VITEST_MAX_WORKERS="1",XDG_CACHE_HOME=str(self.w/"cache"))
  Path(self.env["HOME"]).mkdir(exist_ok=True)
  owned_tmp=self.w/"tmp";owned_tmp.mkdir(mode=0o700,exist_ok=True)
  need(owned_tmp.resolve()==owned_tmp and owned_tmp.is_dir(),"owned temporary directory differs")
  self.env.update(TMPDIR=str(owned_tmp),TMP=str(owned_tmp),TEMP=str(owned_tmp))
  empty=self.w/"empty-npmrc";empty.touch()
  self.env.update(npm_config_userconfig=str(empty),npm_config_globalconfig=str(empty))

 def stop(self,*_):
  self.cancel=True
  if self.p and self.p.poll()is None:kill(self.p.pid,signal.SIGTERM)

 def remaining(self,end,*,cancel=True,phase="disk probe"):
  need(not cancel or not self.cancel,phase+" cancelled")
  left=end-time.monotonic()
  if left<=0:
   owner="global-work" if end==self.work_end else "command-work" if end==self.command_end else "native" if end==self.end else "probe" if self.probe and end==self.probe["deadline"] else "closure"
   if self.probe:self.probe.setdefault("failurePhase",self.probe["phase"])
   raise DeadlineExpired(phase,owner)
  return left

 def owned(self,end):
  if self.probe:self.probe["phase"]="process-snapshot"
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
   self.captured_sessions.add(p["session"])
   result[pid]={**p,"rss":rows[pid][3]*1024}
  rss=sum(p["rss"]for p in result.values())
  self.r["peakRssBytes"]=max(rss,self.r["peakRssBytes"])
  need(rss<=12*GIB,"owned disk probe RSS budget exceeded")
  return result

 def stopped(self,pid,want,end):
  if self.probe:self.probe["phase"]="stopped-thread-check"
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
      if self.probe:self.probe["phase"]="pause"
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
  except Exception:
   if self.probe:self.probe.setdefault("failurePhase",self.probe["phase"])
   raise
  finally:
   if self.probe:self.probe["phase"]="resume"
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
   if finished>=end:self.remaining(end,phase="disk probe including resume")

 def disk(self):
  started=time.monotonic();end=min(started+30,self.end,self.work_end,self.command_end)
  roots=[Path(os.environ["GITHUB_WORKSPACE"]),self.w];marks=[]
  if self.sandbox:roots=covering_roots(roots+self.sandbox.roots)
  for root in roots:
   need(root.is_absolute()and root.resolve()==root,"disk root must be canonical without symlinks")
   s=root.lstat();need(stat.S_ISDIR(s.st_mode),"disk root must be a directory")
   marks.append((s.st_dev,s.st_ino))
  need(self.s.is_relative_to(Path(os.environ["GITHUB_WORKSPACE"])),"source escapes workspace")
  need(all(not a.is_relative_to(b)and not b.is_relative_to(a)for i,a in enumerate(roots)for b in roots[i+1:]),"disk roots overlap")
  self.r["diskAccounting"]={"mode":"owned-process-quiesced-engine-sampled-strict-du"if self.sandbox else"owned-process-quiesced-strict-du","unreadEntryAllowanceBytes":0,"unknownFootprint":"unbounded; refuse","sampledNotQuota":True}
  self.probe={"configuredSeconds":30,"availableSeconds":max(0,end-started),"deadline":end,"deadlineOwner":"global-work" if end==self.work_end else "command-work" if end==self.command_end else "native" if end==self.end else "probe","phase":"root-admission"}
  try:
   with self.quiesced(end):
    self.probe["phase"]="du"
    argv=["du","-s"if self.sandbox else"-sx","--block-size=1","--no-dereference",*(str(p)for p in roots)]
    scan=subprocess.run(argv,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={**self.env,"LC_ALL":"C"},timeout=self.remaining(end))
    self.probe["phase"]="totals-validation"
    need(not scan.returncode and not scan.stderr,f"disk scan failed (exit {scan.returncode}): {("engine/task footprint unreadable"if self.sandbox else clean(scan.stderr)[:4096])}")
    rows=scan.stdout.splitlines();counts=[]
    need(len(rows)==len(roots),"disk scan missing root totals")
    for row,root,mark in zip(rows,roots,marks):
     match=re.fullmatch(r"([0-9]+)\t"+re.escape(str(root)),row)
     need(match is not None,"disk scan malformed root total")
     s=root.lstat();need(root.resolve()==root and stat.S_ISDIR(s.st_mode)and(s.st_dev,s.st_ino)==mark,"disk root replaced during scan")
     counts.append(int(match[1]))
    used=sum(counts);self.r["peakTaskBytes"]=max(used,self.r["peakTaskBytes"])
    free=[shutil.disk_usage(root).free for root in roots]
    self.r["lastDiskSnapshot"]={"roots":[{"path":("engine-root-"+str(i))if self.sandbox and any(root.is_relative_to(q)or q.is_relative_to(root)for q in self.sandbox.roots)else str(root),"bytes":count,"freeBytes":reserve}for i,(root,count,reserve)in enumerate(zip(roots,counts,free))],"taskBytes":used,"taskCapExceeded":used>10*GIB,"reserveFailedRoots":[i for i,reserve in enumerate(free)if reserve<2*GIB]}
    need(used<=10*GIB and all(reserve>=2*GIB for reserve in free),"disk/reserve budget exceeded")
   self.r["diskSnapshots"]=self.r.get("diskSnapshots",0)+1
  except Exception as error:
   self.probe.setdefault("failurePhase",self.probe["phase"])
   self.r.setdefault("diskProbeFailures",[]).append({**self.probe,"elapsedSeconds":round(time.monotonic()-started,3),"error":clean(str(error))[:4096],"unknownFootprint":"unbounded; refuse"})
   raise
  finally:self.probe=None

 def source_snapshot(self,phase,deadline=None):
  """Record public tracked-path provenance, never source bodies or private state."""
  snapshot={"phase":phase,"paths":[],"complete":False}
  self.r.setdefault("sourceSnapshots",[]).append(snapshot)
  try:
   raw=subprocess.check_output(["git","-C",str(self.s),"diff","--raw","--no-abbrev","--no-renames","--no-ext-diff","-z","HEAD","--"],stderr=subprocess.PIPE,timeout=min(10,self.remaining(min(self.end,deadline if deadline is not None else self.end),cancel=False,phase="source snapshot")))
   need(len(raw)<=65536,"source diagnostic oversized")
   fields=raw.split(b"\0");need(fields[-1]==b""and len(fields)%2==1,"source diagnostic malformed")
   paths={}
   for i in range(0,len(fields)-1,2):
    header=fields[i].decode().split();path=fields[i+1].decode()
    need(len(header)==5 and header[0].startswith(":"),"source diagnostic malformed")
    paths[path]={"path":path,"change":header[4],"baseBlob":header[2],"tracked":True}
   for path in self.expected:paths.setdefault(path,{"path":path,"tracked":False})
   need(len(paths)<=128,"source diagnostic path bound exceeded")
   read_bytes=0
   for path,item in paths.items():
    need(not Path(path).is_absolute()and ".."not in Path(path).parts,"source diagnostic path escapes")
    file=self.s/path;need(file.parent.resolve().is_relative_to(self.s),"source diagnostic parent escapes")
    if not file.exists()and not file.is_symlink():item["kind"]="missing"
    elif file.is_symlink():item.update(kind="symlink",sha256=sha(os.fsencode(os.readlink(file))))
    else:
     st=file.lstat();need(stat.S_ISREG(st.st_mode),"source diagnostic non-file")
     read_bytes+=st.st_size;need(read_bytes<=4*1024**2,"source diagnostic read bound exceeded")
     item.update(kind="file",sha256=sha(file.read_bytes()))
    item["expected"]=path in self.expected and item.get("sha256")==self.expected[path]
    snapshot["paths"].append(item)
   snapshot["unexpectedPaths"]=[x["path"]for x in snapshot["paths"]if not x["expected"]]
   self.remaining(min(self.end,deadline if deadline is not None else self.end),cancel=False,phase="source snapshot")
   snapshot["complete"]=True
   if snapshot["unexpectedPaths"]:self.f.append("source changed after "+phase)
  except Exception as error:
   snapshot["error"]=clean(str(error))[:4096];self.f.append("source diagnostic failed: "+snapshot["error"])
  return snapshot

 def dispose_cache(self,cache,mark,parent_mark,result,deadline=None):
  end=min(time.monotonic()+30,self.end,deadline if deadline is not None else self.end);record={"path":str(cache),"removed":False}
  result["cacheCleanup"]=record
  try:
   if self.sandbox:self.sandbox.assert_retired(end)
   need(result["descendantCleanup"]["stillLiveGroups"]==0,"cache retained: captured groups still live")
   need(result["descendantCleanup"].get("leaderJoined")is True,"cache retained: leader not joined")
   need(result["descendantCleanup"].get("sessionCensusComplete")is True and result["descendantCleanup"].get("rootSessionObserved")is True,"cache retained: process closure unknown")
   need(cache.parent==self.w and re.fullmatch(r"vitest-[1-9][0-9]*",cache.name),"cache cleanup path differs")
   need(cache.resolve()==cache and self.w.resolve()==self.w,"cache cleanup symlink")
   st=cache.lstat();need(stat.S_ISDIR(st.st_mode)and(st.st_dev,st.st_ino)==mark,"cache replaced before cleanup")
   scan=subprocess.run(["du","-sx","--block-size=1","--no-dereference",str(cache)],text=True,capture_output=True,timeout=min(10,self.remaining(end,cancel=False,phase="cache footprint")))
   need(not scan.returncode and not scan.stderr,"cache footprint scan failed")
   match=re.fullmatch(r"([0-9]+)\t"+re.escape(str(cache))+r"\n",scan.stdout);need(match is not None,"cache footprint malformed")
   record["bytesBefore"]=int(match[1])
   removal=subprocess.run([sys.executable,"-I","-S","-c",CACHE_DISPOSAL,str(self.w),cache.name,*(str(x)for x in mark+parent_mark)],capture_output=True,text=True,timeout=self.remaining(end,cancel=False,phase="cache removal"))
   need(not removal.returncode and not removal.stderr,"cache cleanup failed: "+clean(removal.stderr)[:4096])
   need(not cache.exists()and not cache.is_symlink(),"cache cleanup incomplete")
   record["removed"]=True
   self.remaining(end,cancel=False,phase="cache removal")
  except Exception as error:
   record["error"]=clean(str(error))[:4096];self.cancel=True
   result["reason"]=result["reason"]or record["error"]

 def plan(self,mf,pins):
  stages=["corepack","install","changed-plan","changed-checks",*(x.replace(":","-")for x in TYPES),"source-build","cli-before"]
  gates=dict.fromkeys(mf["gates"]["patchLifecycle"]+mf["gates"]["producerConsumer"]+list(GATEWAY)+[x for x in pins["fixtures"]if x.endswith(".test.ts")])
  self.planned=dict.fromkeys(stages+["vitest:"+x for x in gates]+["node:"+x for x in mf["gates"]["node"]])

 def report_not_run(self):
  covered={x for item in self.u for x in item.get("stages",[item.get("stage")])}
  self.u.extend({"stage":x,"reason":"NOT_RUN_AFTER_PREREQUISITE_FAILURE"}for x in self.planned if x not in self.reached and x not in covered)
  self.r["plannedStages"]=list(self.planned);self.r["executedStages"]=[x for x in self.planned if x in self.reached]

 def closure_groups(self,root,observed,end):
  """Census is closure evidence, never authority to signal uncaptured processes."""
  need(root and root["pid"]==root["group"]==root["session"],"process closure unknown: root identity unavailable")
  text=subprocess.check_output(["ps","-e","-o","pid=,ppid=,pgid=,sid="],text=True,timeout=min(10,self.remaining(end,cancel=False,phase="process closure census")))
  self.remaining(end,cancel=False,phase="process closure census")
  current=process(root["pid"],dead=True)
  need(current is None or(current["group"],current["session"],current["start"])==(root["group"],root["session"],root["start"]),"process closure unknown: root PID reused")
  # Historical IDs are retention evidence only. A vanished leader cannot make
  # its remaining writers disappear; reused IDs conservatively retain caches.
  groups={want[0]for want in self.known.values()};sessions=self.captured_sessions|{root["session"]};live=set();seen=set()
  # A captured PID can keep its birth identity while changing group/session.
  # Its new group is retention evidence, not newly granted signal authority.
  for pid,want in self.known.items():
   self.remaining(end,cancel=False,phase="process closure census")
   p=process(pid)
   if p and p["start"]==want[1]:
    need(p["group"]>0 and p["session"]>0 and pid!=os.getpid()and p["group"]!=os.getpgrp(),"process closure identity changed")
    live.add(p["group"])
   self.remaining(end,cancel=False,phase="process closure census")
  for row in text.splitlines():
   self.remaining(end,cancel=False,phase="process closure census")
   fields=row.split();need(len(fields)==4 and all(x.isdecimal()for x in fields),"malformed closure process snapshot")
   pid,_,group,session=map(int,fields);need(pid>0 and pid not in seen,"malformed closure process identity");seen.add(pid)
   if session not in sessions and group not in groups:continue
   p=process(pid)
   if not p:continue
   need((p["group"],p["session"])==(group,session)and pid!=os.getpid()and group!=os.getpgrp(),"process closure snapshot changed identity")
   live.add(group)
  need(observed,"process closure unknown: command tree never observed")
  self.remaining(end,cancel=False,phase="process closure census")
  return live

 def runtime_closure(self,owner_end):
  """Let the fixture owner retire after TERM; never remove from the supervisor."""
  if not self.sandbox or not self.p or self.p.poll()is not None:return
  record=self.sandbox.observation()
  if not record or record["phase"]=="retired":return
  end=min(owner_end-OWNER_CLOSURE_SECONDS,time.monotonic()+RUNTIME_CLOSURE_SECONDS)
  if end<=time.monotonic():return
  try:self.p.wait(timeout=self.remaining(end,cancel=False,phase="fixture runtime closure"))
  except subprocess.TimeoutExpired:pass # Existing process owner then joins/kills; custody stays held.

 def run(self,name,argv,seconds=300,want=False,owners=()):
  r={"name":name,"argv":argv,"stages":list(owners or(name,))};self.c.append(r)
  start=time.monotonic();owner_end=min(self.end-TERMINAL_SECONDS,start+seconds)
  closure=OWNER_CLOSURE_SECONDS+(RUNTIME_CLOSURE_SECONDS if self.sandbox else 0)
  end=min(self.work_end,owner_end-closure)
  if self.cancel or start>=end:
   r.update(exit=None,reason="NOT_RUN_AFTER_TIME_OR_CANCELLATION")
   self.f.append(name);self.u.append(r);return r,""
  r["deadline"]={"ownerSeconds":seconds,"ownerEndMonotonic":owner_end,"workSeconds":end-start,"closureSeconds":closure,"nativeLimitSeconds":NATIVE_SECONDS,"terminalReserveSeconds":TERMINAL_SECONDS}
  cache=self.w/f"vitest-{len(self.c)}"
  need(self.w.resolve()==self.w and not cache.exists()and not cache.is_symlink(),"command cache ownership differs")
  cache.mkdir(mode=0o700);st=cache.lstat();parent=self.w.lstat()
  mark,parent_mark=(st.st_dev,st.st_ino),(parent.st_dev,parent.st_ino)
  env={**self.env,"OPENCLAW_VITEST_FS_MODULE_CACHE_PATH":str(cache)}
  if self.sandbox:env["OPENCLAW_NATIVE_SANDBOX_END_MS"]=str(int((time.time()+max(0,owner_end-OWNER_CLOSURE_SECONDS-time.monotonic()))*1000))
  raw=self.w/"command.log";reason=None;next_disk=0;self.known={};known=self.known;self.captured_sessions=set();self.command_end=end
  with raw.open("wb")as output:
   self.p=subprocess.Popen(argv,cwd=self.s,env=env,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
   r["started"]=True
   self.reached.update(r["stages"])
   root=None;observed=False
   try:
    root=process(self.p.pid,dead=True)
    need(root and root["pid"]==root["group"]==root["session"],"command root identity unavailable")
    while self.p.poll()is None:
     rows=[tuple(map(int,x.split()))for x in subprocess.check_output(["ps","-e","-o","pid=,ppid=,rss="],text=True,timeout=min(10,self.remaining(end,phase="command process sample"))).splitlines()]
     owned={self.p.pid}|{pid for pid,want in known.items()if identity(pid)==want}
     while True:
      child={pid for pid,parent,_ in rows if parent in owned}
      if child<=owned:break
      owned|=child
     for pid in owned:
      current=process(pid)
      if current:
       v=(current["group"],current["start"])
       need(v[0]!=os.getpgrp(),"owned process escaped into supervisor group")
       known[pid]=v;self.captured_sessions.add(current["session"])
     if known.get(self.p.pid)==(root["group"],root["start"]):observed=True
     rss=sum(rss*1024 for pid,_,rss in rows if pid in owned)
     self.r["peakRssBytes"]=max(rss,self.r["peakRssBytes"])
     now=time.monotonic()
     self.remaining(end,phase="command execution")
     need(rss<=12*GIB,"owned RSS budget exceeded")
     if now>=next_disk:
      if self.sandbox:
       snapshot={pid:{"rss":value*1024}for pid,_,value in rows if pid in owned}
       self.sandbox.sample(snapshot,end)
      self.disk();next_disk=now+10
     time.sleep(min(1,self.remaining(end,phase="command execution")))
   except Exception as error:reason=clean(str(error))[:4096];self.cancel=True
   finally:
    process_end=min(owner_end,time.monotonic()+20);cleanup_error=None
    def groups():
     result=set()
     self.remaining(process_end,cancel=False,phase="captured process closure")
     for pid,want in known.items():
      self.remaining(process_end,cancel=False,phase="captured process closure")
      if identity(pid)==want:result.add(want[0])
      self.remaining(process_end,cancel=False,phase="captured process closure")
     return result
    status=self.p.poll()
    try:
     if reason and status is None:
      for group in groups()|{self.p.pid}:kill(group,signal.SIGTERM)
      self.runtime_closure(owner_end)
      process_end=min(owner_end,time.monotonic()+20)
      status=self.p.poll()
     if status is None:
      try:status=self.p.wait(timeout=min(10,self.remaining(process_end,cancel=False,phase="leader join")))
      except subprocess.TimeoutExpired:
       kill(self.p.pid,signal.SIGKILL)
       status=self.p.wait(timeout=self.remaining(process_end,cancel=False,phase="leader kill join"))
     if groups():
      reason=reason or "unjoined descendants"
      for group in groups():kill(group,signal.SIGTERM)
      grace=min(process_end,time.monotonic()+5)
      while groups()and time.monotonic()<grace:time.sleep(min(.1,self.remaining(grace,cancel=False,phase="descendant termination")))
      for group in groups():kill(group,signal.SIGKILL)
      while groups()and time.monotonic()<process_end:time.sleep(min(.1,self.remaining(process_end,cancel=False,phase="descendant kill join")))
    except Exception as error:
     cleanup_error=clean(str(error))[:4096];reason=reason or "process cleanup failed: "+cleanup_error;self.cancel=True
    census=False
    try:
     if status is None:live=None
     else:live=len(groups()|self.closure_groups(root,observed,process_end));census=True
    except Exception as error:
     live=None;cleanup_error=cleanup_error or clean(str(error))[:4096];reason=reason or "process closure unknown: "+cleanup_error;self.cancel=True
    if status is None or live:reason=reason or "process cleanup incomplete";self.cancel=True
    r["descendantCleanup"]={"captured":len(known),"stillLiveGroups":live,"leaderJoined":status is not None,"rootSessionObserved":observed,"sessionCensusComplete":census}
    if cleanup_error:r["descendantCleanup"]["error"]=cleanup_error
    if status is not None:self.p=None
    if live==0:self.known={}
    self.command_end=self.end
  total=None;progress=[];text="";log=None
  try:
   self.remaining(owner_end,cancel=False,phase="command log")
   total=raw.stat().st_size
   with raw.open("rb")as stream:
    head=stream.read(16384);stream.seek(max(16384,total-49152));tail=stream.read(49152)
    if name=="changed-checks":
     stream.seek(0)
     try:progress=planner_progress(stream,require_summary=bool(status),end=owner_end)
     except Exception as error:reason=reason or "planner progress refused: "+clean(str(error))[:4096];self.cancel=True
   self.remaining(owner_end,cancel=False,phase="command log")
   text=(head+(b"\n[BOUNDED LOG; MIDDLE OMITTED]\n" if total>65536 else b"")+tail).decode("utf-8","replace")
   if self.sandbox:text=self.sandbox.sanitize(text)
   name_log=f"{len(self.c):02}-{name}.log";(self.o/name_log).write_text(clean(text));log=name_log
   self.remaining(owner_end,cancel=False,phase="command log")
  except Exception as error:
   r["logFailure"]=clean(str(error))[:4096];reason=reason or r["logFailure"];self.cancel=True
  if status is not None and r["descendantCleanup"]["stillLiveGroups"]==0 and not r.get("logFailure"):raw.unlink()
  else:r["rawLogRetained"]=True
  r.update(exit=status,reason=clean(reason)[:4096] if reason else None,log=log,outputBytes=total,logTruncated=total>65536 if total is not None else None,plannerReached=len(progress),plannerCommands=progress)
  self.dispose_cache(cache,mark,parent_mark,r,owner_end)
  self.source_snapshot(name,owner_end)
  try:
   self.remaining(owner_end,cancel=False,phase="command summary")
   print(clean(f"native {name}: exit={status}; {r['reason']or 'completed'}\n{text}"),flush=True)
   self.remaining(owner_end,cancel=False,phase="command summary")
  except Exception as error:
   r["reason"]=r["reason"]or clean(str(error))[:4096];self.cancel=True
  r["seconds"]=round(time.monotonic()-start,3)
  if not good(r)and not want:self.f.append(name)
  return r,text

 def batch_report_deadline(self,result):
  deadline=result.get("deadline",{}).get("ownerEndMonotonic")
  need(type(deadline)in(int,float)and 0<deadline<=self.end,"batch original owner deadline missing/invalid")
  return min(deadline,self.end)

 def batch_reports(self,paths,raw,text,end,observed,evidence):
  check=lambda:self.remaining(end,cancel=True,phase="batch report attribution")
  check();matches=re.findall(r"^\[test\] native report set: (.+)$",text,re.M)
  need(len(matches)==1,"batch native report-set declaration missing/duplicate; single-config attribution requires capture")
  directory=Path(matches[0]);need(directory.parent==self.w and re.fullmatch(re.escape(raw.name)+r"\.reports-[A-Za-z0-9_-]+",directory.name),"batch report directory escapes")
  need(directory.resolve()==directory and directory.is_dir(),"batch report directory symlink/missing")
  st=directory.lstat();parent=self.w.lstat();mark,parent_mark=(st.st_dev,st.st_ino),(parent.st_dev,parent.st_ino)
  budget=4*1024**2;hashes={}
  evidence.update(sourceOwner="scripts/lib/vitest-report-owner.mts",directory=str(directory),fileHashes=hashes)
  def load(file):
   nonlocal budget
   check();need(file.resolve()==file and file.is_file(),"batch report file symlink/missing")
   with file.open("rb")as stream:data=stream.read(budget+1)
   check();need(len(data)<=budget,"batch report set oversized");budget-=len(data)
   hashes[str(file.relative_to(self.w))]=sha(data)
   value=json.loads(data);check();return value
  index=load(directory/"index.json")
  need(isinstance(index,dict)and index.get("requested")==str(raw)and index.get("aggregate")in("",str(raw)),"batch report destination differs")
  evidence["reportSetComplete"]=index.get("complete");entries=index.get("entries")
  need(isinstance(entries,list)and 2<=len(entries)<=len(paths),"batch report index missing/oversized")
  selections=[batch_entry_paths(paths,self.s,entry,raw)for entry in entries]
  selected=[path for group in selections for path in group]
  need(len(selected)==len(set(selected))and set(selected)==set(paths),"batch selected target partition differs")
  originals=[];captures=[];seen={};task_ids=set();evidence["unstartedStages"]=[]
  for i,entry in enumerate(entries,1):
   check();need(isinstance(entry,dict)and type(entry.get("invocation"))is int and entry["invocation"]==i and entry.get("state")in("unstarted","started","finished","error"),"batch invocation index malformed")
   attempts=entry.get("attempts");need(isinstance(attempts,list)and len(attempts)<=1,"batch attempt missing/repeated")
   if entry["state"]=="unstarted":
    need(not attempts and entry.get("acceptedAttempt")is None,"batch unstarted invocation inconsistent")
    check();evidence["unstartedStages"].extend("vitest:"+path for path in selections[i-1]);continue
   expected=directory/str(i)/"1"/"report.json"
   need(len(attempts)==1 and isinstance(attempts[0],dict)and attempts[0].get("json")==str(expected)and attempts[0].get("blob")==str(expected.parent/"blob.json")and expected.parent.resolve()==expected.parent,"batch original report/blob path differs")
   accepted=entry.get("acceptedAttempt");need(accepted is None or type(accepted)is int and accepted==1,"batch accepted attempt inconsistent")
   if entry["state"]!="finished":continue
   original=load(expected);capture=load(Path(str(expected)+".capture.json"))
   owned,_,tasks=batch_invocation_rows(paths,self.s,entry,original,capture,check)
   need(set(owned)==set(selections[i-1]),"batch file/include attribution differs")
   need(not set(seen).intersection(owned)and not task_ids.intersection(tasks),"batch invocation/task overlap")
   check();observed.update(owned)
   seen.update(owned);task_ids.update(tasks);originals.append(original);captures.append(capture)
  check();evidence["acceptedBytes"]=4*1024**2-budget
  need(index.get("complete")is True and index.get("aggregate")==str(raw),"batch native report set incomplete")
  report=load(raw);check();evidence["acceptedBytes"]=4*1024**2-budget
  return report,index,originals,captures,directory,mark,parent_mark

 def dispose_batch_reports(self,raw,directory,mark,parent_mark,result,end):
  record=result["batchReportCleanup"]={"directory":str(directory),"removed":False}
  try:
   self.remaining(end,cancel=True,phase="batch report cleanup")
   need(batch_closed(result),"batch reports retained: process closure unknown")
   need(directory.parent==self.w and directory.resolve()==directory and self.w.resolve()==self.w,"batch report cleanup path differs")
   removal=subprocess.run([sys.executable,"-I","-S","-c",CACHE_DISPOSAL,str(self.w),directory.name,*(str(x)for x in mark+parent_mark)],capture_output=True,text=True,timeout=self.remaining(end,cancel=True,phase="batch report cleanup"))
   self.remaining(end,cancel=True,phase="batch report cleanup")
   need(not removal.returncode and not removal.stderr,"batch report cleanup failed: "+clean(removal.stderr)[:4096])
   need(not directory.exists()and not directory.is_symlink(),"batch report cleanup incomplete")
   need(raw.resolve()==raw and raw.is_file(),"batch aggregate cleanup path differs");raw.unlink()
   self.remaining(end,cancel=True,phase="batch report cleanup");record["removed"]=True
  except Exception as error:
   record["error"]=clean(str(error))[:4096];result["reason"]=result.get("reason")or record["error"]
   self.cancel=True
   if result["name"]not in self.f:self.f.append(result["name"])

 def test_many(self,paths):
  if len(paths)==1:self.test(paths[0]);return
  need(2<=len(paths)<=8 and len(paths)==len(set(paths)),"batch targets empty/duplicate/oversized")
  name=f"test-batch-{len(self.c)}";raw=self.w/f"{name}.json";stages=["vitest:"+path for path in paths]
  argv=["node","--import","./scripts/tsx.mjs","scripts/test-projects.mts","--maxWorkers=1","--reporter=json",f"--outputFile={raw}",*paths]
  original_env=self.env
  try:
   self.env={**original_env,"OPENCLAW_TEST_PROJECTS_SERIAL":"1","OPENCLAW_NODE_TEST_PLAN_CONTINUE_ON_FAILURE":"1"}
   r,text=self.run(name,argv,600 if any(path in GATEWAY for path in paths)else 300,owners=(name,))
  finally:self.env=original_env
  self.reached.discard(name);r["stages"]=stages
  if r["exit"]is None:
   r["ownerResults"]=[{"stage":stage,"status":"NOT_RUN","execution":"NOT_RUN","reason":r["reason"]}for stage in stages];return
  observed={};evidence={};r["batchReportCleanup"]={"removed":False,"retained":True,"reason":"failed/unknown report sets retain originals"}
  try:
   end=self.batch_report_deadline(r);check=lambda:self.remaining(end,cancel=True,phase="batch report attribution")
   check();need(batch_closed(r),"batch process closure unknown")
   report,index,originals,captures,directory,mark,parent_mark=self.batch_reports(paths,raw,text,end,observed,evidence)
   r["ownerResults"]=batch_owner_results(paths,self.s,r,report,index,originals,captures,check)
   r["batchEvidence"]=evidence;r["tests"]={k:report[k]for k in("numTotalTests","numPassedTests","numFailedTests","numPendingTests","numTodoTests")}
   self.reached.update(stages)
   for owner in r["ownerResults"]:print(f"native owner {owner['stage']}: {owner['status']}",flush=True)
   if all(owner["status"]=="PASS"for owner in r["ownerResults"]):
    self.dispose_batch_reports(raw,directory,mark,parent_mark,r,end)
    check();need(r["batchReportCleanup"].get("removed")is True and not r.get("reason"),"batch report cleanup incomplete")
  except(KeyError,ValueError,RuntimeError,OSError,TypeError,subprocess.TimeoutExpired)as error:
   r.pop("batchEvidence",None)
   r["reportFailure"]="batch report refused: "+clean(str(error))[:4096];r["batchReportEvidence"]=evidence
   r["ownerResults"]=[]
   for path,stage in zip(paths,stages):
    owner=observed.get(path)
    if owner:
     owner={**owner,"status":"FAIL"if owner["status"]=="FAIL"else"UNKNOWN","reportFailure":r["reportFailure"]};self.reached.add(stage)
    else:
     unstarted=stage in evidence.get("unstartedStages",[])
     owner={"stage":stage,"status":"NOT_RUN"if unstarted else"UNKNOWN","execution":"NOT_RUN"if unstarted else"UNKNOWN","reportFailure":r["reportFailure"]}
     self.u.append({"stage":stage,"reason":"NOT_RUN_SOURCE_REPORT_INVOCATION_UNSTARTED"if unstarted else"EXECUTION_UNKNOWN_AFTER_BATCH_REPORT_REFUSAL"})
    r["ownerResults"].append(owner)
   if name not in self.f:self.f.append(name)

 def test(self,path,old=False):
  name="cli-before" if old else f"test-{len(self.c)}"
  raw=self.w/f"{name}.json"
  argv=["node","--import","./scripts/tsx.mjs","scripts/test-projects.mts","--maxWorkers=1","--reporter=json",f"--outputFile={raw}",path]
  if old:argv+=["--testNamePattern",CASE]
  r,_=self.run(name,argv,600 if path in GATEWAY else 300,want=old,owners=("cli-before" if old else "vitest:"+path,))
  bound=r.get("deadline",{}).get("ownerEndMonotonic")
  if r["exit"]is None or bound is None:
   r["reportFailure"]="native report refused: owner not run or deadline unavailable";r["rawReportRetained"]=raw.exists()
   self.cancel=True
   if name not in self.f:self.f.append(name)
   return
  end=min(self.end,bound);report_complete=False
  try:
   self.remaining(end,phase="native test report")
   need(raw.exists()and raw.stat().st_size<=4*1024**2,"native report missing/oversized")
   report=read(raw)
   self.remaining(end,phase="native test report")
   r["tests"]={k:report.get(k)for k in("numTotalTests","numPassedTests","numFailedTests","numPendingTests","numTodoTests")}
   aa=[a for suite in report["testResults"]for a in suite["assertionResults"]]
   failures=[{"name":clean(a["fullName"]),"messages":[clean(m)for m in a["failureMessages"]]}for a in aa if a["status"]=="failed"]
   d=json.dumps(failures);r["failedTests"]=[clean(x["name"])for x in failures];r["failureDetails"]=d[:65536];r["failureDetailsTruncated"]=len(d)>65536
   if old:
    sel=[a for a in aa if a["fullName"].endswith(CASE)]
    need(r["exit"]and not r["reason"]and len(failures)==len(sel)==1 and sel[0]["status"]=="failed" and any(re.search(r"promise resolved.*instead of rejecting",clean(m),re.S)for m in sel[0]["failureMessages"]),"Commander predecessor not proven")
    r["expectedFailureProven"]=True
   else:need(good(r)and report["numTotalTests"]>0 and not report["numPendingTests"]and not report.get("numTodoTests",0),"owner failed/empty/skipped")
   self.remaining(end,phase="native test report");report_complete=True
  except subprocess.TimeoutExpired as error:
   r["reportFailure"]=clean(str(error))[:4096];self.f.append(name);self.cancel=True
  except(KeyError,ValueError,RuntimeError)as error:
   r["reportFailure"]=clean(str(error))[:4096];self.f.append(name)
  finally:
   closed=r.get("descendantCleanup",{})
   if report_complete and closed.get("leaderJoined")and closed.get("sessionCensusComplete")and closed.get("rootSessionObserved")and closed.get("stillLiveGroups")==0 and time.monotonic()<end:
    raw.unlink(missing_ok=True)
    try:self.remaining(end,phase="native report cleanup")
    except subprocess.TimeoutExpired as error:
     r["reportFailure"]=clean(str(error))[:4096];self.f.append(name);self.cancel=True
   else:r["rawReportRetained"]=raw.exists()

 def node_contracts(self,paths):
  end=min(self.end,time.monotonic()+600)
  for i,path in enumerate(paths):
   name=f"node-contract-{i+1}"
   r,text=self.run(name,["node","--test","--test-concurrency=1","--test-reporter=tap",path],max(0,end-time.monotonic()),owners=("node:"+path,))
   if r["exit"]is None:continue
   r["tests"]={}
   bound=r.get("deadline",{}).get("ownerEndMonotonic")
   if bound is None:
    r["reportFailure"]="Node report refused: owner deadline unavailable";self.cancel=True
    if name not in self.f:self.f.append(name)
    continue
   report_end=min(end,self.end,bound)
   try:
    self.remaining(report_end,cancel=False,phase="Node report")
    need(not r.get("logTruncated",False),"Node report truncated")
    totals=node_summary(text)
    self.remaining(report_end,cancel=False,phase="Node report")
    r["tests"]=totals
    need(good(r),"Node command failed/cancelled")
   except(ValueError,RuntimeError,subprocess.TimeoutExpired)as error:
    r["reportFailure"]=clean(str(error))[:4096]
    if name not in self.f:self.f.append(name)

 def execute(self):
  global PRIVATE_REDACTOR
  p,t=self.s,self.t
  pins=read(t/"scripts/fork-release/native-inputs.json");event=read(os.environ["GITHUB_EVENT_PATH"])
  sha_t=os.environ["GITHUB_SHA"];m=t/"scripts/fork-release/manifest.json";mf=read(m);s=mf["source"];self.plan(mf,pins)
  need(os.environ["GITHUB_REPOSITORY"]=="fr-meyer/openclaw" and not event["repository"]["private"],"public fork required")
  need(os.environ["GITHUB_REF"]==REF and os.environ["GITHUB_EVENT_NAME"]=="push" and os.environ["GITHUB_ACTOR"]=="fr-meyer" and os.environ["GITHUB_RUN_ATTEMPT"]=="1","ref/event/actor/attempt")
  need(re.fullmatch(r"[0-9a-f]{40}",sha_t)and git(t,"rev-parse","HEAD").decode().strip()==sha_t==os.environ["GITHUB_WORKFLOW_SHA"],"T/workflow differs")
  need(not mf["productionEligible"]and sha(m.read_bytes())==pins["manifestSha256"]and s["commit"]==pins["sourceCommit"]and s["tree"]==pins["sourceTree"],"S/tree/M differs")
  need(git(p,"rev-parse","HEAD").decode().strip()==s["commit"],"S checkout differs")
  need(sha(git(p,"diff","--no-ext-diff","--binary","--full-index",BASE,s["commit"]))==PATCH,"reviewed patch differs")
  paths=git(p,"diff","--name-only",BASE,s["commit"]).decode().splitlines();need(len(paths)==42,"owner count differs")
  hh={f:sha((p/f).read_bytes())for f in pins["dependencyPaths"]}
  need(sha(json.dumps(hh,sort_keys=True,separators=(",",":")).encode())==pins["dependencyFingerprint"],"dependency fingerprint")
  batch_hashes={path:sha((p/path).read_bytes())for path in BATCH_REPORT_SOURCES}
  need(batch_hashes==BATCH_REPORT_SOURCES,"batch source report-owner contract differs")
  self.r["batchReportSourceHashes"]=batch_hashes
  snapshot=self.source_snapshot("admission")
  need(snapshot["complete"]and not snapshot["unexpectedPaths"],"source admission differs")
  self.r.update(sourceSha=s["commit"],sourceTree=s["tree"],toolingSha=sha_t,manifestSha256=pins["manifestSha256"],inputsSha256=sha((t/"scripts/fork-release/native-inputs.json").read_bytes()),runId=os.environ["GITHUB_RUN_ID"],attempt=1,fileHashes=hh,fixtureHashes=pins["fixtures"])
  need(shutil.disk_usage(p).free>=12*GIB,"initial free space <12 GiB");self.disk()
  version=lambda*a:subprocess.check_output(a,cwd=p,env=self.env,text=True,timeout=90).strip()
  need(version("node","-p","process.versions.node+'/'+process.platform+'/'+process.arch")=="24.21.0/linux/x64","Node runtime differs")
  need(read(p/"package.json")["packageManager"]==pins["packageManager"],"packageManager differs")
  rt,_=self.run("corepack",["bash","-euc",'corepack enable; test "$(corepack pnpm --version)" = "12.5.1"; test "$(corepack pnpm config get registry)" = "https://registry.npmjs.org/"'])
  need(good(rt),"pnpm/official registry differs")
  ins,_=self.run("install",["corepack","pnpm","install","--frozen-lockfile","--store-dir",str(self.w/"store")],900)
  need(good(ins),"install failed; dependents unrun")
  # Inventory assertions compare Git and filesystem discovery of exact S. Run
  # this owner before T-only fixtures exist, once, without retrying a failure.
  self.test(CI_INVENTORY)
  over=[];cli=p/"extensions/workboard/src/cli.ts";fixed=cli.read_bytes()
  try:
   for path,want in pins["fixtures"].items():
    need((re.fullmatch(r"(?:src/gateway|test/helpers)/[A-Za-z0-9_./-]+\.ts",path)or path=="extensions/workboard/src/gateway.test.ts")and ".." not in path.split("/"),"invalid test overlay")
    data=(t/path).read_bytes();old=(p/path).read_bytes()if(p/path).exists()else None
    need(sha(data)==want and(old is None or sha(old)==pins["fixtureBaseHashes"].get(path)),"fixture/base differs")
    (p/path).parent.mkdir(parents=True,exist_ok=True);(p/path).write_bytes(data);over.append((p/path,old));self.expected[path]=want
   accounting=SandboxAccounting(self)
   PRIVATE_REDACTOR=accounting.sanitize
   accounting.admit(min(self.work_end,time.monotonic()+30))
   planner=["node","scripts/check-changed.mjs","--base",BASE,"--head",s["commit"],"--",*paths,*pins["fixtures"]]
   dry,plan=self.run("changed-plan",planner[:2]+["--dry-run"]+planner[2:]);need(good(dry),"owner plan failed")
   plan=[shlex.split(l.split("would run: ",1)[1])for l in plan.splitlines()if l.startswith("[check:changed:dry-run] would run: ")];need(plan,"empty plan")
   check,_=self.run("changed-checks",planner,3600)
   reached=check["plannerReached"]
   need(not good(check)or reached==len(plan),"passing planner omitted commands")
   if good(check):
    for command in check["plannerCommands"]:command["status"]=0
   need(reached<=len(plan),"ambiguous planner count")
   for i,command in enumerate(plan[reached:]):
    guard=command[0]=="pnpm" and(command[1].startswith(("check:","lint:tmp:","lint:auth:","lint:webhook:","lint:plugins:","lint:extensions:no-","plugin-sdk:","plugins:","deps:","config:","sqlite:","runtime-sidecars:"))or command[1]=="dup:check:coverage")or command[0]=="node" and any(x.startswith("scripts/check-")for x in command[1:])
    if guard:self.run(f"remaining-guard-{i}",["corepack",*command]if command[0]=="pnpm" else command)
    elif not any(command[:2]==["pnpm",x]for x in TYPES):self.u.append({"argv":command,"reason":"NOT_RUN_AFTER_PLANNER_FAILURE"})
   for owner in TYPES:
    if any(c[:2]==["pnpm",owner]for c in plan[:reached]):
     self.reached.add(owner.replace(":","-"))
     self.r.setdefault("plannerStages",{})[owner.replace(":","-")]=check["plannerCommands"][next(i for i,c in enumerate(plan[:reached])if c[:2]==["pnpm",owner])]["status"]
    else:self.run(owner.replace(":","-"),["corepack","pnpm",owner],1800)
   self.run("source-build",["corepack","pnpm","build"],3300)
   self.node_contracts(mf["gates"]["node"])
   cli.write_bytes(before(fixed));self.expected["extensions/workboard/src/cli.ts"]=OLD
   try:self.test("extensions/workboard/src/cli.test.ts",old=True)
   finally:cli.write_bytes(fixed);self.expected.pop("extensions/workboard/src/cli.ts",None);need(sha(cli.read_bytes())==NEW,"CLI restore failed")
   gates=dict.fromkeys(mf["gates"]["patchLifecycle"]+mf["gates"]["producerConsumer"]+list(GATEWAY)+[x for x in pins["fixtures"]if x.endswith(".test.ts")])
   # Close previously missing coverage before the unchanged bulk owners consume
   # the global budget. Every original owner remains present, exactly once.
   priority=[x for x in pins["fixtures"]if x.endswith(".test.ts")]+[GATEWAY[-1]]
   positives=[path for path in dict.fromkeys(priority+list(gates))if path!=CI_INVENTORY]
   for batch in positive_batches(positives):self.test_many(batch)
  finally:
   cli.write_bytes(fixed)
   for path,old in over:
    if old is None:path.unlink(missing_ok=True)
    else:path.write_bytes(old)
   self.expected.clear()
   self.r["cliRestoredSha256"]=sha(cli.read_bytes())
  restored=subprocess.check_output(["git","-C",str(p),"status","--porcelain","--untracked-files=no"],timeout=min(10,self.remaining(self.end,cancel=False,phase="source restore verification")))
  need(not restored.strip(),"tracked source changed")

def main():
 ap=argparse.ArgumentParser();ap.add_argument("command",choices=("run","finalize"));ap.add_argument("--source",type=Path,required=True);ap.add_argument("--tooling",type=Path,required=True)
 args=ap.parse_args();n=Native(args.source,args.tooling);rcp=n.o/"receipt.json"
 if args.command=="run":
  for sig in(signal.SIGTERM,signal.SIGINT):signal.signal(sig,n.stop)
  try:n.execute()
  except Exception as error:n.r["failures"].append(clean(str(error)))
  finally:
   if n.sandbox:
    try:n.sandbox.assert_retired(min(n.end,time.monotonic()+10))
    except Exception as error:n.f.append("sandbox retirement held: "+clean(str(error))[:4096])
   n.source_snapshot("final")
   n.report_not_run()
   elapsed=time.monotonic()-n.started
   n.r["timeAccounting"]={"nativeLimitSeconds":NATIVE_SECONDS,"ownerClosureReserveSeconds":OWNER_CLOSURE_SECONDS,"runtimeClosureReserveSeconds":RUNTIME_CLOSURE_SECONDS,"terminalReserveSeconds":TERMINAL_SECONDS,"elapsedSeconds":round(elapsed,3),"envelopeExceeded":elapsed>=NATIVE_SECONDS}
   if elapsed>=NATIVE_SECONDS:n.f.append("native total deadline exceeded")
   n.r["complete"]=not n.r["failures"]and not n.r["notRun"]
   rcp.write_text(json.dumps(public_data(n.r),indent=2)+"\n")
   finished=time.monotonic()-n.started
   if finished>=NATIVE_SECONDS:
    if "native total deadline exceeded"not in n.f:n.f.append("native total deadline exceeded")
    n.r["timeAccounting"].update(elapsedSeconds=round(finished,3),envelopeExceeded=True)
    n.r["complete"]=False
    rcp.write_text(json.dumps(public_data(n.r),indent=2)+"\n")
  return 0 if n.r["complete"]else 1
 if not rcp.exists():
  n.plan(read(n.t/"scripts/fork-release/manifest.json"),read(n.t/"scripts/fork-release/native-inputs.json"))
  n.f.append("native unrun; inspect earlier steps");n.report_not_run()
  n.r.update(complete=False,toolingSha=os.environ.get("GITHUB_SHA"),runId=os.environ.get("GITHUB_RUN_ID"));r=n.r
 else:r=read(rcp)
 files=list(n.o.iterdir())
 need(all(p.is_file()and not p.is_symlink()and(p.name=="receipt.json" or re.fullmatch(r"\d+-[a-z0-9-]+\.log",p.name))for p in files),"unexpected evidence input")
 r["artifact"]={"retentionDays":3,"maximumBytes":20971520,"modeledGrossUsd":0.00053,"incrementalGithubCapUsd":0.01}
 rcp.write_text(json.dumps(public_data(r),indent=2))
 need(sum(p.stat().st_size for p in n.o.iterdir())<=20*1024**2-65536,"evidence >20 MiB with margin")
 if "GITHUB_STEP_SUMMARY" in os.environ:
  with open(os.environ["GITHUB_STEP_SUMMARY"],"a")as summary:summary.write(f"Native complete: {r['complete']}; failures: {len(r['failures'])}. Source-only evidence ≤20 MiB/3 days.\n")
 return 0

if __name__=="__main__":raise SystemExit(main())

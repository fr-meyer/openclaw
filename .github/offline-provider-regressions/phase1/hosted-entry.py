#!/usr/bin/env python3
"""Future owner-approved exact payload + guarded dispatch is authority root.
Derived root JSON is custody/scope binding, NOT independent owner authentication.
No downloads, installs, daemon reconfiguration or candidate execution.
"""
import argparse,hashlib,importlib.util,json,os,pathlib,stat,sys,time,uuid,re
HERE=pathlib.Path(__file__).resolve().parent
KEYS=['GITHUB_REPOSITORY','GITHUB_REF','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT']
def require(v,m):
 if not v:raise RuntimeError(m)
def digest(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def admission(env,project,scopehash):
 require(env.get('GITHUB_ACTIONS')=='true' and env.get('GITHUB_EVENT_NAME')=='workflow_dispatch','guarded manual dispatch only')
 require(env.get('GITHUB_REPOSITORY')=='fr-meyer/openclaw' and env.get('GITHUB_REF')=='refs/heads/ci/offline-provider-regressions-20261116' and env.get('GITHUB_RUN_ATTEMPT')=='1','exact owner repo/ref/attempt')
 require(project in ['bfl','embeddings'] and scopehash==digest(HERE/'authorization-scope.json'),'reviewed finite payload scope')
 require(env.get('RUNNER_ENVIRONMENT')=='github-hosted' and env.get('RUNNER_OS')=='Linux' and env.get('ImageOS')=='ubuntu24' and env.get('ImageVersion'),'trusted GitHub-managed ubuntu24 image boundary')
 require(env.get('GITHUB_RUN_ID','').isdigit() and len(env.get('GITHUB_SHA',''))==40,'observed Actions run identity')
 return {k:env[k] for k in KEYS}
def tool(path):
 p=pathlib.Path(path).resolve();s=p.stat();require(p.is_file() and s.st_uid==0 and not s.st_mode&0o022 and os.access(p,os.X_OK),'existing root-custody host executable: '+path)
 return {'path':str(p),'sha256':digest(p)}
def node_check(value,stage,reason,lexical=None,canonical=None,ancestor=None,metadata=None):
 """Diagnostics only: same condition/order/error; no new filesystem reads."""
 if value:return
 def safe_path(path):
  if path is None:return 'UNKNOWN'
  text=str(path)
  fixed=['/','/usr','/usr/bin','/usr/local','/usr/local/bin','/usr/bin/node','/usr/local/bin/node','/opt','/opt/hostedtoolcache','/opt/hostedtoolcache/node']
  if text not in fixed and not text.startswith(('/usr/','/opt/hostedtoolcache/node/')):return 'OUTSIDE_MANAGED_ROOTS'
  if len(text)>256 or not text.isascii():return 'REDACTED_PATH'
  if text in fixed or re.fullmatch(r'/opt/hostedtoolcache/node/(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})(/x64(/bin(/node)?)?)?',text):return text
  return 'MANAGED_OTHER' if text.startswith(('/usr/','/opt/hostedtoolcache/node/')) and not any(x in text.split('/') for x in ['.','..']) and re.fullmatch(r'/[A-Za-z0-9_./-]+',text) else 'OUTSIDE_MANAGED_ROOTS'
 def number(key):
  value=getattr(metadata,key,None) if metadata is not None else None
  return value if type(value) is int and 0<=value<2**64 else None
 mode=number('st_mode');mode=mode if mode is not None and mode<2**32 else None
 kind='UNKNOWN' if mode is None else 'symlink' if stat.S_ISLNK(mode) else 'directory' if stat.S_ISDIR(mode) else 'regular' if stat.S_ISREG(mode) else 'other'
 record={'schema':'NODE_REJECTION_V1','stage':stage if re.fullmatch(r'[a-z_]{1,48}',stage) else 'REDACTED','reason':reason if reason in NODE_REASONS else 'managed Node invariant rejected','lexical':safe_path(lexical),'canonical':safe_path(canonical),'ancestor':safe_path(ancestor),'uid':number('st_uid'),'gid':number('st_gid'),'mode':oct(stat.S_IMODE(mode)) if mode is not None else None,'filetype':kind,'device':number('st_dev')}
 message=json.dumps(record,sort_keys=True,separators=(',',':'),ensure_ascii=True)
 if len(message.encode())>2016:message='{"schema":"NODE_REJECTION_V1","stage":"diagnostic_bound","reason":"managed Node invariant rejected"}'
 raise RuntimeError('NODE_REJECTION '+message)
NODE_REASONS=frozenset(['managed Node executable identity name','lexical managed Node custody','Node outside approved managed roots','undeclared managed Node ancestor mount','existing root-custody managed Node executable','managed Node ancestor custody/mount','managed Node parent directory','managed toolcache root symlink escape','managed toolcache root custody','bounded Node toolcache entries','strict managed Node semver directory','no existing trusted managed Node'])
def node_mount_points():
 with open('/proc/self/mountinfo','rb') as f:raw=f.read(1024*1024+1)
 require(len(raw)<=1024*1024,'bounded managed mount metadata');rows=raw.decode().splitlines();require(len(rows)<=8192,'bounded managed mounts')
 points=[]
 for row in rows:
  fields=row.split();require(len(fields)>=10 and ' - ' in row,'kernel mountinfo shape')
  value=re.sub(r'\\([0-7]{3})',lambda m:chr(int(m.group(1),8)),fields[4]);points.append(pathlib.PurePosixPath(value))
 return points
def managed_node(path):
 """Existing platform bytes only; canonical managed roots and ancestor custody.
 No PATH lookup, subprocess/probe, import, download or executable invocation.
 """
 original=pathlib.Path(path);p=original.resolve(strict=True)
 node_check(p.name in ['node','nodejs'],'canonical_identity','managed Node executable identity name',original,p)
 for part in [*reversed(original.parents),original]:
  v=part.lstat();node_check(v.st_uid==0 and (stat.S_ISLNK(v.st_mode) or not v.st_mode&0o022),'lexical_custody','lexical managed Node custody',original,p,part,v)
 roots=[pathlib.Path('/usr'),pathlib.Path('/usr/local'),pathlib.Path('/opt/hostedtoolcache/node')]
 node_check(any(p==root or root in p.parents for root in roots),'canonical_boundary','Node outside approved managed roots',original,p)
 node_check(not any(m!=pathlib.PurePosixPath('/') and (m==p or m in p.parents) for m in node_mount_points()),'canonical_mount','undeclared managed Node ancestor mount',original,p)
 s=p.stat();node_check(stat.S_ISREG(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022 and s.st_mode&0o111 and os.access(p,os.X_OK),'canonical_executable','existing root-custody managed Node executable',original,p,p,s)
 # Canonical resolved chain must stay on the managed OS filesystem, with no
 # writable/non-root ancestors or undeclared child mount boundary.
 device=pathlib.Path('/').stat().st_dev
 for parent in [*reversed(p.parents),p]:
  v=parent.stat();node_check(v.st_uid==0 and not v.st_mode&0o022 and v.st_dev==device,'canonical_custody','managed Node ancestor custody/mount',original,p,parent,v)
  if parent!=p:node_check(stat.S_ISDIR(v.st_mode),'canonical_parent_type','managed Node parent directory',original,p,parent,v)
 return {'path':str(p),'sha256':digest(p)}
def discover_node():
 for value in ['/usr/bin/node','/usr/local/bin/node']:
  try:pathlib.Path(value).lstat()
  except FileNotFoundError:continue
  return managed_node(value) # Present but unsafe is a failure, not a hidden fallback.
 root=pathlib.Path('/opt/hostedtoolcache/node')
 try:root.lstat()
 except FileNotFoundError:node_check(False,'node_missing','no existing trusted managed Node')
 node_check(root.resolve(strict=True)==root,'cache_boundary','managed toolcache root symlink escape',root)
 v=root.stat();node_check(stat.S_ISDIR(v.st_mode) and v.st_uid==0 and not v.st_mode&0o022,'cache_custody','managed toolcache root custody',root,None,root,v)
 versions=[]
 with os.scandir(root) as entries:
  for entry in entries:
   node_check(len(versions)<64,'cache_entries','bounded Node toolcache entries',root)
   match=re.fullmatch(r'(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})',entry.name)
   node_check(match is not None and entry.is_dir(follow_symlinks=False),'cache_semver','strict managed Node semver directory',root)
   versions.append((tuple(map(int,match.groups())),entry.name))
 # Fixed OS paths first; otherwise highest installed stable semver (numeric).
 for _,version in sorted(versions,reverse=True):
  candidate=root/version/'x64/bin/node'
  try:candidate.lstat()
  except FileNotFoundError:continue
  return managed_node(candidate)
 node_check(False,'node_missing','no existing trusted managed Node')
def main(argv=None):
 p=argparse.ArgumentParser();p.add_argument('mode',choices=['run','finalize']);p.add_argument('--project',required=True);p.add_argument('--scope-hash',required=True);p.add_argument('--candidate',default='candidate-input');p.add_argument('--carrier',default='carrier-input');p.add_argument('--tooling',default='tooling');p.add_argument('--artifacts',default='phase1-artifacts');a=p.parse_args(argv)
 require(os.geteuid()==0,'exact scoped future workflow sudo entry required');identity=admission(os.environ,a.project,a.scope_hash)
 if a.mode=='finalize':
  result=pathlib.Path(a.artifacts)/'domain.json'
  require(result.is_file() and not result.is_symlink() and result.stat().st_size<=65536,'UNVERIFIED no post-close receipt; retain owned reservation, no teardown success inference')
  value=json.loads(result.read_text());require(value.get('close')=={'status':'CLOSED','absent':True} and value.get('status')=='SOURCE_RECIPE_AND_DOMAIN_CLOSURE_PASS','UNVERIFIED whole-domain closure; retain reservation')
  require(value.get('identity')==identity and value.get('project')==a.project and value.get('bootstrapSha256')==digest(HERE/'bounded_ci_domain.py'),'finalizer exact run/project/source binding')
  return 0
 # Existing trusted managed image supplies executables/loaders; observed hashes identify
 # these bytes, not independent provenance. Image identity/owner-reviewed dispatch is trust.
 paths={'python':'/usr/bin/python3','docker':'/usr/bin/docker','dockerd':'/usr/bin/dockerd','mkfs':'/usr/sbin/mkfs.ext4','losetup':'/usr/sbin/losetup','mount':'/usr/bin/mount','umount':'/usr/bin/umount'}
 tools={k:tool(v) for k,v in paths.items()};node=discover_node()
 provenance={'trust':'owner-approved exact payload and guarded GitHub-hosted workflow_dispatch; managed OS/binaries/loaders are explicit platform trust boundary','ImageOS':os.environ['ImageOS'],'ImageVersion':os.environ['ImageVersion'],'osRelease':pathlib.Path('/etc/os-release').read_text(),'python':sys.version,'tools':tools,'node':node}
 nonce=uuid.uuid4().hex;root='/mnt/openclaw-phase1-'+nonce
 custody=pathlib.Path('/run/openclaw-phase1')
 if custody.exists():
  s=custody.lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o077,'root custody directory')
 else:custody.mkdir(mode=0o700)
 authpath=custody/(nonce+'.json')
 scope={'capacity_bytes':12*2**30,'outside_allowance_bytes':128*2**20,'nonce':nonce,'root':root,'tools':tools,'node':node,'runner_provenance':provenance,'worker':{'relative_path':'trusted/qualification-worker.py','sha256':digest(HERE/'qualification-worker.py')},'runtime_authorization_path':str(authpath)}
 auth={k:scope[k] for k in ['capacity_bytes','outside_allowance_bytes','nonce','root','tools','node','runner_provenance','worker']};auth.update(operation='ephemeral-ci-bounded-engine',bootstrap_sha256=digest(HERE/'bounded_ci_domain.py'),expires_epoch=int(time.time())+2700,identity=identity,project=a.project,payload_scope_sha256=a.scope_hash)
 raw=json.dumps(auth).encode();require(len(raw)<=65536,'bounded root authority metadata')
 fd=os.open(authpath,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw)
 scope['runtime_authorization_sha256']=digest(authpath)
 scopepath=custody/(nonce+'-scope.json');scopepath.write_text(json.dumps(scope));scopepath.chmod(0o600)
 spec=importlib.util.spec_from_file_location('trusted_supervisor',HERE/'phase1-supervisor.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 # No subprocess child before Domain.open; retain exact single-thread/nochildren barrier.
 return m.main(['run','--project',a.project,'--candidate',a.candidate,'--carrier',a.carrier,'--tooling',a.tooling,'--artifacts',a.artifacts,'--scope',str(scopepath)])
if __name__=='__main__':sys.exit(main())

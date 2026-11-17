#!/usr/bin/env python3
"""Trusted managed-runner entrypoint; no owner credential/identity fabrication."""
import argparse,hashlib,importlib.util,json,os,pathlib,shutil,signal,stat,sys
HERE=pathlib.Path(__file__).resolve().parent
BOOTSTRAP='7726d3fd955a24df15c5ca7f08c6241b80e45b1262a4cbd8732b4a3cdffe1fa5'
def digest(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def require(v,m):
 if not v:raise RuntimeError(m)
def copy_tree(source,target,budget):
 source=pathlib.Path(source).resolve();require(source.is_dir(),'input directory');target.mkdir();total=0;count=0
 for parent,dirs,files in os.walk(source,followlinks=False):
  rel=pathlib.Path(parent).relative_to(source)
  for name in [*dirs,*files]:
   p=pathlib.Path(parent)/name;s=p.lstat();count+=1;require(count<=250000,'input entry bound')
   require(stat.S_ISREG(s.st_mode) or stat.S_ISDIR(s.st_mode) or stat.S_ISLNK(s.st_mode),'special input denied')
   out=target/rel/name
   if stat.S_ISLNK(s.st_mode):
    value=os.readlink(p);require(not os.path.isabs(value) and source in (p.parent/value).resolve().parents,'input symlink containment');out.symlink_to(value)
   elif stat.S_ISDIR(s.st_mode):out.mkdir()
   else:
    total+=s.st_size;budget[0]+=s.st_size;require(s.st_size<=64*2**20 and budget[0]<=2*2**30,'aggregate context copy bound')
    with p.open('rb') as src,out.open('xb') as dst:
     for chunk in iter(lambda:src.read(65536),b''):dst.write(chunk)
    out.chmod(s.st_mode&0o777)
 return total
def orchestrate(scope,args,domain_factory):
 domain=domain_factory(scope);opened=None;closed=None;result=None;failure=None;receipts={};budget=[0]
 def interrupted(signum,frame):raise RuntimeError('cancellation; whole domain closure required')
 old={s:signal.signal(s,interrupted) for s in [signal.SIGTERM,signal.SIGINT]}
 try:
  opened=domain.open();context=pathlib.Path(opened['context_path']);require(str(context)==scope['root']+'/fs/context','literal context binding')
  copy_tree(args.tooling,context/'tooling',budget);copy_tree(args.candidate,context/'candidate',budget)
  if args.project=='embeddings':copy_tree(args.carrier,context/'carrier',budget)
  else:(context/'carrier').mkdir()
  trusted=context/'trusted';trusted.mkdir();closure={}
  for p in HERE.iterdir():
   if p.is_file():
    require(p.stat().st_size<=16*2**20,'trusted file bound');budget[0]+=p.stat().st_size;require(budget[0]<=2*2**30,'context bound');shutil.copyfile(p,trusted/p.name)
    if p.name not in ['worker-closure.json','qualification-worker.py']:closure[p.name]=digest(p)
  (trusted/'worker-closure.json').write_text(json.dumps(closure))
  # Existing accepted core locates tools as HERE.parent and tooling checkout as TOOLS.parents[1].
  # Worker is relocated to tooling's reviewed phase1 directory; scope binds exact path.
  target=context/scope['worker']['relative_path'];require(target.is_file() and digest(target)==scope['worker']['sha256'],'future scope exact worker')
  identity={k:os.environ[k] for k in ['GITHUB_ACTIONS','GITHUB_REPOSITORY','GITHUB_REF','GITHUB_RUN_ATTEMPT','GITHUB_SHA','GITHUB_RUN_ID','OPENCLAW_PHASE1_OWNER_AUTHORIZED']}
  cfg={'project':args.project,'identity':identity,'hostParent':str(pathlib.Path(scope['root']).parent),'docker':scope['tools']['docker']['path'],'node':scope['node']['path']}
  require(digest(scope['node']['path'])==scope['node']['sha256'],'trusted runner Node pin')
  (context/'worker-input.json').write_text(json.dumps(cfg))
  env=domain.engine_env();require(env['DOCKER_HOST']=='unix://'+scope['root']+'/fs/docker.sock','exact owned socket')
  result=domain.run_phase('qualification-worker',[scope['tools']['python']['path'],'-I','-S','-B',str(target)],2500,64*2**20)
  for p in (context/'receipts').glob('*.json'):
   require(p.name in ['result.json','resources.json','graph.json','provenance.json','failure.json'] and not p.is_symlink() and p.stat().st_size<=8*2**20,'bounded receipt whitelist');receipts[p.name]=p.read_bytes()
  require(sum(map(len,receipts.values()))<=64*2**20,'existing host receipt64MiB bound')
  require(json.loads(receipts['result.json'])['status']=='PHASE1_IMAGE_FEASIBILITY_PASS','worker full integrity/recipe success required')
 except BaseException as e:
  failure=e
  domain.abort(str(e))
 finally:
  try:closed=domain.close()
  finally:
   for s,h in old.items():signal.signal(s,h)
 require(closed=={'status':'CLOSED','absent':True},'whole writer/mount closure unverified; no acceptance')
 if failure:raise failure
 out=pathlib.Path(args.artifacts);require(not out.exists(),'fresh bounded artifact directory');out.mkdir()
 for name,raw in receipts.items():
  (out/name).write_bytes(raw);(out/name).chmod(0o644)
 final={'project':args.project,'identity':{k:os.environ.get(k) for k in ['GITHUB_REPOSITORY','GITHUB_REF','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT']},'bootstrapSha256':BOOTSTRAP,'worker':result['receipt'],'opened':opened,'close':closed,'status':'SOURCE_RECIPE_AND_DOMAIN_CLOSURE_PASS','productQualified':False}
 raw=json.dumps(final).encode();require(len(raw)<=65536 and sum(map(len,receipts.values()))+len(raw)<=64*2**20,'same64MiB outside receipt bucket');(out/'domain.json').write_bytes(raw);(out/'domain.json').chmod(0o644);out.chmod(0o755);return 0
def main(argv=None):
 p=argparse.ArgumentParser();p.add_argument('mode',choices=['run']);p.add_argument('--project',required=True,choices=['bfl','embeddings']);p.add_argument('--candidate',required=True);p.add_argument('--carrier',required=True);p.add_argument('--tooling',required=True);p.add_argument('--artifacts',required=True);p.add_argument('--scope',required=True);a=p.parse_args(argv)
 scopepath=pathlib.Path(a.scope);s=scopepath.stat();require(s.st_uid==0 and not s.st_mode&0o022 and not scopepath.is_symlink(),'managed runner scope custody')
 scope=json.loads(scopepath.read_text());authpath=pathlib.Path(scope['runtime_authorization_path']);auth=json.loads(authpath.read_text())
 require(digest(authpath)==scope['runtime_authorization_sha256'],'external authority digest')
 require(auth.get('node')==scope['node'],'external exact Node authority')
 require(auth.get('payload_scope_sha256')==digest(HERE/'authorization-scope.json'),'external reviewed payload scope')
 require(auth.get('identity')=={k:os.environ.get(k) for k in ['GITHUB_REPOSITORY','GITHUB_REF','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT']},'external exact run identity')
 require(auth.get('project')==a.project,'external project identity')
 require(scope['worker']['relative_path']=='trusted/qualification-worker.py','reviewed worker placement')
 require(digest(HERE/'bounded_ci_domain.py')==BOOTSTRAP,'sealed bootstrap pin')
 spec=importlib.util.spec_from_file_location('trusted_domain',HERE/'bounded_ci_domain.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 return orchestrate(scope,a,m.BoundedEngineDomain)
if __name__=='__main__':sys.exit(main())

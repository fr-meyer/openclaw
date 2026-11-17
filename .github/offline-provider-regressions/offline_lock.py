#!/usr/bin/env python3
"""Trusted metadata-only qualification. Production entry fails closed on missing mounts.
No candidate imports. Real package-manager behavior requires separately authorized runtime.
"""
import hashlib,json,os,pathlib,subprocess,sys,stat

def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def canonical(p):
 p=pathlib.Path(p)
 if not p.is_absolute() or p.resolve()!=p: raise ValueError('noncanonical path')
 return p

def metadata(root):
 allowed={'package.json','pnpm-lock.yaml','pnpm-workspace.yaml','.npmrc'}
 rows={}
 paths=[]
 for directory,dirs,files in os.walk(root,followlinks=False):
  dirs[:]=[d for d in dirs if d not in {'node_modules','.git'}]
  for d in dirs:
   if (pathlib.Path(directory)/d).is_symlink():raise ValueError('source directory symlink')
  paths.extend(pathlib.Path(directory)/f for f in files)
 for p in paths:
  rel=p.relative_to(root)
  if p.name in {'.pnpmfile.cjs','pnpmfile.cjs','.pnpmfile.mjs','pnpmfile.mjs'}: raise ValueError('hook denied')
  take=str(rel) in allowed or (p.name=='package.json' and rel.parts[0] in {'packages','extensions','examples','ui'}) or rel.parts[0]=='patches'
  if take and not p.is_dir():
   if p.is_symlink() or p.resolve()!=p or not p.is_file(): raise ValueError('metadata symlink')
   rows[str(rel)]=digest(p)
 for name in ['package.json','pnpm-lock.yaml','pnpm-workspace.yaml','.npmrc']:
  if name not in rows: raise ValueError('missing root metadata '+name)
 return rows

def measure(root):
 total=0;count=0
 for p in root.rglob('*'):
  if p.is_symlink(): raise ValueError('scratch symlink denied')
  if p.is_file():total+=p.stat().st_size;count+=1
 return total,count

def cache_inventory(root):
 root=canonical(root)
 if not stat.S_ISDIR(root.lstat().st_mode):raise ValueError('cache root type')
 rows={}
 def visit(directory):
  for p in sorted(directory.iterdir()):
   st=p.lstat();rel=str(p.relative_to(root))
   if stat.S_ISLNK(st.st_mode):raise ValueError('cache symlink denied: '+rel)
   if stat.S_ISDIR(st.st_mode):
    rows[rel]={'type':'directory'};visit(p)
   elif stat.S_ISREG(st.st_mode):rows[rel]={'type':'file','bytes':st.st_size,'sha256':digest(p)}
   else:raise ValueError('unsupported cache type: '+rel)
 visit(root)
 return rows

def qualify(spec, runner=None, fixture=False):
 stage='preconditions';result={'productQualified':False,'actualPnpmQualified':False,'fixture':fixture,'exit':1}
 admitted=False
 try:
  out=canonical(spec['output'])
  source=canonical(spec['source']);scratch=canonical(spec['scratch']);cache=canonical(spec['cache']);store=canonical(spec['store']);corepack=canonical(spec['corepack'])
  if any(a==b or a in b.parents or b in a.parents for a in [scratch,out] for b in [source,cache,store,corepack]):raise ValueError('overlapping writable/immutable paths')
  if not fixture:
   if [str(x) for x in [source,scratch,cache,store,corepack,out]]!=['/app','/qualification/workspace','/opt/offline-cache','/opt/offline-store','/opt/corepack','/qualification/output']:raise ValueError('production paths')
   if not spec['hardQuotaAttested'] or not spec['readOnlyMountsAttested']:raise ValueError('external sandbox attestation missing')
   if spec['pnpm']!='/usr/local/bin/pnpm':raise ValueError('pnpm path')
  for immutable in [source,cache,store,corepack]:
   if not stat.S_ISDIR(immutable.lstat().st_mode):raise ValueError('immutable root type')
  for destination in [scratch,out]:
   if os.path.lexists(destination):raise ValueError('destination exists')
   if not stat.S_ISDIR(destination.parent.lstat().st_mode):raise ValueError('destination parent type')
  if scratch==out or scratch in out.parents or out in scratch.parents:raise ValueError('scratch/output overlap')
  protected=[canonical(spec['imageReceipt']),pathlib.Path(spec['pnpm']).resolve()]
  if any(d==p or d in p.parents for d in [scratch,out] for p in protected):raise ValueError('destination overlaps trusted input')
  pnpm=pathlib.Path(spec['pnpm'])
  if not pnpm.is_absolute() or str(pnpm.resolve())!=spec['pnpmCanonical']:raise ValueError('pnpm canonical binding')
  if digest(pnpm)!=spec['pnpmSha256']:raise ValueError('pnpm shim pin drift')
  image=canonical(spec['imageReceipt'])
  if digest(image)!=spec['imageReceiptSha256']:raise ValueError('image binding drift')
  binding=json.loads(image.read_bytes())
  if binding.get('pnpmVersion')!='12.9.0' or not isinstance(binding.get('immutableImageId'),str) or not binding['immutableImageId'].startswith('sha256:'):raise ValueError('image/pnpm identity missing')
  if scratch==out or scratch in out.parents or out in scratch.parents:raise ValueError('scratch/output overlap')
  if not fixture:
   for immutable in [source,cache,store,corepack]:
    if not os.statvfs(immutable).f_flag & os.ST_RDONLY:raise ValueError('immutable mount not readonly')
  if binding['candidateMetadata']!=spec['metadata'] or not binding['completeInstalledGraph'] or binding['candidateRoot']!='/app':raise ValueError('installed image metadata binding')
  stage='source-metadata';before=metadata(source)
  if before!=spec['metadata']:raise ValueError('metadata source drift')
  cachebefore=cache_inventory(cache)
  if {k:v['sha256'] for k,v in cachebefore.items() if v['type']=='file'}!=spec['cacheHashes']:raise ValueError('cache pin drift')
  stage='metadata-budget'
  metadata_bytes=sum((source/r).stat().st_size for r in before)
  if metadata_bytes>spec['scratchByteLimit'] or len(before)>spec['scratchFileLimit']:raise ValueError('precopy scratch bounds')
  budget=spec['scratchByteLimit'];filelimit=spec['scratchFileLimit']
  if type(budget)!=int or not 0<budget<=67108864 or type(filelimit)!=int or not 0<filelimit<=10000:raise ValueError('scratch policy')
  out.mkdir(exist_ok=False);admitted=True
  stage='metadata-copy';scratch.mkdir(exist_ok=False)
  for rel,want in before.items():
   dest=scratch/rel;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes((source/rel).read_bytes())
  budget=spec['scratchByteLimit'];filelimit=spec['scratchFileLimit']
  if not isinstance(budget,int) or not 0<budget<=67108864 or not isinstance(filelimit,int) or not 0<filelimit<=10000:raise ValueError('scratch policy')
  def bounds():
   b,f=measure(scratch)
   if b>budget or f>filelimit:raise ValueError('scratch bounds')
   return {'bytes':b,'files':f,'byteLimit':budget,'fileLimit':filelimit}
  result['before']=bounds()
  runtime=scratch/'.qualification-runtime';runtime.mkdir()
  env={'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':str(runtime/'home'),'TMPDIR':str(runtime/'tmp'),'XDG_CACHE_HOME':str(cache),'XDG_STATE_HOME':str(runtime/'state'),'XDG_CONFIG_HOME':str(runtime/'config'),'COREPACK_HOME':str(corepack),'COREPACK_ENABLE_NETWORK':'0','COREPACK_DEFAULT_TO_LATEST':'0','COREPACK_ENABLE_DOWNLOAD_PROMPT':'0','CI':'true','npm_config_update_notifier':'false'}
  for key in ['HOME','TMPDIR','XDG_STATE_HOME','XDG_CONFIG_HOME']:pathlib.Path(env[key]).mkdir()
  argv=[str(pnpm),'install','--lockfile-only','--offline','--frozen-lockfile','--ignore-scripts','--ignore-pnpmfile','--store-dir='+str(store)]
  result.update(argv=argv,env=env,metadataBytes=sum((source/r).stat().st_size for r in before),cacheCopiedBytes=0,dependenciesCopiedBytes=0)
  stage='pnpm-offline-frozen'
  try:
   if runner is None:
    with (out/'pnpm.stdout').open('xb') as so,(out/'pnpm.stderr').open('xb') as se:
     command=subprocess.run(argv,cwd=str(scratch),env=env,stdin=subprocess.DEVNULL,stdout=so,stderr=se,timeout=300)
    if (out/'pnpm.stdout').stat().st_size>1048576 or (out/'pnpm.stderr').stat().st_size>1048576:raise ValueError('command log budget exceeded')
    r=subprocess.CompletedProcess(argv,command.returncode,stdout=(out/'pnpm.stdout').read_bytes(),stderr=(out/'pnpm.stderr').read_bytes())
   else:r=runner(argv,cwd=str(scratch),env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=300)
  except Exception as e:r=subprocess.CompletedProcess(argv,125,stdout=b'',stderr=(type(e).__name__+': '+str(e)).encode());result['runnerError']=str(e)
  result.update(commandExit=r.returncode,stdoutSha256=hashlib.sha256(r.stdout).hexdigest(),stderrSha256=hashlib.sha256(r.stderr).hexdigest(),stderrPreview=r.stderr[:2048].decode('utf8','replace'))
  stage='postflight';faults=[]
  try:result['after']=bounds()
  except Exception as e:faults.append(str(e))
  if metadata(source)!=before:faults.append('immutable source drift')
  if metadata(scratch)!=before:faults.append('scratch metadata/lock drift')
  try:
   if cache_inventory(cache)!=cachebefore:faults.append('readonly cache topology/bytes drift')
  except Exception as e:faults.append('readonly cache topology: '+str(e))
  if faults:raise ValueError(';'.join(faults))
  if r.returncode:stage='pnpm-offline-frozen';raise ValueError('package manager exit '+str(r.returncode))
  result.update(exit=0,actualPnpmQualified=not fixture,status='FIXTURE_PASS' if fixture else 'OFFLINE_FROZEN_PASS')
 except Exception as e:result.update(stage=stage,error=type(e).__name__+': '+str(e),status='FAIL')
 if admitted:(out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
 else:print(json.dumps(result),file=sys.stderr)
 return result

if __name__=='__main__':
 spec=json.loads(pathlib.Path(sys.argv[1]).read_bytes());r=qualify(spec);print(json.dumps(r));sys.exit(r['exit'])

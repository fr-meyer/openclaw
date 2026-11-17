#!/usr/bin/env python3
"""Future-authority-only phase1: source assembly, inert image acquisition, trusted observation, offline/noop.
No product command, compiler, lint, native probe, workflow mutation, push or rerun exists here.
"""
import argparse,base64,gzip,hashlib,json,os,pathlib,selectors,shutil,signal,stat,subprocess,sys,time,uuid
HERE=pathlib.Path(__file__).resolve().parent;TOOLS=HERE.parent
G=2**30;M=2**20;FLOOR=8*G;RESERVATION=12*G;NOOP=['/usr/local/bin/node','/opt/layout/phase1-noop.mjs']
BASE_IMAGE='node:24.16.0-bookworm@sha256:0fff24ba994c5450728278d000f7e8395ac22a8832b9f295723cf9411dae8df0'
class Gate(RuntimeError):pass
def sha(b):return hashlib.sha256(b).hexdigest()
def load(p):return json.loads(pathlib.Path(p).read_text())
def put(p,v):pathlib.Path(p).write_text(json.dumps(v,indent=2,ensure_ascii=False)+chr(10))
def prepare_image_tree(root):
 """Only generated container-bound stage: never authority/domain/source input.
 Normalize directories and read/execute bits while preserving Git owner-exec identity.
 Never follow/chmod symlinks or modify bytes; no world writes.
 """
 root=pathlib.Path(root)
 if root.is_symlink() or not root.is_dir():raise Gate('image stage directory required')
 for parent,dirs,files in os.walk(root,followlinks=False):
  base=pathlib.Path(parent);base.chmod(0o755)
  for name in [*dirs,*files]:
   p=base/name;mode=p.lstat().st_mode
   if stat.S_ISLNK(mode):continue
   if stat.S_ISDIR(mode):p.chmod(0o755)
   elif stat.S_ISREG(mode):p.chmod(0o755 if mode&stat.S_IXUSR else 0o644)
   else:raise Gate('special file in image stage')
 # Read actual staged metadata before Docker cp, not a declared permission flag.
 for parent,dirs,files in os.walk(root,followlinks=False):
  for p in [pathlib.Path(parent),*[pathlib.Path(parent)/x for x in [*dirs,*files]]]:
   mode=p.lstat().st_mode
   if stat.S_ISLNK(mode):continue
   if stat.S_IMODE(mode)!=(0o755 if stat.S_ISDIR(mode) or mode&stat.S_IXUSR else 0o644):raise Gate('image stage reader mode mismatch')
def identity_guard(project,env):
 if env.get('OPENCLAW_PHASE1_OWNER_AUTHORIZED')!=sha((HERE/'authorization-scope.json').read_bytes()) or env.get('GITHUB_ACTIONS')!='true' or env.get('GITHUB_REPOSITORY')!='fr-meyer/openclaw' or env.get('GITHUB_REF')!='refs/heads/ci/offline-provider-regressions-20261116' or env.get('GITHUB_RUN_ATTEMPT')!='1' or project not in ['bfl','embeddings']:raise Gate('future owner/publication/one-attempt workflow identity gate')
def payload_guard():
 pins=load(HERE/'PAYLOAD-SHA256.json')
 for name,digest in pins.items():
  p=TOOLS.parents[1]/name
  if p.is_symlink() or sha(p.read_bytes())!=digest:raise Gate('reviewed payload pin mismatch')
 return pins
class Flow:
 def __init__(self,args):
  self.args=args;self.project=args.project;self.work=pathlib.Path(args.work).resolve();self.artifacts=pathlib.Path(args.artifacts).resolve();self.source=pathlib.Path(args.candidate).resolve();self.carrier=pathlib.Path(args.carrier).resolve();self.token=uuid.uuid4().hex;self.deadline=time.monotonic()+2380;self.images=[];self.resources=[];self.logbytes=0;self.docker=shutil.which('docker');self.node=shutil.which('node');self.dockerRoot=None;self.dockerBaseline=0;self.stage='admission';self.cleanupOK=True
 def artifact(self,name,value):
  if name not in ['result.json','resources.json','graph.json','provenance.json','failure.json']:raise Gate('artifact whitelist')
  data=(json.dumps(value,indent=2)+chr(10)).encode();used=sum(p.stat().st_size for p in self.artifacts.glob('*.json'))
  if len(data)>8*M or used+len(data)>64*M:raise Gate('public artifact byte budget')
  (self.artifacts/name).write_bytes(data)
 def floor(self):
  if shutil.disk_usage(self.workerContext['hostParent']).free<FLOOR:raise Gate('8GiB host free-space floor; no resize/prune authorized')
 def call(self,argv,seconds=60,allow=False):
  if time.monotonic()>=self.deadline:raise Gate('phase1 overall deadline')
  self.floor();p=subprocess.Popen([str(x) for x in argv],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env=self.workerContext['engineEnv'] if getattr(self,'workerContext',None) else {'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':str(self.work/'home'),'GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_NOSYSTEM':'1','GIT_OPTIONAL_LOCKS':'0'})
  sel=selectors.DefaultSelector();sel.register(p.stdout,selectors.EVENT_READ,'out');sel.register(p.stderr,selectors.EVENT_READ,'err');buffers={'out':bytearray(),'err':bytearray()};end=min(self.deadline,time.monotonic()+seconds)
  try:
   while sel.get_map():
    self.floor()
    if time.monotonic()>end:raise Gate('command timeout; whole-domain abort required before acceptance')
    for key,_ in sel.select(timeout=1):
     b=os.read(key.fileobj.fileno(),65536)
     if not b:sel.unregister(key.fileobj);continue
     self.logbytes+=len(b);buffers[key.data].extend(b)
     if len(buffers['out'])+len(buffers['err'])>16*M or self.logbytes>64*M:raise Gate('bounded aggregate host receipt output exceeded')
   code=p.wait(timeout=5)
  except BaseException:
   self.cleanupOK=False
   try:os.killpg(p.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   p.wait(timeout=10);raise
  finally:sel.close()
  if code and not allow:raise Gate('command nonzero at '+self.stage+': '+pathlib.Path(str(argv[0])).name)
  return code,bytes(buffers['out']),bytes(buffers['err'])
 def jsoncall(self,args,seconds=60):return json.loads(self.call(args,seconds)[1])
 def docker_call(self,args,seconds=60,allow=False):return self.call([self.docker,*args],seconds,allow)
 def inspect(self,image):return self.jsoncall([self.docker,'image','inspect',image])[0]
 def allocated(self):
  root=pathlib.Path(self.workerContext['context']);v=os.statvfs(root)
  return (v.f_blocks-v.f_bfree)*v.f_frsize
 def resources_check(self):
  self.floor();allocated=self.allocated();delta=max(0,allocated-self.dockerBaseline)
  rows=[self.inspect(i['id']) for i in self.images];leaf=[]
  for item in rows:
   layers=item['RootFS']['Layers']
   if not any(len(other['RootFS']['Layers'])>len(layers) and other['RootFS']['Layers'][:len(layers)]==layers for other in rows):leaf.append(item)
  virtual=sum(v['Size'] for v in {x['Id']:x for x in leaf}.values())
  context=self.call(['/usr/bin/du','--summarize','--block-size=1',self.work],60)[1];contextBytes=int(context.split()[0])
  if virtual>8*G or delta>8*G or contextBytes>2*G:raise Gate('observed immutable/layer/context allocation ceiling')
  self.resources.append({'stage':self.stage,'dockerAllocatedBytes':allocated,'dockerDeltaBytes':delta,'leafRootfsUpperBound':virtual,'images':[{'id':v['Id'],'size':v['Size'],'layers':v['RootFS']['Layers']} for v in rows],'contextAllocatedBytes':contextBytes,'hostFreeBytes':shutil.disk_usage(self.workerContext['hostParent']).free})
 def assemble(self,binding):
  if self.call(['/usr/bin/git','-C',self.source,'rev-parse','HEAD'])[1].decode().strip()!=binding['base']:raise Gate('candidate base mismatch')
  self.call(['/usr/bin/git','-C',self.source,'diff','--exit-code']);self.call(['/usr/bin/git','-C',self.source,'diff','--cached','--exit-code'])
  if self.call(['/usr/bin/git','-C',self.source,'ls-files','--others','--exclude-standard'])[1].strip():raise Gate('untracked candidate input')
  p=HERE/'bfl73.patch.gz' if self.project=='bfl' else self.carrier/binding['patchPath'];data=gzip.decompress(p.read_bytes())
  if len(data)>2*M or sha(data)!=binding['patchSha256']:raise Gate('exact accepted public patch mismatch')
  patch=self.work/'source.patch';patch.write_bytes(data);self.call(['/usr/bin/git','-C',self.source,'apply','--index','--whitespace=error',patch],60)
  if self.call(['/usr/bin/git','-C',self.source,'write-tree'])[1].decode().strip()!=binding['expectedCandidateTree']:raise Gate('BFL73/embeddings full tree mismatch')
  names=self.call(['/usr/bin/git','-C',self.source,'diff','--cached','--name-only',binding['base']])[1].decode().splitlines()
  if sorted(names)!=sorted(binding['files']):raise Gate('complete patch path set mismatch')
  for name,digest in binding['files'].items():
   if sha((self.source/name).read_bytes())!=digest:raise Gate('accepted source file pin mismatch')
  entries=[];metadata=[];raw=self.call(['/usr/bin/git','-C',self.source,'ls-files','--stage','-z'])[1]
  for row in raw.split(bytes([0])):
   if not row:continue
   head,name=row.split(bytes([9]),1);mode,oid,stage=head.decode().split();name=name.decode();p=self.source/name
   if stage!='0' or mode not in ['100644','100755','120000']:raise Gate('unsupported source tracked entry')
   data=os.readlink(p).encode() if mode=='120000' else p.read_bytes();entry={'path':name,'mode':mode,'oid':oid,'sha256':sha(data)};entries.append(entry)
   parts=name.split('/');take=name in ['package.json','pnpm-lock.yaml','pnpm-workspace.yaml','.npmrc'] or p.name=='package.json' and parts[0] in ['packages','extensions','examples','ui'] or parts[0]=='patches'
   if take:metadata.append({'path':name,'mode':mode,'bytes':len(data),'sha256':sha(data)})
  entries.sort(key=lambda e:e['path']);metadata.sort(key=lambda e:e['path']);tracked=self.work/'tracked.json';put(tracked,entries)
  config={'sourceRoot':str(self.source),'trackedManifest':str(tracked),'expectedTrackedManifestSha256':sha(tracked.read_bytes()),'expectedTree':binding['expectedCandidateTree'],'expectedLockSha256':sha((self.source/'pnpm-lock.yaml').read_bytes()),'expectedMetadataSha256':sha((json.dumps(metadata,indent=2,ensure_ascii=False)+chr(10)).encode()),'sourceLimitBytes':512*M,'sourceFileLimit':200000,'singleSourceFileLimitBytes':64*M,'metadataLimitBytes':64*M,'immutableLimitBytes':8*G,'receiptLimitBytes':16*M,'sdkRootIds':binding['sdkRootIds'],'uiBindingNames':binding['uiBindingNames']}
  return config
 def api(self,mode,config,target,image=None):
  file=self.work/'config.json';put(file,config);argv=[self.node,HERE/'phase1-api.mjs',mode,file,target]+([image] if image else []);out=self.call(argv,330 if mode=='runtime' else 120)[1]
  return out if mode=='runtime' else json.loads(out)
 def image_register(self,image,kind):
  info=self.inspect(image)
  if kind!='node-base' and info['Config'].get('Labels',{}).get('openclaw.phase1.token')!=self.token:raise Gate('owned image label mismatch')
  self.images.append({'id':info['Id'],'kind':kind})
 def build(self,context,network,kind):
  # Every pull/cp/commit, including daemon-side writers, is inside the outer
  # BoundedEngineDomain.run_phase. No shared daemon, BuildKit or legacy BUILD.
  context=pathlib.Path(context);recipe=(context/'Dockerfile').read_text();dependency=network=='default'
  if dependency:
   expected=getattr(self,'inertPrepared',{}).get('dockerfileSha256')
   if not expected or sha(recipe.encode())!=expected:raise Gate('accepted inert recipe pin mismatch')
   self.docker_call(['pull',BASE_IMAGE],330);base=self.inspect(BASE_IMAGE)['Id'];self.image_register(base,'node-base')
   command=['/usr/bin/timeout','1200','/usr/local/bin/node','/opt/layout/acquire-recipe.mjs'];user='0:0'
  else:
   lines=recipe.splitlines()
   if len(lines)!=7 or lines[0]!='ARG DEPENDENCY_IMAGE' or not lines[1].startswith('FROM sha256:') or lines[2:5]!=['COPY source/ /app/','COPY git/ /app/.git/','COPY trusted/ /opt/layout/'] or not lines[5].startswith('LABEL org.openclaw.layout.receipt-sha256=') or lines[6]!='WORKDIR /app':raise Gate('exact inert COPY-only finalization recipe required')
   base=lines[1].split(' ',1)[1];command=['/usr/local/bin/node','-e',''];user='1000:1000'
  name='phase1-'+self.token+'-'+kind
  create=['create','--name',name,'--network',network,'--cpus','2','--memory',str(6*G),'--memory-swap',str(6*G),'--pids-limit','512','--cap-drop','ALL','--security-opt','no-new-privileges','--user',user,'--log-driver','none','--workdir','/app','--label','openclaw.phase1.token='+self.token]
  if dependency:
   for value in ['CI=true','COREPACK_HOME=/opt/corepack','COREPACK_ENABLE_DOWNLOAD_PROMPT=0','COREPACK_DEFAULT_TO_LATEST=0','PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1','XDG_CACHE_HOME=/opt/offline-cache']:create+=['--env',value]
  cid=self.docker_call([*create,base,*command])[1].decode().strip()
  try:
   before=self.jsoncall([self.docker,'container','inspect',cid])[0];h=before['HostConfig']
   if before['Image']!=base or before['Config'].get('Labels',{}).get('openclaw.phase1.token')!=self.token or before['Config'].get('User')!=user or h.get('NetworkMode')!=network or h.get('NanoCpus')!=2_000_000_000 or h.get('Memory')!=6*G or h.get('MemorySwap')!=6*G or h.get('PidsLimit')!=512 or h.get('Privileged') or h.get('Devices') or h.get('Binds') or h.get('CapAdd') or h.get('CapDrop')!=['ALL'] or not any(v in ['no-new-privileges','no-new-privileges:true'] for v in h.get('SecurityOpt',[])):raise Gate('actual owned assembly/acquisition before-start sandbox mismatch')
   if dependency:
    layout=self.work/'acquisition-layout';layout.mkdir()
    for name in ['no-copy-layout.mjs','openclaw-image-dependency-projector.mjs','inert-manifest.json']:shutil.copyfile(context/name,layout/name)
    shutil.copyfile(context/'Dockerfile',layout/'dependency-Dockerfile');shutil.copyfile(HERE/'acquire-recipe.mjs',layout/'acquire-recipe.mjs')
    prepare_image_tree(context/'manifests');prepare_image_tree(layout)
    self.docker_call(['cp',str(context/'manifests')+'/.',cid+':/app'],120);self.docker_call(['cp',str(layout)+'/.',cid+':/opt/layout'],120)
    self.docker_call(['start','--attach',cid],1230);code=int(self.docker_call(['wait',cid])[1]);after=self.jsoncall([self.docker,'container','inspect',cid])[0]
    if after['State']['Running'] or after['State']['ExitCode']!=code or code:raise Gate('trusted dependency acquisition not terminal-success')
   else:
    for folder,dest in [('source','/app'),('git','/app/.git'),('trusted','/opt/layout')]:
     prepare_image_tree(context/folder);self.docker_call(['cp',str(context/folder)+'/.',cid+':'+dest],180)
   commit=['commit','--change','LABEL openclaw.phase1.token='+self.token]
   if not dependency:commit+=['--change','LABEL org.openclaw.layout.receipt-sha256='+sha((context/'trusted/layout-receipt.json').read_bytes())]
   image=self.docker_call([*commit,cid],330)[1].decode().strip();self.image_register(image,kind);self.resources_check();return image
  finally:self.remove_container(cid)
 def extract_snapshot(self,image):
  cid=self.docker_call(['create','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','512','--user','1000:1000','--label','openclaw.phase1.token='+self.token,image,'/usr/local/bin/node','-e',''])[1].decode().strip()
  try:self.docker_call(['cp',cid+':/opt/layout/image-manifest.json',str(self.work/'base-snapshot.json')]);return self.work/'base-snapshot.json'
  finally:self.remove_container(cid)
 def remove_container(self,cid):
  info=self.jsoncall([self.docker,'container','inspect',cid])[0]
  if info['Config'].get('Labels',{}).get('openclaw.phase1.token')!=self.token or info['State']['Running']:raise Gate('refuse unrelated/running container cleanup')
  self.docker_call(['rm',cid]);code,out,err=self.docker_call(['container','inspect',cid],allow=True)
  if code!=1 or not any(t in err.decode() for t in ['No such container','No such object']):raise Gate('container absence unproved')
 def remove_image(self,image):
  item=next(v for v in self.images if v['id']==image);info=self.inspect(image)
  if item['kind']=='node-base':
   if BASE_IMAGE.split('@')[1] not in [x.split('@')[-1] for x in info.get('RepoDigests',[])]:raise Gate('pulled base identity drift')
  elif info['Config'].get('Labels',{}).get('openclaw.phase1.token')!=self.token:raise Gate('owned image cleanup identity mismatch')
  self.docker_call(['image','rm',image]);self.images.remove(item)
 def preflight(self):
  if not getattr(self,'workerContext',None):raise Gate('must execute inside the owned Domain.run_phase worker')
  env=self.workerContext['engineEnv']
  if not env.get('DOCKER_HOST','').startswith('unix:///') or env['DOCKER_HOST'] in ['unix:///var/run/docker.sock','unix:///run/docker.sock']:raise Gate('isolated engine endpoint required')
  root=pathlib.Path(self.workerContext['context']).resolve();domainDev=root.stat().st_dev;fs=os.statvfs(root)
  if self.work!=root/'phase1-private' or self.work.stat().st_dev!=domainDev or fs.f_blocks*fs.f_frsize>12*G:raise Gate('actual bounded filesystem identity/capacity mismatch')
  info=self.jsoncall([self.docker,'info','--format','{{json .}}'])
  data=pathlib.Path(info['DockerRootDir']).resolve()
  if info.get('Driver')!='overlay2' or data.stat().st_dev!=domainDev or any('snapshotter' in str(v).lower() or 'containerd' in str(v).lower() for row in info.get('DriverStatus',[]) for v in row):raise Gate('owned classic engine data outside bounded filesystem')
  self.dockerRoot=str(data);self.dockerBaseline=0
 def run(self):
  identity_guard(self.project,os.environ);payload_guard()
  if self.work.exists() or self.artifacts.exists():raise Gate('fresh private work/artifact directories required')
  self.work.mkdir();self.artifacts.mkdir();(self.work/'home').mkdir()
  config=None;observed=None;qualified=False;failure=None
  try:
   head=self.call(['/usr/bin/git','-C',TOOLS.parents[1],'rev-parse','HEAD'])[1].decode().strip()
   if head!=os.environ.get('GITHUB_SHA'):raise Gate('actual tooling checkout differs from event SHA')
   self.call(['/usr/bin/git','-C',TOOLS.parents[1],'diff','--exit-code']);self.call(['/usr/bin/git','-C',TOOLS.parents[1],'diff','--cached','--exit-code'])
   self.stage='host-resource-preflight';self.preflight();binding=load(HERE/'bindings.json')['projects'][self.project];self.stage='source-assembly';config=self.assemble(binding)
   self.stage='inert-metadata-only';context=self.work/'inert';prepared=self.api('inert',config,context);self.inertPrepared=prepared;base=self.build(context,'default','dependency');snapshot=self.extract_snapshot(base)
   if snapshot.stat().st_size>64*M:raise Gate('base receipt byte budget')
   baseReceipt=self.work/'base-image.json';put(baseReceipt,{'id':base,'size':self.inspect(base)['Size'],'snapshotSha256':sha(snapshot.read_bytes())})
   config.update(baseSnapshot=str(snapshot),baseImageReceipt=str(baseReceipt),expectedBaseSnapshotSha256=sha(snapshot.read_bytes()),expectedBaseImageReceiptSha256=sha(baseReceipt.read_bytes()),expectedDependencyRecipeSha256=prepared['dockerfileSha256'])
   adapter=self.work/'phase1-docker.py';shutil.copyfile(HERE/'phase1-docker.py',adapter);adapter.chmod(0o755);put(adapter.with_suffix('.json'),{'docker':self.docker,'proof':str(self.work/'runtime-proof.ndjson'),'engine_env':self.workerContext['engineEnv']})
   config.update(externalExecution=True,executionApprovalSha256=sha((HERE/'authorization-scope.json').read_bytes()),hostDiskFloorValidated=True,ownedContainerCleanupApproved=True,dockerBinary=str(adapter),uid=1000,gid=1000,timeoutSeconds=300,fullValidation=False)
   config['extraTrustedModules']=[{'name':'phase1-observer.mjs','file':str(HERE/'phase1-observer.mjs'),'sha256':sha((HERE/'phase1-observer.mjs').read_bytes())}]
   self.stage='offline-copy-only-probe-compose';context=self.work/'probe';r=self.api('compose',config,context);probe=self.build(context,'none','probe');config.update(finalImageId=probe,receiptSha256=r['receiptSha256'],command=['/usr/local/bin/node','/opt/layout/phase1-observer.mjs'])
   self.stage='strict-network-none-probe';output=self.api('runtime',config,context/'trusted/layout-receipt.json',probe).decode();lines=[s.split('=',1)[1] for s in output.splitlines() if s.startswith('PHASE1_OBSERVATION=')]
   if len(lines)!=1:raise Gate('actual observer receipt absent');
   observed=json.loads(base64.b64decode(lines[0]));
   if observed.get('phase')!='NETWORK_NONE_ACTUAL_GRAPH_AND_DISTRIBUTION_OBSERVATION' or observed.get('productQualified') is not False or len(observed.get('sdkRootIds',[]))!=62 or len(observed.get('uiBindingNames',[]))!=52 or not observed.get('graph') or not observed.get('metadata') or not observed.get('pnpm',{}).get('distribution',{}).get('entries') or not observed.get('corepackDistribution',{}).get('entries'):raise Gate('complete actual graph/distribution receipt required')
   if observed['candidateTree']!=binding['expectedCandidateTree'] or observed['receiptSha256']!=r['receiptSha256'] or observed['sdkRootIds']!=binding['sdkRootIds'] or observed['uiBindingNames']!=binding['uiBindingNames']:raise Gate('actual strict graph/source receipt mismatch')
   self.remove_image(probe)
   shutil.rmtree(context) # Generated COPY-only probe context, after captured observation.
   graphReceipt={'pnpmVersion':observed['pnpm']['version'],'immutableImageId':base,'candidateRoot':'/app','candidateMetadata':observed['metadata'],'completeInstalledGraph':True,'provenance':{'actualProbeImageId':probe,'probeLayoutReceiptSha256':r['receiptSha256'],'graphSha256':observed['graphSha256'],'observationSha256':sha(json.dumps(observed,sort_keys=True).encode()),'baseSnapshotSha256':config['expectedBaseSnapshotSha256'],'candidateTree':binding['expectedCandidateTree'],'pnpmDistributionSha256':observed['pnpm']['distribution']['inventorySha256'],'corepackDistributionSha256':observed['corepackDistribution']['inventorySha256'],'runtimeActualQuotaProofSha256':sha((self.work/'runtime-proof.ndjson').read_bytes())}}
   graphfile=self.work/'offline-image-receipt.json';put(graphfile,graphReceipt)
   spec={'source':'/app','scratch':'/qualification/workspace','cache':'/opt/offline-cache','store':'/opt/offline-store','corepack':'/opt/corepack','output':'/qualification/output','pnpm':'/usr/local/bin/pnpm','pnpmCanonical':observed['pnpm']['canonical'],'pnpmSha256':observed['pnpm']['shimSha256'],'metadata':observed['metadata'],'cacheHashes':observed['cacheHashes'],'imageReceipt':'/opt/layout/offline-image-receipt.json','imageReceiptSha256':sha(graphfile.read_bytes()),'scratchByteLimit':64*M,'scratchFileLimit':10000,'timeoutSeconds':180,'hardQuotaAttested':True,'readOnlyMountsAttested':True}
   # These booleans describe already measured prior probe plus unchanged accepted guard's actual checks.
   # They never admit an image on their own: final guard verifies actual mounts/graph before recipe.
   specfile=self.work/'offline-spec.json';put(specfile,spec)
   baselinefile=self.work/'phase1-baseline.json';put(baselinefile,{'python':observed['python'],'pnpmDistribution':observed['pnpm']['distribution'],'corepackDistribution':observed['corepackDistribution']})
   config['extraTrustedModules']=[{'name':name,'file':str(file),'sha256':sha(file.read_bytes())} for name,file in [('offline_lock.py',TOOLS/'offline_lock.py'),('offline-spec.json',specfile),('offline-image-receipt.json',graphfile),('phase1-baseline.json',baselinefile),('phase1-noop.mjs',HERE/'phase1-noop.mjs'),('phase1-observer.mjs',HERE/'phase1-observer.mjs')]];config['offlineQualification']={'pythonCanonical':observed['python']['canonical'],'pythonSha256':observed['python']['sha256']}
   self.stage='final-offline-copy-only-compose';context=self.work/'final';r=self.api('compose',config,context);final=self.build(context,'none','final');config.update(finalImageId=final,receiptSha256=r['receiptSha256'],command=NOOP)
   self.stage='genuine-offline-then-constant-trusted-noop';self.resources_check();output=self.api('runtime',config,context/'trusted/layout-receipt.json',final).decode()
   if output.count('PHASE1_TRUSTED_NOOP')!=1 or output.count('PHASE1_POSTFLIGHT=')!=1:raise Gate('constant trusted noop terminal marker absent')
   self.resources_check();qualified=True
   self.artifact('graph.json',{'candidateTree':observed['candidateTree'],'probeImageId':probe,'finalImageId':final,'graph':observed['graph'],'graphSha256':observed['graphSha256'],'productQualified':False})
   self.artifact('provenance.json',{'graphReceipt':graphReceipt,'python':observed['python'],'pnpm':observed['pnpm'],'corepackDistribution':observed['corepackDistribution'],'measures':observed['measures'],'actualRuntimeQuotas':[json.loads(x) for x in (self.work/'runtime-proof.ndjson').read_text().splitlines()],'postflight':'actual full Python/pnpm/Corepack provenance rehashed before/after fixed trusted NOOP; accepted guard additionally rehashes protected/source/Git'})
  except Exception as e:self.cleanupOK=False;failure={'stage':self.stage,'kind':type(e).__name__,'reason':str(e)[:1024],'termination':'unverified if timeout/client killed; never infer successful postflight'};self.artifact('failure.json',failure)
  finally:
   for item in list(reversed(self.images)):
    try:self.remove_image(item['id'])
    except Exception:self.cleanupOK=False
   self.artifact('resources.json',{'samples':self.resources,'ceilings':{'immutableAndLayerBytes':8*G,'modulesBytes':3*G,'cacheBytes':256*M,'runtimeWritableBytes':2*G,'contextBytes':2*G,'hostFloorBytes':FLOOR,'initialReservationBytes':RESERVATION,'cpu':2,'memoryBytes':6*G,'pids':512},'cleanupOwnedOnlyVerified':self.cleanupOK,'noPruneOrDiskResize':True,'allocationEnforcement':'outer BoundedEngineDomain physical filesystem capacity/backstop and whole-writer cgroup;8GiB immutable/2GiB context monitored thresholds, shared12GiB capacity'})
   self.artifact('result.json',{'status':'PHASE1_IMAGE_FEASIBILITY_PASS' if qualified and self.cleanupOK else 'PHASE1_FAILED_CLOSED','project':self.project,'toolingHead':os.environ.get('GITHUB_SHA'),'runId':os.environ.get('GITHUB_RUN_ID'),'reviewedPayloadManifestSha256':sha((HERE/'PAYLOAD-SHA256.json').read_bytes()),'authorizationScopeSha256':sha((HERE/'authorization-scope.json').read_bytes()),'sourceBindingSha256':sha((HERE/'bindings.json').read_bytes()),'candidateTree':config.get('expectedTree') if config else None,'productQualified':False,'fullValidationExecuted':False,'ownedCleanupVerified':self.cleanupOK,'failureStage':failure['stage'] if failure else None})
  return 0 if qualified and self.cleanupOK else 1

def main(argv=None):
 import importlib.util
 p=HERE/'phase1-supervisor.py';spec=importlib.util.spec_from_file_location('trusted_supervisor',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m.main(argv)
if __name__=='__main__':
 try:sys.exit(main())
 except Exception as e:print('PHASE1_ADMISSION_FAILED_CLOSED: '+str(e),file=sys.stderr);sys.exit(1)

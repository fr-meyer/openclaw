"""Actual Docker transport for inspected owned acquisition and readonly storage observation.
No Docker process is launched at import. P2 provides only the storage/finalization plan.
"""
import json,os,pathlib,re,stat,time,uuid
from bounded_resource import OwnedResource,Unverified,supervise,classic_storage,kernel_caps
G=2**30;LIMITS={'nanoCpus':2_000_000_000,'memory':6*G,'pids':512}
def mountinfo(text):
 rows=[]
 for line in text.splitlines():
  left,right=line.split(' - ',1);a=left.split();b=right.split()
  path=re.sub(r'\\([0-7]{3})',lambda m:chr(int(m[1],8)),a[4])
  rows.append({'path':path,'device':a[2],'type':b[0]})
 return rows
class Transport:
 def __init__(self,flow):self.flow=flow;self.owned={};self.proofs=[]
 def invoke(self,args,seconds=30,allow=False):return self.flow.docker_call(args,seconds,allow)
 def info(self):return json.loads(self.invoke(['info','--format','{{json .}}'])[1])
 def inspect(self,cid):return json.loads(self.invoke(['container','inspect',cid])[1])[0]
 def __call__(self,action,cid):
  if action=='inspect':return self.inspect(cid)
  if action=='exists':
   code,out,err=self.invoke(['container','inspect',cid],allow=True)
   if code==0:return True
   if code!=1 or not any(s in err.decode() for s in ['No such container','No such object']):raise Unverified('absence query itself unverified')
   return False
  command={'start':['start',cid],'kill':['kill','--signal','KILL',cid],'wait':['wait',cid],'remove':['rm',cid]}[action]
  result=self.invoke(command,15)
  if action=='remove':self.owned.pop(cid,None)
  return result
 def create(self,image,command,mounts,network='none',user='1000:1000',limits=LIMITS):
  if not re.fullmatch(r'sha256:[0-9a-f]{64}',image):raise Unverified('actual cached opaque image required; no implicit pull')
  name='phase1-'+self.flow.token+'-'+uuid.uuid4().hex[:8]
  args=['create','--name',name,'--label','openclaw.phase1.token='+self.flow.token,'--pull','never','--read-only','--network',network,'--user',user,'--cap-drop','ALL','--security-opt','no-new-privileges','--cpus',str(limits['nanoCpus']/1e9),'--memory',str(limits['memory']),'--memory-swap',str(limits['memory']),'--pids-limit',str(limits['pids']),'--log-driver','none']
  for entry in mounts:
   if ',' in entry['source'] or ',' in entry['target'] or not entry['source'].startswith('/') or not entry['target'].startswith('/'):raise Unverified('canonical mount path required')
   option='type=bind,src='+entry['source']+',dst='+entry['target']+(',readonly' if entry['readonly'] else '')
   if entry.get('nonrecursive'):option+=',bind-recursive=disabled'
   args+=['--mount',option]
  # Name is journaled before daemon CREATE; failures must resolve this name, never infer absence.
  self.owned[name]={'name':name,'image':image,'stage':'creating'}
  cid=self.invoke(args+[image,*command])[1].decode().strip()
  resource=OwnedResource(self,cid,image,self.flow.token,limits)
  self.owned.pop(name);self.owned[cid]={'name':name,'image':image,'stage':'created'}
  try:
   info=self.inspect(cid);resource.identity(info)
   h=info['HostConfig']
   if h.get('NetworkMode')!=network or not h.get('ReadonlyRootfs') or info['Config'].get('User')!=user:raise Unverified('actual acquisition sandbox mismatch')
   actual=sorted((m['Source'],m['Destination'],not m['RW']) for m in info.get('Mounts',[]))
   expected=sorted((m['source'],m['target'],m['readonly']) for m in mounts)
   if actual!=expected:raise Unverified('actual acquisition mount map mismatch')
  except BaseException:
   resource.cancel_and_remove();raise
  return resource
 def execute(self,image,command,mounts,sample,network='none',user='1000:1000',timeout=1200,limits=LIMITS):
  resource=self.create(image,command,mounts,network,user,limits)
  proof=supervise(resource,sample,lambda:not self.inspect(resource.id)['State']['Running'],timeout=timeout)
  self.proofs.append({'id':resource.id,'image':image,'network':network,'limits':limits,**proof})
  return proof
 def observe(self,image,root,script,host_mounts):
  # Trusted code only, no Docker socket, no host file-content reads; recursive binds disabled.
  mounts=[{'source':root,'target':'/observed','readonly':True,'nonrecursive':True},{'source':str(script.resolve()),'target':'/observer.mjs','readonly':True}]
  limits={'nanoCpus':250_000_000,'memory':256*2**20,'pids':16}
  resource=self.create(image,['/usr/local/bin/node','/observer.mjs'],mounts,user='0:0',limits=limits)
  try:
   before=resource.inspect();resource.identity(before);kernel_caps(before,image,self.flow.token,limits)
   code,out,err=self.invoke(['start','--attach',resource.id],30)
   after=resource.inspect();resource.identity(after)
   if after['State']['Running'] or after['State'].get('ExitCode')!=0:raise Unverified('physical observation partial/read failure')
   receipt=json.loads(out)
   if receipt.get('schema')!=1 or receipt.get('complete') is not True or not isinstance(receipt.get('allocatedBytes'),int) or receipt['allocatedBytes']<0:raise Unverified('physical observer receipt invalid')
   return receipt
  finally:resource.cancel_and_remove()
 def acquire(self,image,mounts,sample,command):
  # Only a fixed, internally generated metadata recipe is admissible, never caller product argv.
  if command[0:2]!=['/usr/local/bin/node','/opt/layout/acquire-recipe.mjs']:raise Unverified('trusted acquisition entrypoint required')
  if not any(m['target']=='/app' for m in mounts):raise Unverified('owned inert metadata root required')
  if any(m['target'] in ['/var/run/docker.sock','/run/docker.sock'] for m in mounts):raise Unverified('no daemon socket in acquisition')
  return self.execute(image,command,mounts,sample,network='default')

 def discover(self,image,script):
  info=self.info();root=info.get('DockerRootDir','')
  if info.get('Driver')!='overlay2' or any('containerd' in str(v).lower() or 'snapshotter' in str(v).lower() for row in info.get('DriverStatus',[]) for v in row):raise Unverified('unsupported storage backend BEFORE acquisition')
  if not root.startswith('/') or os.path.realpath(root)!=root or os.path.islink(root):raise Unverified('noncanonical Docker storage root')
  census=mountinfo(pathlib.Path('/proc/self/mountinfo').read_text())
  data=self.observe(image,root,script,census)
  device=int(data['rootDevice']);facts={'readable':True,'symlink':False,'device':str(os.major(device))+':'+str(os.minor(device))}
  admitted=classic_storage(info,census,facts)
  if mountinfo(pathlib.Path('/proc/self/mountinfo').read_text())!=census:raise Unverified('mount census changed during complete observation')
  admitted.update(observation=data,complete=True,observerReadOnly=True)
  return admitted

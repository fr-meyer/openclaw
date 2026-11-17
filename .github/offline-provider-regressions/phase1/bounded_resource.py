"""Source-only R2 repair primitives. Not wired into an acquisition route yet.
All external effects go through an injected Docker transport; no subprocess at import.
"""
import json,time
class Unverified(RuntimeError):pass

def classic_storage(info,mounts,root_stat,owned_merged=()):
 root=info.get('DockerRootDir','');driver=info.get('Driver')
 if driver!='overlay2' or not root.startswith('/') or root.rstrip('/')!=root or root_stat.get('symlink') or not root_stat.get('readable'):raise Unverified('unsupported/unreadable classic storage root')
 if any(any(s in str(cell).lower() for s in ['containerd','snapshotter']) for row in info.get('DriverStatus',[]) for cell in row):raise Unverified('containerd image store unsupported')
 covering=[m for m in mounts if root==m['path'] or root.startswith(m['path'].rstrip('/')+'/')]
 if not covering:raise Unverified('storage backing domain missing')
 backing=max(covering,key=lambda m:len(m['path']))
 if backing['type'] not in ['ext4','xfs'] or backing['device']!=root_stat['device']:raise Unverified('unsupported/mismatched backing filesystem')
 for m in mounts:
  if m['path'].startswith(root+'/') and not (m['type']=='overlay' and m['path'] in owned_merged):raise Unverified('unaccounted separate Docker storage mount')
 return {'driver':'overlay2','root':root,'device':backing['device'],'filesystem':backing['type'],'completeDomains':[backing['device']]}

def kernel_caps(info,image,token,limits):
 h=info['HostConfig'];c=info['Config']
 if info['Image']!=image or c.get('Labels',{}).get('openclaw.phase1.token')!=token:raise Unverified('owned resource identity mismatch')
 if h.get('NanoCpus')!=limits['nanoCpus'] or h.get('Memory')!=limits['memory'] or h.get('MemorySwap')!=limits['memory'] or h.get('PidsLimit')!=limits['pids']:raise Unverified('actual acquisition CPU/RAM/PID differs before start')
 if h.get('Privileged') or h.get('CapAdd') or h.get('Devices') or h.get('CapDrop')!=['ALL']:raise Unverified('acquisition security mismatch')
 if not any(v in ['no-new-privileges','no-new-privileges:true'] for v in h.get('SecurityOpt',[])):raise Unverified('no-new-privileges missing')
 return True

class OwnedResource:
 """ID/name+owner are admitted before START. Cancellation never targets unknown resources."""
 def __init__(self,docker,resource_id,image,token,limits):
  self.docker=docker;self.id=resource_id;self.image=image;self.token=token;self.limits=limits;self.started=False;self.terminal=False;self.absent=False
 def inspect(self):return self.docker('inspect',self.id)
 def identity(self,info):
  if info['Id']!=self.id or info['Image']!=self.image or info['Config'].get('Labels',{}).get('openclaw.phase1.token')!=self.token:raise Unverified('refuse unrelated resource')
 def start(self):
  info=self.inspect();self.identity(info);kernel_caps(info,self.image,self.token,self.limits)
  if info['State']['Running']:raise Unverified('expected stopped resource')
  self.docker('start',self.id);self.started=True
 def cancel_and_remove(self):
  info=self.inspect();self.identity(info)
  if info['State']['Running']:self.docker('kill',self.id)
  if info['State'].get('Status')!='created':self.docker('wait',self.id)
  info=self.inspect();self.identity(info)
  if info['State']['Running']:raise Unverified('termination unverified')
  self.terminal=True;self.docker('remove',self.id)
  if self.docker('exists',self.id):raise Unverified('absence unverified')
  self.absent=True

def supervise(resource,sample,finished,clock=time.monotonic,sleep=time.sleep,timeout=1200,interval=.25):
 """Every active-loop sample covers storage AND context, not just free space.
 sample must raise on unsupported/partial reads, stale observation or any threshold.
 This does NOT create a hard disk quota or establish an overshoot bound by itself.
 """
 end=clock()+timeout
 try:
  sample();resource.start()
  while True:
   sample()
   if clock()>=end:raise Unverified('owned writer deadline')
   if finished():break
   sleep(interval)
  sample();info=resource.inspect();resource.identity(info)
  if info['State']['Running']:raise Unverified('finished reply without terminal state')
  if info['State'].get('ExitCode')!=0:raise Unverified('owned writer nonzero')
  resource.cancel_and_remove()
  return {'terminal':True,'absent':True}
 except BaseException as error:
  try:resource.cancel_and_remove()
  except BaseException as cleanup:raise Unverified('TERMINATION_OR_ABSENCE_UNVERIFIED') from cleanup
  raise error

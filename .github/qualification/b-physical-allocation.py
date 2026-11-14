"""Actual syscall-backed adapter; NO built-in supported kernel profile.
Reviewed profile file+SHA compiled into PROFILE_* by final integration only.
Unknown kernel/THP/security profile refuses. No runtime owner booleans.
"""
import ctypes,hashlib,json,os,platform,stat,errno,importlib.util
from pathlib import Path
API_VERSION=1
PROFILE_PATH=str(Path(__file__).with_name('vendor_profile.py'))
PROFILE_SHA256='bb095b140fabbdd4c751e6a0a22b2ae82c64f758af0b9c280e32ef93af62cdac'
R=1024**3
CAP=3*R
RECEIPT_LIMIT=16384
class Gate(ValueError):pass
def require(x,s):
 if not x:raise Gate(s)
def small(path,limit=1024**2):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  chunks=[];left=limit+1
  while left:
   chunk=os.read(fd,min(left,65536))
   if not chunk:break
   chunks.append(chunk);left-=len(chunk)
  data=b''.join(chunks);require(len(data)<=limit,'bounded evidence file');return data
 finally:os.close(fd)
def mount_rows():
 result=[]
 for line in small('/proc/self/mountinfo',2*1024**2).decode().splitlines():
  a,b=line.split(' - ');x=a.split();y=b.split();result.append({'id':x[0],'device':x[2],'path':x[4],'options':set(x[5].split(',')),'fs':y[0],'super':set(y[2].split(','))})
 return result
def covering(path,mounts):
 path=str(Path(path));c=[m for m in mounts if path==m['path'] or path.startswith(m['path'].rstrip('/')+'/')];require(c,'mount coverage');return max(c,key=lambda m:len(m['path']))
def statfs_type(path):
 # Linux statfs native structure is larger than this buffer; f_type first long.
 b=ctypes.create_string_buffer(512);libc=ctypes.CDLL(None,use_errno=True);require(libc.statfs(os.fsencode(path),ctypes.byref(b))==0,'statfs failed');return ctypes.c_long.from_buffer(b).value

def load_profile():
 require(PROFILE_PATH and PROFILE_SHA256,'reviewed vendor profile missing')
 raw=small(PROFILE_PATH);require(hashlib.sha256(raw).hexdigest()==PROFILE_SHA256,'profile pin')
 spec=importlib.util.spec_from_file_location('pinned_vendor_profile',PROFILE_PATH);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 return {'select':module.select,'profile':module.PROFILE}

def no_default_acl(path):
 try:os.getxattr(path,'system.posix_acl_default',follow_symlinks=False)
 except OSError as error:
  require(error.errno==errno.ENODATA,'default ACL observation failed')
 else:raise Gate('default ACL inheritance unsupported')

def observe(context,profile):
 mounts=mount_rows();tmp=covering(context['checkout'],mounts);require(tmp['fs']=='tmpfs' and tmp['path']=='/tmp','checkout tmpfs mount')
 magic=statfs_type('/tmp');require(magic==0x01021994,'statfs tmpfs magic')
 require(os.stat(context['checkout']).st_dev==os.stat('/tmp').st_dev,'checkout device')
 require(not any(m['path'].startswith(context['checkout']+'/') for m in mounts),'nested checkout mount')
 v=os.statvfs('/tmp');page=os.sysconf('SC_PAGE_SIZE')
 signature=small('/proc/version_signature').decode().strip();thp=small('/sys/kernel/mm/transparent_hugepage/shmem_enabled').decode().strip()
 per_size=[]
 with os.scandir('/sys/kernel/mm/transparent_hugepage') as entries:
  for entry in entries:
   if entry.name.startswith('hugepages-'):
    candidate=Path(entry.path)/'shmem_enabled'
    if os.path.lexists(candidate):per_size.append(str(candidate))
 for parent in ['/tmp',context['checkout'],str(Path(context['checkout'])/'node_modules'),str(Path(context['checkout'])/'ui/node_modules')]:no_default_acl(parent)
 observation={'uname_release':platform.release(),'version_signature':signature,'architecture':platform.machine(),'page_size':page,'mount_fs':tmp['fs'],'mount_magic':magic,'fragment_size':v.f_frsize,'block_size':v.f_bsize,'blocks':v.f_blocks,'files':v.f_files,'available_blocks':v.f_bavail,'free_blocks':v.f_bfree,'super_options':','.join(sorted(tmp['super'])),'shmem_enabled':thp,'per_size_shmem_controls':per_size,'active_lsms':small('/sys/kernel/security/lsm').decode().strip(),'default_acl_xattr':None}
 try:selected=profile['select'](observation)
 except (KeyError,ValueError) as error:raise Gate('unsupported reviewed runtime profile: '+str(error)) from error
 fields=dict(line.split(':',1) for line in small('/proc/self/status').decode().splitlines() if ':' in line)
 require(int(fields['CapEff'].strip(),16)==0 and fields['NoNewPrivs'].strip()=='1','container isolation flags')
 permitted={os.getpid(),os.getppid(),1}
 for p in Path('/proc').iterdir():
  if p.name.isdigit() and int(p.name) not in permitted:
   try:cmd=(p/'comm').read_text().strip()
   except FileNotFoundError:continue
   raise Gate('unexpected process outside synchronous parent phase '+cmd)
 for root in context['donors'].values():
  require(str(Path(root).resolve())==root,'donor alias');m=covering(root,mounts)
  require('ro' in m['options'] or 'ro' in m['super'],'donor writable mount')
  require(not any(n['path'].startswith(root+'/') and not ('ro' in n['options'] or 'ro' in n['super']) for n in mounts),'donor writable override')
 return {'mountId':tmp['id'],'device':tmp['device'],'page':page,'total':v.f_blocks*v.f_frsize,'signature':signature,'thp':thp,'selected':selected,'observations':observation}

class Session:
 def __init__(self,context):
  self.context=context;self.profile=load_profile();self.observation=observe(context,self.profile);self.page=self.observation['page'];self.index=0;self.failed=False;self.finished=False;self.rows=None;self.ledger=[]
  raw=small(context['capacityReceipt']);require(hashlib.sha256(raw).hexdigest()==context['capacityReceiptSha256'],'capacity receipt digest');receipt=json.loads(raw)
  require(receipt['schema']==1 and receipt['status']=='ADMITTED','capacity schema/status')
  for a,b in [('source','source'),('sourceTree','tree'),('workflow','workflow'),('imageId','imageId'),('manifestSha256','manifestSha256')]:require(receipt[a]==context[b],'capacity identity '+a)
  require(receipt['generatedReserveBytes']==R and receipt['capacityBytes']==self.observation['total'],'capacity constants')
  require(context['imageId'].startswith('sha256:') and len(context['imageId'])==71,'approved image format')
  self.receipt='/tmp/b-physical-receipt';require(not os.path.lexists(self.receipt),'stale physical receipt')
 def geometry(self):
  v=os.statvfs('/tmp');require(v.f_blocks*v.f_frsize==self.observation['total'] and v.f_frsize==self.page,'geometry drift');return v.f_bavail*v.f_frsize,v.f_favail
 def bind_manifest(self,roots,rows):
  require(roots==self.context['donors'],'donor namespace mismatch');self.rows=rows
 def authorize_native_or_script(self,key,digest,mode):
  require(self.rows is not None and key in self.rows,'unknown executable request');r=self.rows[key];require(r['kind']=='file' and r['sha256']==digest and r['mode']==mode,'executable request drift')
  label,rel=key.split('/',1);p=Path(self.context['donors'][label])/rel;require(p.resolve()==p,'executable external alias');s=p.lstat();require(stat.S_ISREG(s.st_mode),'executable type')
  # Approval derives from exact already-approved immutable image, not new per-file approval.
 def charge(self,kind,size):
  require(type(size) is int and size>=0,'operation size')
  if kind=='write':return 0 if size==0 else self.page*((size+self.page-2)//self.page+1)
  if kind=='symlink':require(size+1<=self.page,'long symlink unsupported');return self.page
  require(kind in ['mkdir','create','chmod','rename','unlink-link'],'unknown operation');return 0
 def preflight(self,rows,plan):
  require(rows is self.rows,'manifest unbound');
  for alias in plan.get('aliases',[]):no_default_acl(str(Path(alias['path']).parent))
  self.ledger=plan['operations'];require(len(self.ledger)<=2000000,'ledger bound')
  total=sum(self.charge(k,n) for k,n in self.ledger)
  # Worst bounded failure + success receipts budgeted simultaneously; one actually emitted.
  self.receiptCharge=2*self.charge('write',RECEIPT_LIMIT);self.receiptInodes=2
  inode=sum(k in ['mkdir','create','symlink'] for k,n in self.ledger)+self.receiptInodes
  available,free=self.geometry();require(available>=R+total+self.receiptCharge,'whole peak reserve');require(free>=inode,'whole inode peak');self.remaining=total;self.inodes=inode;self.admitted=True
 def before(self,kind,size):
  require(getattr(self,'admitted',False) and not self.failed and not self.finished,'inactive session');require(self.index<len(self.ledger) and self.ledger[self.index]==[kind,size],'unplanned operation')
  u=self.charge(kind,size);a,i=self.geometry();require(a>=R+self.remaining+self.receiptCharge and i>=self.inodes,'per-operation whole remaining gate');self.index+=1;return(a,u,kind,size,i)
 def after(self,ticket):
  a,u,kind,size,priorInodes=ticket;b,i=self.geometry();require(priorInodes-i<=(1 if kind in ['mkdir','create','symlink'] else 0),'unexpected inode charge');require(a-b<=u,'actual charge exceeds reviewed U');require(b>=R+self.receiptCharge,'reserve after operation');self.remaining-=u
  if kind in ['mkdir','create','symlink']:self.inodes-=1
 def emit(self,status,error=''):
  data=json.dumps({'schema':1,'status':status,'source':self.context['source'],'tree':self.context['tree'],'workflow':self.context['workflow'],'imageId':self.context['imageId'],'operationsCompleted':self.index,'error':str(error)[:512]},sort_keys=True).encode();require(len(data)<=RECEIPT_LIMIT,'receipt bound')
  a,i=self.geometry();u=self.charge('write',len(data));require(a>=R+u and i>=1,'receipt reserve')
  primary=None
  try:
   fd=os.open(self.receipt,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   try:require(os.write(fd,data)==len(data),'short receipt write')
   finally:os.close(fd)
  except BaseException as error:primary=error
  try:
   b,postInodes=self.geometry();require(a-b<=u and b>=R and i-postInodes<=1,'receipt accounting')
  except BaseException as account:
   if primary is None:raise
   if hasattr(primary,'add_note'):primary.add_note('receipt after-account: '+str(account)[:256])
  if primary is not None:raise primary
 def failure(self,primary):
  if self.failed:return
  self.failed=True;self.emit('FAILED',primary)
 def finish(self,result):
  require(self.index==len(self.ledger) and not self.failed,'incomplete ledger');self.emit('COPIED_PENDING_PRODUCT_QUALIFICATION');self.finished=True

def open_contract(context):return Session(context)

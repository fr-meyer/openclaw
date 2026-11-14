"""Actual syscall-backed adapter; NO built-in supported kernel profile.
Reviewed profile file+SHA compiled into PROFILE_* by final integration only.
Unknown kernel/THP/security profile refuses. No runtime owner booleans.
"""
import ctypes,hashlib,json,os,platform,stat,errno,importlib.util
from pathlib import Path
API_VERSION=1
PROFILE_PATH=str(Path(__file__).with_name('vendor_profile.py'))
PROFILE_SHA256='cba533fc4ab2047c388483bbbdd0a6224490af254b2601d3b89c794d449e70a6'

# Exact-tag simple_xattr_space = 40 + strlen(full_name) + value_length.
# Four simultaneous generations per protected name deliberately cover two
# serialized target contexts (foreground + final fput) and old/new overlap.
ISPACE_UNIT=1024
IMA_VALUE_MAX=257
EVM_VALUE_MAX=21
INTEGRITY_ISPACE_PEAK=4*((40+12+IMA_VALUE_MAX)+(40+12+EVM_VALUE_MAX))
INTEGRITY_UNITS=(INTEGRITY_ISPACE_PEAK+ISPACE_UNIT-1)//ISPACE_UNIT
TMP_OBJECT_LIMIT=400000
INTEGRITY_MODEL='ima-evm-lifetime-ispace-v1'
def integrity_objects(root='/tmp'):
 require(root=='/tmp','fixed integrity namespace')
 count=0;device=os.lstat(root).st_dev
 def check(path):
  nonlocal count
  before=os.lstat(path);require(before.st_dev==device,'integrity nested filesystem')
  require(stat.S_ISREG(before.st_mode) or stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode),'integrity object type')
  names=os.listxattr(path,follow_symlinks=False);require(len(names)==len(set(names)) and set(names)<={'security.ima','security.evm'},'integrity unexpected xattr/ACL')
  for name in names:
   value=os.getxattr(path,name,follow_symlinks=False);require(len(value)<=(IMA_VALUE_MAX if name=='security.ima' else EVM_VALUE_MAX),'integrity existing value bound');require(bool(value) and (value[0] in (1,4) if name=='security.ima' else value[0]==2 and len(value)==21),'integrity imported signature/type unsupported')
  after=os.lstat(path);require((before.st_dev,before.st_ino,before.st_mode,before.st_size,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_mode,after.st_size,after.st_ctime_ns),'integrity enumeration drift')
  count+=1;require(count<=TMP_OBJECT_LIMIT,'integrity object count bound')
 check(root)
 for parent,dirs,files in os.walk(root,followlinks=False,onerror=lambda error:(_ for _ in ()).throw(error)):
  for name in dirs+files:check(os.path.join(parent,name))
 return count

def entry_ispace_objects():
 v=os.statvfs('/tmp');require(0<v.f_files and 0<=v.f_ffree<=v.f_files and v.f_favail==v.f_ffree,'entry inode occupancy geometry');return v.f_files-v.f_ffree

def integrity_bank(existing,fresh,receipts=2):
 require(all(type(n) is int and 0<=n<=2000000 for n in (existing,fresh,receipts)),'integrity count type/bound')
 return INTEGRITY_UNITS*(existing+fresh+receipts)

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

def active_lsms(signature,context):
 import runpy
 trusted=runpy.run_path('/tmp/b-host-runtime/b-host-lsm.py',run_name='trusted_lsm_consumer')
 return trusted['consume'](context,signature)

def _observe(context,profile):
 mounts=mount_rows();tmp=covering(context['checkout'],mounts);require(tmp['fs']=='tmpfs' and tmp['path']=='/tmp','checkout tmpfs mount')
 magic=statfs_type('/tmp');require(magic==0x01021994,'statfs tmpfs magic')
 require(os.stat(context['checkout']).st_dev==os.stat('/tmp').st_dev,'checkout device')
 require(not any(m['path'].startswith('/tmp/') for m in mounts),'nested checkout mount')
 v=os.statvfs('/tmp');page=os.sysconf('SC_PAGE_SIZE')
 signature=small('/proc/version_signature').decode().strip();thp=small('/sys/kernel/mm/transparent_hugepage/shmem_enabled').decode().strip()
 per_size=[]
 with os.scandir('/sys/kernel/mm/transparent_hugepage') as entries:
  for entry in entries:
   if entry.name.startswith('hugepages-'):
    candidate=Path(entry.path)/'shmem_enabled'
    if os.path.lexists(candidate):per_size.append(str(candidate))
 for parent in ['/tmp',context['checkout'],str(Path(context['checkout'])/'node_modules'),str(Path(context['checkout'])/'ui/node_modules')]:no_default_acl(parent)
 observation={'uname_release':platform.release(),'version_signature':signature,'architecture':platform.machine(),'page_size':page,'mount_fs':tmp['fs'],'mount_magic':magic,'fragment_size':v.f_frsize,'block_size':v.f_bsize,'blocks':v.f_blocks,'files':v.f_files,'available_blocks':v.f_bavail,'free_blocks':v.f_bfree,'super_options':','.join(sorted(tmp['super'])),'shmem_enabled':thp,'per_size_shmem_controls':per_size,'active_lsms':active_lsms(signature,context),'default_acl_xattr':None}
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


def observe(context,profile):
 try:
  result=_observe(context,profile)
 except (OSError,ValueError) as error:
  print(json.dumps({'physicalObservation':'REFUSED','reason':str(error)[:256]},sort_keys=True),flush=True)
  raise
 print(json.dumps({'physicalObservation':'OBSERVED_NOT_COPY_ADMISSION','observations':result['observations']},sort_keys=True),flush=True)
 return result

class Session:
 def __init__(self,context):
  self.context=context;self.profile=load_profile();self.observation=observe(context,self.profile);self.page=self.observation['page'];self.index=0;self.failed=False;self.finished=False;self.rows=None;self.ledger=[];self.integrityEnabled=self.observation['selected'].get('integrity_accounting')==INTEGRITY_MODEL
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
  model=self.observation['selected'].get('integrity_accounting');require(model in (None,INTEGRITY_MODEL),'unknown integrity accounting model')
  fresh=sum(k in ['mkdir','create','symlink'] for k,n in self.ledger)
  self.integrityExisting=max(integrity_objects(),entry_ispace_objects()) if model else 0
  self.integrityBank=integrity_bank(self.integrityExisting,fresh) if model else 0
  inode=sum(k in ['mkdir','create','symlink'] for k,n in self.ledger)+self.receiptInodes
  available,free=self.geometry();require(available>=R+total+self.receiptCharge,'whole peak reserve');require(free>=inode+2*self.integrityBank,'whole inode/xattr lifetime peak');self.remaining=total;self.inodes=inode;self.admitted=True;self.phase='COPIER_ADMITTED_EXISTING_OCCUPANCY_AND_PENDING_RELEASE_BANKED'
 def before(self,kind,size):
  require(getattr(self,'admitted',False) and not self.failed and not self.finished,'inactive session');require(self.index<len(self.ledger) and self.ledger[self.index]==[kind,size],'unplanned operation')
  u=self.charge(kind,size);a,i=self.geometry();require(a>=R+self.remaining+self.receiptCharge and i>=self.inodes+self.integrityBank,'per-operation whole remaining gate');self.index+=1;return(a,u,kind,size,i)
 def after(self,ticket):
  a,u,kind,size,priorInodes=ticket;b,i=self.geometry();require(priorInodes-i<=(1 if kind in ['mkdir','create','symlink'] else 0)+self.integrityBank,'unexpected inode charge');require(a-b<=u,'actual charge exceeds reviewed U');require(b>=R+self.receiptCharge,'reserve after operation');require(i>=self.inodes-(1 if kind in ['mkdir','create','symlink'] else 0)+self.integrityBank,'inode/xattr reserve after operation');self.remaining-=u
  if kind in ['mkdir','create','symlink']:self.inodes-=1
 def emit(self,status,error=''):
  data=json.dumps({'schema':1,'status':status,'source':self.context['source'],'tree':self.context['tree'],'workflow':self.context['workflow'],'imageId':self.context['imageId'],'operationsCompleted':self.index,'error':str(error)[:512]},sort_keys=True).encode();require(len(data)<=RECEIPT_LIMIT,'receipt bound')
  a,i=self.geometry();u=self.charge('write',len(data));bank=getattr(self,'integrityBank',0);receiptBank=max(bank,INTEGRITY_UNITS if self.integrityEnabled else 0);require(a>=R+u and i>=1+receiptBank,'receipt reserve')
  primary=None
  try:
   fd=os.open(self.receipt,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   try:require(os.write(fd,data)==len(data),'short receipt write')
   finally:os.close(fd)
  except BaseException as error:primary=error
  try:
   b,postInodes=self.geometry();require(a-b<=u and b>=R and i-postInodes<=1+receiptBank and postInodes>=bank,'receipt accounting')
  except BaseException as account:
   if primary is None:raise
   if hasattr(primary,'add_note'):primary.add_note('receipt after-account: '+str(account)[:256])
  if primary is not None:raise primary
 def failure(self,primary):
  if self.failed:return
  self.failed=True;self.phase='COPIER_FAILURE_CLOSE_RECEIPT';self.emit('FAILED',primary)
 def finish(self,result):
  require(self.index==len(self.ledger) and not self.failed,'incomplete ledger');self.phase='COPIER_FINAL_CLOSE_RECEIPT';self.emit('COPIED_PENDING_PRODUCT_QUALIFICATION');self.finished=True;self.phase='HANDOFF_PRODUCTS_NO_PEAK_GUARANTEE';print(json.dumps({'physicalPhase':self.phase,'integrityLifetimeBankUnits':self.integrityBank,'pendingPriorReleaseEffectsBankedNotClaimedDrained':True,'actualProductQualification':False},sort_keys=True),flush=True)

def open_contract(context):return Session(context)

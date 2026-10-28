"""Native read-only bootstrap primitives. Default Mac import/CLI is inert."""
import datetime as dt
import os,platform,stat,sys,time,signal
from contextlib import contextmanager
from pathlib import Path
from guard import Refusal,need,SOURCE

ENTRY=SOURCE+'/bootstrap/guest_boot.py'


class NativeEvidenceIO:
 def __init__(self,entry_path):
  need(sys.platform=='linux' and os.geteuid()==os.getegid()==0 and str(Path(entry_path).resolve())==ENTRY,'boot.native_entry_required')
  self.own=None;self.commands=None;self.program=None;self.claimed=False;self.shutdown_intent=False;self.started=time.monotonic();self.serial_ops=None
 def utc(self):return dt.datetime.now(dt.timezone.utc)
 def monotonic(self):return time.monotonic()
 @contextmanager
 def wrapper_limit(self):
  need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'boot.outer_timer_present')
  previous=signal.getsignal(signal.SIGALRM)
  def expired(_signal,_frame):raise Refusal('boot.wrapper_deadline')
  remaining=self.started+2000-self.monotonic();need(remaining>0,'boot.wrapper_deadline')
  signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,remaining)
  try:yield
  finally:
   signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
 def readlink(self,path):return os.readlink(path)
 def _read(self,path,cap,*,cleanup=False):
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   out=bytearray()
   while len(out)<=cap:
    need(cleanup or time.monotonic()<self.started+2000,'boot.wrapper_deadline')
    raw=os.read(fd,min(65536,cap+1-len(out)))
    if not raw:break
    out.extend(raw)
   need(len(out)<=cap,'boot.read_cap');return bytes(out)
  finally:os.close(fd)
 def read(self,path,cap):return self._read(path,cap)
 def current_boot(self,*,cleanup=False):
  # A single fixed 128-byte identity read remains available for owned cleanup.
  return self._read('/proc/sys/kernel/random/boot_id',128,cleanup=cleanup).decode('ascii').strip()
 def file(self,path,cap):
  p=Path(path);need(str(p.resolve())==path,'boot.file_symlink')
  before=p.lstat();need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=cap,'boot.file_type')
  fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   opened=os.fstat(fd);out=bytearray()
   while len(out)<=cap:
    need(time.monotonic()<self.started+2000,'boot.wrapper_deadline')
    raw=os.read(fd,min(65536,cap+1-len(out)))
    if not raw:break
    out.extend(raw)
   after=os.fstat(fd)
  finally:os.close(fd)
  identity=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  need(identity(before)==identity(opened)==identity(after)==identity(p.lstat()) and len(out)==before.st_size,'boot.file_changed')
  return {'raw':bytes(out),'uid':before.st_uid,'gid':before.st_gid,'mode':stat.S_IMODE(before.st_mode),'regular':True,'canonicalPath':path}
 def check_source_roster(self,expected):
  found=set()
  for parent,dirs,files in os.walk(SOURCE,followlinks=False):
   p=Path(parent);s=p.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and not stat.S_IMODE(s.st_mode)&0o022,'boot.source_parent')
   for name in dirs:need(not(p/name).is_symlink(),'boot.source_directory_link')
   for name in files:
    found.add((p/name).relative_to(SOURCE).as_posix());need(len(found)<=257,'boot.source_roster_cap')
  need(found==set(expected),'boot.source_roster_changed')
 def facts(self):
  mem={}
  for line in self.read('/proc/meminfo',16384).decode().splitlines():
   if ':'in line:
    k,v=line.split(':',1)
    if k in('MemAvailable','SwapTotal'):mem[k]=int(v.strip().split()[0])*1024
  fs=os.statvfs('/')
  return {'platform':sys.platform,'machine':platform.machine(),'euid':os.geteuid(),'egid':os.getegid(),'pid':os.getpid(),
    'kernelVersion':platform.release(),'rootFreeBytes':fs.f_bavail*fs.f_frsize,
    'availableMemoryBytes':mem.get('MemAvailable',0),'swapTotalBytes':mem.get('SwapTotal',-1)}
 def own_guest_checkpoint(self,markers,build,boot):self.own=(dict(markers),dict(build),boot)
 def bind_readonly_commands(self,program):
  need(self.own is not None and self.commands is None,'boot.readonly_binding')
  io=self
  class ReadOnlyCommands(program.native.NativeCommandIO):
   def __init__(self):pass  # Own-guest source/build checks above; no native unit capability.
   def spawn(self,argv):
    allowed=(argv[0]=='/usr/bin/gpgv' and argv[1:4]==('--status-fd=1','--keyring','/opt/ocv/control/apt-data/keyring.gpg') and argv[4:] ==('/opt/ocv/control/apt-data/InRelease',) or
      argv==('/usr/bin/systemctl','poweroff','--no-block'))
    need(allowed,'boot.readonly_command');return super().spawn(argv)
  self.commands=program.native.CommandCapture(ReadOnlyCommands());self.program=program
 def command(self,argv,timeout=5):
  need(self.commands is not None,'boot.readonly_unbound')
  if tuple(argv)!=('/usr/bin/systemctl','poweroff','--no-block'):
   remaining=self.started+2000-self.monotonic();need(remaining>0,'boot.wrapper_deadline');timeout=min(timeout,remaining)
  return self.commands.command(tuple(argv),timeout)
 def claim_boot(self,session):
  need(self.own is not None and not self.claimed,'boot.claim_once')
  base=Path('/run/ocv');base.mkdir(mode=0o700,exist_ok=True)
  s=base.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and not stat.S_IMODE(s.st_mode)&0o077,'boot.claim_parent')
  target=base/(session+'.intent')
  try:fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  except FileExistsError:raise Refusal('boot.claim_exists') from None
  try:os.write(fd,b'ocv-public-synthetic-once\n');os.fsync(fd)
  finally:os.close(fd)
  self.claimed=True
 def compatibility_scratch(self,session):
  need(self.own is not None and self.own[0]['ocv.session']==session,'boot.compatibility_owner')
  base=Path('/run/ocv');base.mkdir(mode=0o700,exist_ok=True)
  s=base.lstat();need(str(base.resolve())==str(base) and stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0 and
   stat.S_IMODE(s.st_mode)==0o700,'boot.compatibility_parent')
  return str(base/(session+'-consumer'))  # Suite itself requires this path absent.
 def mkdir(self,path,mode):Path(path).mkdir(parents=True,mode=mode,exist_ok=False)
 def emit(self,raw):
  from serial_io import NativeSerialOps,emit_once
  need(self.own is not None,'boot.serial_own_guest')
  if self.serial_ops is None:self.serial_ops=NativeSerialOps(self)
  return emit_once(self.serial_ops,raw)
 def poweroff(self):
  need(self.own is not None and not self.shutdown_intent,'boot.no_unowned_or_repeated_shutdown')
  self.shutdown_intent=True
  return self.command(('/usr/bin/systemctl','poweroff','--no-block'),5)

 def write_failure(self,session,raw):
  need(self.own is not None and len(raw)<=8192,'boot.failure_custody')
  import hashlib,json
  directory=Path('/run/ocv')/(session+'-bootstrap-failure');directory.mkdir(parents=True,mode=0o700,exist_ok=False)
  meta={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'truncated':False,'viewBytes':len(raw),'viewSha256':hashlib.sha256(raw).hexdigest()}
  for name,data in (('host-diagnostics.private.bin',raw),('host-diagnostics.private.json',json.dumps(meta,sort_keys=True,separators=(',',':')).encode())):
   fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   try:
    view=memoryview(data)
    while view:
     count=os.write(fd,view);need(count>0,'boot.failure_short_write');view=view[count:]
    os.fsync(fd)
   finally:os.close(fd)
  return str(directory)

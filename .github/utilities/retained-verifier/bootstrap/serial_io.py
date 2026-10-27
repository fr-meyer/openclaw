"""Fixed root-only serial framing. Native backend is never used in local tests."""
import os,stat,time,select
from pathlib import Path
from guard import Refusal,need,sha


def emit_once(ops,raw):
 need(not ops.claimed and type(raw)is bytes and len(raw)<=1048576,'boot.serial_once_or_cap')
 ops.claimed=True;fd=None;phase='identity';written=0
 try:
  identity=ops.identity();need(identity['char']is True and identity['uid']==0 and identity['rdev']==os.makedev(4,64) and
    identity['canonical']is True,'boot.serial_device')
  phase='open';fd=ops.open();need(ops.same(fd,identity),'boot.serial_device_changed')
  deadline=min(ops.now()+45,getattr(ops,'deadline',float('inf')));view=memoryview(raw)
  while view:
   need(ops.now()<deadline,'boot.serial_deadline');phase='write'
   try:count=ops.write(fd,view)
   except BlockingIOError:ops.writable(fd,min(.05,max(0,deadline-ops.now())));continue
   need(type(count)is int and 0<count<=len(view),'boot.serial_short_write')
   written+=count;view=view[count:]
  need(ops.same(fd,identity),'boot.serial_device_changed')
  return {'bytes':written,'sha256':sha(raw),'complete':True}
 except BaseException as error:
  raise Refusal('boot.serial_failed',{'phase':phase,'writtenBytes':written,'inputBytes':len(raw),
    'errno':error.errno if isinstance(error,OSError)else None})from None
 finally:
  if fd is not None:ops.close(fd)


class NativeSerialOps:
 def __init__(self,owner):
  from native_io import NativeEvidenceIO
  need(type(owner)is NativeEvidenceIO and owner.own is not None,'boot.serial_owner')
  self.claimed=False;self.deadline=owner.started+900
 def identity(self):
  p=Path('/dev/ttyS0');s=p.lstat()
  return {'char':stat.S_ISCHR(s.st_mode),'uid':s.st_uid,'rdev':s.st_rdev,'canonical':str(p.resolve())==str(p),
    'identity':(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_rdev)}
 def open(self):return os.open('/dev/ttyS0',os.O_WRONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 def same(self,fd,row):
  s=os.fstat(fd);return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_rdev)==row['identity']
 def now(self):return time.monotonic()
 def write(self,fd,view):return os.write(fd,view)
 def writable(self,fd,seconds):select.select([],[fd],[],seconds)
 def close(self,fd):os.close(fd)

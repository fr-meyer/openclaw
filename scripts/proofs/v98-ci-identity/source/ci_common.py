"""Bounded local metadata and original clocks; no authentication or provider calls."""
import hashlib,json,math,os,signal,stat,time
from pathlib import Path
class Refusal(ValueError):pass
def need(value,code):
 if not value:raise Refusal(code)
def finite(value):return type(value)in(int,float)and math.isfinite(value)
def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def read_json(raw):
 def pairs(items):
  result={}
  for k,v in items:need(k not in result,'DUPLICATE_METADATA_KEY');result[k]=v
  return result
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'NONFINITE_METADATA'))
def pin(path):
 path=Path(path);raw=path.read_bytes();return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def private_read(path,limit=65536):
 path=Path(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode)and s.st_uid==os.getuid()and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=limit,'BOUNDED_OWNED_METADATA');raw=os.read(fd,limit+1);need(len(raw)==s.st_size,'UNCHANGED_METADATA_SIZE');return raw
 finally:os.close(fd)
def directory(path):
 path=Path(path);s=path.lstat();need(stat.S_ISDIR(s.st_mode)and not path.is_symlink()and path.resolve()==path and s.st_uid==os.getuid()and stat.S_IMODE(s.st_mode)==0o700,'OWNED_PRIVATE_DIRECTORY');return path
def exact(item):
 raw=private_read(item['path'],max(1,item['bytes']));need(len(raw)==item['bytes']and hashlib.sha256(raw).hexdigest()==item['sha256'],'EXACT_PUBLIC_RECEIPT');return read_json(raw)
def publish(path,value,check=lambda:None,file_cap=16384,directory_cap=65536):
 # A failed/uncertain publication consumes its prepared path. Never adopt it
 # as a new intent, overwrite it, or replay the associated operation.
 path=Path(path);check();directory(path.parent);raw=encoded(value);need(len(raw)<=file_cap,'PUBLIC_RECEIPT_CAP')
 total=0
 for entry in path.parent.iterdir():
  s=entry.lstat();need(not entry.is_symlink()and s.st_uid==os.getuid()and((stat.S_ISREG(s.st_mode)and stat.S_IMODE(s.st_mode)==0o600)or(stat.S_ISDIR(s.st_mode)and stat.S_IMODE(s.st_mode)==0o700)),'PUBLIC_DIRECTORY_ENTRIES');total+=s.st_size if stat.S_ISREG(s.st_mode)else 0
 need(total+len(raw)*2<=directory_cap,'PUBLIC_DIRECTORY_CAP');prepared=path.with_name('.prepared-'+path.name)
 check();fd=os.open(prepared,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as f:check();f.write(raw);check();f.flush();os.fsync(f.fileno());check()
 os.link(prepared,path,follow_symlinks=False)
 def sync():
  check();fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:os.fsync(fd);check()
  finally:os.close(fd)
 sync();prepared.unlink();sync();check()
 return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
class Deadline:
 def __init__(self,end,wall=time.time,mono=time.monotonic,maximum=20):
  self.wall=wall;self.mono=mono;self.w=wall();self.m=mono();self.last=(self.w,self.m);self.failed=False;need(finite(end)and self.w<end,'ORIGINAL_DEADLINE');self.end=min(end,self.w+maximum);self.mend=self.m+self.end-self.w
 def sample(self):
  w,m=self.wall(),self.mono();good=not self.failed and finite(w)and finite(m)and self.last[0]<=w<self.end and self.last[1]<=m<self.mend and abs(w-self.w-(m-self.m))<=2;self.failed=not good;need(good,'ORIGINAL_CLOCK_OR_CUTOFF');self.last=(w,m);return w,m
 def remaining(self):
  w,m=self.sample();return min(self.end-w,self.mend-m)
class SelfAlarm:
 def __init__(self,clock):self.clock=clock
 def __enter__(self):
  self.old_handler=signal.getsignal(signal.SIGALRM);self.old_remaining,self.interval=signal.getitimer(signal.ITIMER_REAL);self.started=time.monotonic();need(self.interval==0,'NO_INHERITED_PERIODIC_ALARM')
  def cutoff(_s,_f):raise Refusal('OWN_ORIGINAL_AUTH_ALARM')
  remaining=min(self.clock.remaining(),self.old_remaining if self.old_remaining>0 else float('inf'))
  signal.signal(signal.SIGALRM,cutoff)
  try:signal.setitimer(signal.ITIMER_REAL,remaining)
  except BaseException:signal.signal(signal.SIGALRM,self.old_handler);raise
  return self
 def __exit__(self,*exc):
  signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,self.old_handler)
  if self.old_remaining>0:
   remaining=self.old_remaining-(time.monotonic()-self.started);signal.setitimer(signal.ITIMER_REAL,max(.000001,remaining))
  return False

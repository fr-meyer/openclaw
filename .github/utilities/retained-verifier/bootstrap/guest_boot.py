"""Fixed future CI guest entry. Default Mac import/CLI performs no native work."""
import hashlib,importlib.util,json,os,stat,sys
from pathlib import Path
ROOT='/opt/ocv/source'


def _need(ok,code):
 if not ok:raise RuntimeError(code)

def _read(path,cap):
 p=Path(path);_need(str(p.resolve())==path,'boot.initial_path')
 s=p.lstat();_need(stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1 and
  stat.S_IMODE(s.st_mode)==0o444 and 0<=s.st_size<=cap,'boot.initial_file')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  opened=os.fstat(fd);data=bytearray()
  while len(data)<=cap:
   raw=os.read(fd,min(65536,cap+1-len(data)))
   if not raw:break
   data.extend(raw)
  after=os.fstat(fd)
 finally:os.close(fd)
 identity=lambda x:tuple(getattr(x,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
 _need(len(data)==s.st_size and identity(s)==identity(opened)==identity(after)==identity(p.lstat()),'boot.initial_changed')
 return bytes(data)


def _load_checked_bootstrap():
 # Before executing any helper imports, bind source rows to the host-provided
 # kernel identity marker. This marker is not itself cryptographic provenance.
 with open('/proc/cmdline','rb') as stream:cmdline=stream.read(8193)
 _need(len(cmdline)<=8192,'boot.initial_cmdline')
 tokens=[v.split('=',1)[1]for v in cmdline.decode('ascii').split()if v.startswith('ocv.source=')]
 _need(len(tokens)==1 and len(tokens[0])==64,'boot.initial_source_marker')
 raw=_read(ROOT+'/PUBLIC-SOURCE-MANIFEST.json',1048576)
 _need(hashlib.sha256(raw).hexdigest()==tokens[0],'boot.initial_source_pin')
 def pairs(rows):
  out={}
  for k,v in rows:_need(k not in out,'boot.initial_duplicate');out[k]=v
  return out
 doc=json.loads(raw,object_pairs_hook=pairs);_need(set(doc)=={'schema','files'} and doc['schema']=='ocv-public-source-v1','boot.initial_schema')
 rows={r['path']:r for r in doc['files']};_need(len(rows)==len(doc['files']),'boot.initial_duplicate')
 for name in ('guest_boot.py','guard.py','native_io.py','issuer.py','result_frame.py','serial_io.py'):
  rel='bootstrap/'+name;row=rows[rel];source=_read(ROOT+'/'+rel,262144)
  _need(row['mode']==0o444 and len(source)==row['bytes'] and hashlib.sha256(source).hexdigest()==row['sha256'],'boot.initial_code_pin')
 sys.path.insert(0,ROOT+'/bootstrap')
 import guard,native_io,issuer,result_frame
 return guard,native_io,issuer,result_frame


def handle_failure(io,plan,error,guard,issuer,frames,emitter=None):
 from types import SimpleNamespace
 code=error.code if isinstance(error,guard.Refusal)else 'boot.checked_entry_refused'
 if code=='boot.claim_exists':
  sys.stderr.write('OCV_BOOT_REFUSED:boot.claim_exists\n');return  # Never stop a prior same-session owner.
 if io.own is None:
  sys.stderr.write('OCV_BOOT_REFUSED:'+code+'\n');sys.stderr.flush();return
 if plan is None:plan=SimpleNamespace(markers=io.own[0],build=io.own[1])
 if emitter is None or not emitter.used:
  diagnostic=guard.canonical({'phase':'bootstrap','reason':code,'exceptionType':type(error).__name__,
    'facts':error.facts if isinstance(error,guard.Refusal)else {},
    'errno':error.errno if isinstance(error,OSError)else None})
  try:
   directory=io.write_failure(plan.markers['ocv.session'],diagnostic)
   if emitter is None:emitter=frames.Emitter(plan,lambda p,c:io.read(p,c),io.emit,compatibility_raw=getattr(io,'compatibility_raw',None))
   emitter.emit(guard.canonical({'status':'refused','phase':'bootstrap','reason':code,'nativeProof':False}),directory)
  except BaseException:sys.stderr.write('OCV_BOOT_REFUSED:'+code+'\n');sys.stderr.flush()
 if io.commands is None:
  try:io.bind_readonly_commands(issuer.load_program(plan,io))
  except BaseException:sys.stderr.write('OCV_BOOT_SHUTDOWN_UNBOUND\n');sys.stderr.flush();return
 if not io.shutdown_intent:
  try:io.poweroff()
  except BaseException:sys.stderr.write('OCV_BOOT_SHUTDOWN_UNCERTAIN\n');sys.stderr.flush()


def run_owned(io,guard,issuer,frames):
 plan=None;emitter=None
 try:
  plan=guard.verify(io);program=issuer.load_program(plan,io);io.bind_readonly_commands(program)
  prepared=issuer.prepare(plan,io,program)
  prepared=issuer.complete_compatibility(plan,io,prepared,program,ROOT+'/consumer',io.compatibility_scratch(plan.markers['ocv.session']))
  cap=issuer.issue_native(plan,io,prepared);ops=issuer.successor_ops(program,cap)
  manifest,context=issuer.plan_native_job(plan,prepared,program,io.utc())
  port=issuer.port_successor(program,ops,manifest,context,plan,prepared,io)
  directory='/run/ocv/'+plan.markers['ocv.session'];io.mkdir(directory,0o700)
  emitter=frames.Emitter(plan,lambda p,c:io.read(p,c),io.emit,capability=cap,context_raw=guard.canonical(context),
    compatibility_raw=prepared.compatibility.raw,observations=port.bootstrap_custody)
  entry=program.entry.Entry(port,directory+'/custody',directory+'/result',clock=io,
    emit=lambda raw:emitter.emit(raw,directory+'/custody'))
  return entry.run(guard.canonical(context))
 except BaseException as error:
  handle_failure(io,plan,error,guard,issuer,frames,emitter);raise


def main():
 _need(sys.platform=='linux' and os.geteuid()==os.getegid()==0 and len(sys.argv)==1 and
       str(Path(__file__).resolve())==ROOT+'/bootstrap/guest_boot.py','boot.checked_ci_entry_required')
 guard,native_io,issuer,frames=_load_checked_bootstrap();io=native_io.NativeEvidenceIO(__file__)
 with io.wrapper_limit():return run_owned(io,guard,issuer,frames)


if __name__=='__main__':main()

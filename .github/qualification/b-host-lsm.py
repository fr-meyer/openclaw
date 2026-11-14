"""Fixed B-only local helper transport. No caller-selected Docker endpoint or receipt."""
import base64,ctypes,fcntl,hashlib,io,json,os,platform,re,secrets,select,signal,socket,stat,struct,subprocess,sys,tarfile,time
from pathlib import Path,PurePosixPath
S='2c4cec2e47930c7825e8256dc9526bf247fcf6b7';T='8076f530775d9f25d398da31d70f954a011b0a90';BASE='30786562e236aab6a924981c62aa61b920132c76'
LIMIT=4096;FD=9;ENDPOINT='unix:///var/run/docker.sock';DOCKER='/usr/bin/docker';TRUST='/tmp/b-host-runtime';ROOT='/tmp/openclaw-worktree-test'
KEYS={'source','tree','workflow','workflowTree','manifest','image','helper','nonce','boot','kernel','signature','arch','daemon','issued','run'}
ALLOWED={'capability','apparmor','yama','lockdown','landlock'}
def need(ok,msg):
 if not ok:raise ValueError(msg)
def sha(b):return hashlib.sha256(b).hexdigest()
def canonical(a):return json.dumps(a,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
def pairs(items):
 d={}
 for k,v in items:need(k not in d,'duplicate JSON field');d[k]=v
 return d
def decode(data):
 need(0<len(data)<=LIMIT,'receipt size');a=json.loads(data,object_pairs_hook=pairs);need(canonical(a)==data,'noncanonical receipt');return a
def hexid(value,n):return isinstance(value,str) and re.fullmatch('[0-9a-f]{'+str(n)+'}',value) is not None
def small(path,limit=1024):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  b=os.read(fd,limit+1);need(len(b)<=limit,'host/kernel read bound');need(not os.read(fd,1),'partial host read');return b.decode('ascii').strip()
 finally:os.close(fd)
def kernel():
 need(platform.machine()=='x86_64' and ctypes.sizeof(ctypes.c_void_p)==8 and ctypes.sizeof(ctypes.c_long)==8,'unsupported ABI')
 release=platform.release();sig=small('/proc/version_signature')
 need(release=='7.0.0-1017-azure' and re.fullmatch(r'Ubuntu 7[.]0[.]0-1017[.]17(?:~24[.]04[.]1)?-azure 7[.]0(?:[.][0-9]+)?',sig),'unsupported vendor/kernel')
 boot=small('/proc/sys/kernel/random/boot_id');need(re.fullmatch('[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',boot),'boot ID')
 return {'boot':boot,'kernel':release,'signature':sig,'arch':'x86_64'}
def lsm_list(text):
 need(isinstance(text,str) and 0<len(text)<=256 and text==text.strip(),'LSM bound/whitespace')
 names=text.split(',');need(len(names)==len(set(names)) and all(x in ALLOWED for x in names) and 'capability' in names,'LSM unknown/duplicate/missing capability')
 return names
def context(e):
 need(type(e)==dict and set(e)==KEYS,'context fields')
 need(e['source']==S and e['tree']==T and hexid(e['workflow'],40) and e['workflow']!=S and hexid(e['workflowTree'],40),'source/workflow identity')
 need(all(hexid(e[k],64) for k in ['manifest','helper','nonce']),'context pin/nonce')
 need(re.fullmatch('sha256:[0-9a-f]{64}',e['image']) and re.fullmatch('[0-9A-Za-z:_-]{1,128}',e['daemon']),'image/daemon identity')
 need(type(e['issued'])==int and 0<=time.monotonic_ns()-e['issued']<=300*10**9,'receipt stale/future')
 need(re.fullmatch('[1-9][0-9]{0,18}',e['run']),'provider run')
 need(e['arch']=='x86_64' and e['kernel']=='7.0.0-1017-azure','context ABI/kernel')
 return e
def receipt(a,expected=None):
 need(type(a)==dict and set(a)=={'version','context','cid','lsms'},'receipt fields');need(type(a['version'])==int and a['version']==1,'receipt version');context(a['context']);need(hexid(a['cid'],64),'full container ID');need(type(a['lsms'])==list and 0<len(a['lsms'])<=5 and all(type(x)==str for x in a['lsms']),'LSM receipt type');lsm_list(','.join(a['lsms']))
 if expected is not None:need(a['context']==expected,'receipt independently expected context mismatch')
 return a
def exact(fd,n,timeout=10):
 out=bytearray();end=time.monotonic()+timeout
 while len(out)<n:
  wait=end-time.monotonic();need(wait>0 and select.select([fd],[],[],wait)[0],'frame timeout')
  b=os.read(fd,n-len(out));need(bool(b),'truncated frame');out.extend(b)
 return bytes(out)
def frame(data):need(0<len(data)<=LIMIT,'frame bound');return struct.pack('!I',len(data))+data
def read_frame(fd,expected):
 length=struct.unpack('!I',exact(fd,4))[0];need(0<length<=LIMIT,'frame length');data=exact(fd,length);receipt(decode(data),expected);return data

def fresh_pipe(data,target=FD):
 need(0<len(data)<=LIMIT,'pipe bound');r,w=os.pipe2(os.O_CLOEXEC)
 try:
  need(fcntl.fcntl(w,fcntl.F_GETPIPE_SZ)>=len(data),'pipe capacity')
  need(os.write(w,data)==len(data),'partial pipe write')
 finally:os.close(w)
 try:
  if r!=target:os.dup2(r,target,inheritable=False)
  else:os.set_inheritable(target,False)
 finally:
  if r!=target:os.close(r)
 return target

def read_pipe(fd=FD,timeout=3):
 try:
  need(stat.S_ISFIFO(os.fstat(fd).st_mode) and re.fullmatch(r'pipe:\[[0-9]+\]',os.readlink('/proc/self/fd/'+str(fd))),'receipt FD not anonymous FIFO');need(fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY,'receipt FD not readonly')
  try:os.lseek(fd,0,os.SEEK_CUR)
  except OSError as e:need(e.errno==29,'receipt FD seek error')
  else:raise ValueError('seekable receipt FD')
  data=bytearray();end=time.monotonic()+timeout
  while True:
   wait=end-time.monotonic();need(wait>0 and select.select([fd],[],[],wait)[0],'receipt writer/EOF timeout')
   b=os.read(fd,LIMIT+1-len(data));need(len(data)+len(b)<=LIMIT,'pipe oversized')
   if not b:break
   data.extend(b)
  return receipt(decode(bytes(data)))
 finally:os.close(fd)

def consume(ctx,signature):
 a=read_pipe();need(socket.gethostname()==a['cid'][:12],'collector actual CID/hostname');e=a['context'];live=kernel();need(all(e[k]==live[k] for k in live),'host/container boot/kernel/ABI mismatch');need(signature==live['signature'],'allocator signature mismatch')
 for key,field in [('source','source'),('tree','tree'),('workflow','workflow'),('manifestSha256','manifest'),('imageId','image')]:need(ctx[key]==e[field],'collector context mismatch '+key)
 need(sha(Path(TRUST+'/openclaw-worktree-test-isolated').read_bytes())==e['helper'],'collector helper pin')
 print(json.dumps({'hostLsm':'OBSERVED_CONTEXT_BOUND','workflow':e['workflow'],'workflowTree':e['workflowTree'],'cid':a['cid'],'lsms':a['lsms']},sort_keys=True),flush=True)
 return ','.join(a['lsms'])

def safe_extract(stream,root,max_bytes=1024**3,max_entries=100000):
 root=Path(root);need(root.is_absolute() and not root.is_symlink(),'extract root');root.mkdir(parents=True,exist_ok=True);seen=set();total=0
 with tarfile.open(fileobj=stream,mode='r|') as tf:
  for member in tf:
   name=member.name
   if name.startswith('./'):name=name[2:]
   if name in ('','.'):
    need(member.isdir(),'archive root type');continue
   parts=PurePosixPath(name).parts;need(not name.startswith('/') and all(p not in ('..','.') for p in parts) and len(name)<=2048,'archive path')
   need(name not in seen and len(seen)<max_entries,'archive duplicate/count');seen.add(name);dest=root.joinpath(*parts)
   for parent in [root,*list(dest.parents)[:-1]]:
    if parent==root or root in parent.parents:need(not parent.is_symlink(),'archive symlink ancestor')
   need(not dest.exists() and not dest.is_symlink(),'archive overwrite')
   need(member.size>=0 and not member.pax_headers,'archive metadata')
   total+=member.size;need(total<=max_bytes,'archive byte bound');dest.parent.mkdir(parents=True,exist_ok=True)
   if member.isdir():dest.mkdir(exist_ok=True);os.chmod(dest,0o755)
   elif member.isfile():
    fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o755 if member.mode&0o111 else 0o644)
    try:
     src=tf.extractfile(member);left=member.size
     while left:
      data=src.read(min(65536,left));need(data and len(data)<=left,'archive truncated file');need(os.write(fd,data)==len(data),'archive short write');left-=len(data)
    finally:os.close(fd)
   elif member.issym():
    link=member.linkname;need(link and not link.startswith('/'),'archive absolute link');target=os.path.normpath(str(dest.parent/link));need(os.path.commonpath([str(root),target])==str(root),'archive escaping link');os.symlink(link,dest)
   else:raise ValueError('archive hardlink/special type')
  buffered=getattr(tf.fileobj,'buf',b'')
 need(not buffered.strip(bytes([0])),'archive buffered trailing data')
 padding=0
 while True:
  tail=stream.read(1024)
  if not tail:break
  padding+=len(tail);need(padding<=10240 and not tail.strip(bytes([0])),'archive trailing data/padding')
 return len(seen),total

# Docker host implementation follows. All Docker calls use one pinned local socket,
# an empty private CLI config and an explicit minimal environment.
def docker_environment(environ):
 need(not any(k.startswith(('DOCKER_','OPENCLAW_B_LSM_')) for k in environ),'caller Docker/receipt environment')
 return {'PATH':'/usr/bin:/bin','HOME':'/nonexistent','DOCKER_CONFIG':'/nonexistent','DOCKER_HOST':ENDPOINT,'DOCKER_API_VERSION':'1.48','GH_NO_UPDATE_NOTIFIER':'1'}
def command(args,env,timeout=30):
 p=subprocess.run([DOCKER,'--host',ENDPOINT,'--config','/nonexistent',*args],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=True)
 need(len(p.stdout)<=1024*1024,'Docker output bound');return p.stdout

def daemon(data):
 need(data['ServerVersion']=='28.0.4' and data['OSType']=='linux' and data['Architecture']=='x86_64' and data['KernelVersion']=='7.0.0-1017-azure','daemon version/kernel')
 need([x for x in data['SecurityOptions'] if x.startswith('name=seccomp,')]==['name=seccomp,profile=builtin'],'daemon default seccomp')
 need(not any(x in data['SecurityOptions'] for x in ['name=rootless','name=userns']),'daemon namespace')
 need(type(data['ID'])==str and re.fullmatch('[0-9A-Za-z:_-]{1,128}',data['ID']),'daemon ID');return data['ID']

def inspect_object(a,cid,image,nonce,argv,envlist):
 need(type(a)==list and len(a)==1,'inspect response');a=a[0];h=a['HostConfig'];c=a['Config']
 need(a['Id']==cid and a['Image']==image and c['Image']==image and c['Entrypoint']==['/usr/bin/python3'] and c['Cmd']==['-I','-B',*argv] and c['Hostname']==cid[:12],'container image/bootstrap')
 need(c['Env']==envlist and c['Labels'].get('openclaw.b.host-lsm')==nonce,'container env/ownership')
 need(h['NetworkMode']=='none' and h['ReadonlyRootfs'] is True and h['Privileged'] is False and h['PidMode']=='' and h['IpcMode']=='private' and h['UsernsMode']=='' and h['CapDrop']==['ALL'] and not h.get('CapAdd') and h['PidsLimit']==512,'container isolation')
 need(not h.get('Binds') and not h.get('Mounts') and (a.get('Mounts')==[] or len(a.get('Mounts',[]))==1 and a['Mounts'][0].get('Type')=='tmpfs' and a['Mounts'][0].get('Destination')=='/tmp' and not a['Mounts'][0].get('Source')),'container host binds/mounts')
 need(h['Tmpfs']=={'/tmp':'rw,nosuid,nodev,exec,size=3g'} and h['SecurityOpt']==['no-new-privileges'],'container tmpfs/default seccomp')
 need(not a['State']['Running'],'container already running')

def git(root,*args):
 p=subprocess.run(['/usr/bin/git','-C',str(root),*args],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20,env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null'});need(len(p.stdout)<=2*1024*1024,'Git read bound');return p.stdout

def host_context(root,w,run,image,manifest):
 need(hexid(w,40) and re.fullmatch('[1-9][0-9]{0,18}',run),'provider identity arguments');need(re.fullmatch('sha256:[0-9a-f]{64}',image) and hexid(manifest,64),'B command pins')
 root=Path(root);need(root.is_absolute() and root.resolve()==root and root.name=='candidate','fixed candidate root');workflow=root.parent/'workflow'
 need(git(root,'rev-parse','HEAD').decode().strip()==S and git(root,'rev-parse','HEAD^{tree}').decode().strip()==T,'source checkout identity')
 need(git(workflow,'rev-parse','HEAD').decode().strip()==w,'provider workflow head')
 raw=git(workflow,'cat-file','commit',w);need(hashlib.sha1(b'commit '+str(len(raw)).encode()+bytes([0])+raw).hexdigest()==w,'raw workflow hash')
 headers=raw.split(bytes([10,10]),1)[0].splitlines();trees=[x[5:].decode() for x in headers if x.startswith(b'tree ')];parents=[x[7:].decode() for x in headers if x.startswith(b'parent ')];need(len(trees)==1 and hexid(trees[0],40) and parents==[S],'workflow tree/sole parent')
 for path in git(workflow,'diff-tree','--no-commit-id','--name-only','-r',w).decode().splitlines():need(path.startswith('.github/qualification/') or path=='.github/workflows/unified-b-outbox-source307-qualification.yml','workflow changes source')
 support=root/'.github/qualification';need(Path(__file__).resolve()==support/'b-host-lsm.py','fixed host module path')
 files={}
 for name in ['b-host-lsm.py','b-physical-allocation.py','vendor_profile.py','b-tree-guard.py','openclaw-image-dependency-projector.mjs','openclaw-worktree-test-isolated']:
  p=support/name;need(stat.S_ISREG(p.lstat().st_mode) and not p.is_symlink(),'support regular type');data=p.read_bytes();need(data==git(workflow,'show',w+':.github/qualification/'+name),'authenticated support content');files[name]=data
 mp=support/'b-full-source.json';need(stat.S_ISREG(mp.lstat().st_mode) and sha(mp.read_bytes())==manifest,'source manifest')
 m=json.loads(mp.read_bytes());need(m['source']==S and m['tree']==T and m['workflow']==w and m['parent']==BASE,'manifest identity')
 e={'source':S,'tree':T,'workflow':w,'workflowTree':trees[0],'manifest':manifest,'image':image,'helper':sha(files['openclaw-worktree-test-isolated']),'nonce':secrets.token_hex(32),'run':run,'issued':time.monotonic_ns(),**kernel()}
 return e,files

def bootstrap(expected,bundle):
 need(not any(k.startswith('OPENCLAW_B_LSM_') for k in os.environ),'inherited receipt input');context(expected)
 data=read_frame(0,expected);a=decode(data);need(socket.gethostname()==a['cid'][:12],'actual container ID/hostname mismatch');live=kernel();need(all(expected[k]==live[k] for k in live),'bootstrap kernel/boot')
 need(not os.path.lexists(TRUST) and not os.path.lexists(ROOT),'bootstrap preexisting destination');Path(TRUST).mkdir(mode=0o700)
 for name,encoded in bundle.items():
  need(name in ['b-host-lsm.py','b-physical-allocation.py','vendor_profile.py','b-tree-guard.py','openclaw-image-dependency-projector.mjs','openclaw-worktree-test-isolated'],'trusted file allowlist')
  b=base64.b64decode(encoded,validate=True);p=Path(TRUST)/name;fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
  try:need(os.write(fd,b)==len(b),'trusted bootstrap write')
  finally:os.close(fd)
 Path(ROOT).mkdir(mode=0o755);safe_extract(os.fdopen(os.dup(0),'rb',buffering=0),ROOT)
 mp=Path(ROOT+'/.github/qualification/b-full-source.json');need(sha(mp.read_bytes())==expected['manifest'],'extracted manifest')
 import runpy
 guard=runpy.run_path(TRUST+'/b-tree-guard.py',run_name='trusted_guard');m=guard['load_manifest'](mp,expected['manifest']);need(m['workflow']==expected['workflow'] and m['source']==S and m['tree']==T,'extracted manifest context');guard['verify'](Path(ROOT),m)
 env={**os.environ,'HOME':'/tmp/openclaw-home','XDG_CACHE_HOME':'/tmp/openclaw-cache','CI':'true','OPENCLAW_IMAGE_NODE_MODULES':'/app/node_modules'}
 Path(env['HOME']).mkdir();Path(env['XDG_CACHE_HOME']).mkdir()
 commands=[['git','init','-q'],['git','config','user.name','openclaw-isolated-validation'],['git','config','user.email','openclaw-isolated-validation@invalid'],['git','add','-A'],['git','commit','-q','-m','isolated validation baseline']]
 projector=Path(ROOT+'/scripts/openclaw-image-dependency-projector.mjs');projector.write_bytes(Path(TRUST+'/openclaw-image-dependency-projector.mjs').read_bytes())
 for args in commands:subprocess.run(args,cwd=ROOT,env=env,check=True,close_fds=True)
 subprocess.run(['node',str(projector),ROOT,'/app/node_modules'],cwd=ROOT,env=env,check=True,close_fds=True)
 context(expected);fresh_pipe(data)
 try:p=subprocess.Popen(['bash','.github/qualification/b-run.sh','--image-id',expected['image'],'--manifest-sha',expected['manifest']],cwd=ROOT,env=env,pass_fds=(FD,),close_fds=True)
 finally:os.close(FD)
 code=p.wait();need(code==0,'B command failed '+str(code))

def create_args(image,nonce,argv,envlist):
 args=['create','--pull','never','--network','none','--read-only','--tmpfs','/tmp:rw,nosuid,nodev,exec,size=3g','--security-opt','no-new-privileges','--cap-drop','ALL','--pids-limit','512','--ipc','private','--label','openclaw.purpose=isolated-worktree-test','--label','openclaw.b.host-lsm='+nonce,'--workdir',ROOT,'--entrypoint','/usr/bin/python3','-i']
 for item in envlist:args+=['--env',item]
 return args+[image,'-I','-B',*argv]

def lifecycle(e,files,root,env):
 info=json.loads(command(['info','--format','{{json .}}'],env));e['daemon']=daemon(info)
 ver=json.loads(command(['version','--format','{{json .Server}}'],env));need(ver['Version']=='28.0.4' and ver['GitCommit'] in ['6430e49','6430e49a55babd9b8f4d08e70ecb2b68900770fe'],'Docker commit')
 lsms=lsm_list(small('/sys/kernel/security/lsm',256));live=kernel();need(all(e[k]==live[k] for k in live),'host observation context changed')
 context(e);bundle={k:base64.b64encode(v).decode() for k,v in files.items()}
 source=files['b-host-lsm.py'].decode().replace("if __name__=='__main__':main()",'');code=source+chr(10)+'bootstrap('+repr(e)+','+repr(bundle)+')'+chr(10);need(len(code.encode())<120000,'bootstrap argv bound')
 argv=['-c',code];imageenv=json.loads(command(['image','inspect',e['image']],env));need(len(imageenv)==1 and imageenv[0]['Id']==e['image'],'immutable image')
 envlist=imageenv[0]['Config'].get('Env') or [];need(all(not x.split('=',1)[0].startswith(('DOCKER_','OPENCLAW_B_LSM_','PYTHON')) for x in envlist),'image inherited transport/interpreter environment')
 cid=None;owned=False;attach=None;producer=None;primary=None;writer=None
 try:
  print(json.dumps({'hostLsm':'CREATE_INTENT','workflow':e['workflow'],'image':e['image'],'nonce':e['nonce']}),flush=True)
  raw=command(create_args(e['image'],e['nonce'],argv,[]),env).decode().strip();need(hexid(raw,64),'ambiguous create response: no retry');cid=raw
  actual=json.loads(command(['inspect',cid],env));owned=bool(type(actual)==list and len(actual)==1 and actual[0].get('Id')==cid and actual[0].get('Config',{}).get('Labels',{}).get('openclaw.b.host-lsm')==e['nonce']);inspect_object(actual,cid,e['image'],e['nonce'],argv,envlist);owned=True
  need(daemon(json.loads(command(['info','--format','{{json .}}'],env)))==e['daemon'],'daemon changed before attach')
  live=kernel();need(all(e[k]==live[k] for k in live),'host context changed before attach')
  payload=canonical({'version':1,'context':e,'cid':cid,'lsms':lsms});receipt(decode(payload),e)
  print(json.dumps({'hostLsm':'INSTANCE_VERIFIED','cid':cid,'daemon':e['daemon'],'lsms':lsms}),flush=True)
  attach=subprocess.Popen([DOCKER,'--host',ENDPOINT,'--config','/nonexistent','start','--attach','--interactive',cid],env=env,stdin=subprocess.PIPE,close_fds=True)
  producer=subprocess.Popen(['/usr/bin/tar','--format=gnu','-C',str(root),'--exclude=./.git','--exclude=./node_modules','--exclude=./.artifacts','--exclude=./coverage','-cf','-','.'],env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LC_ALL':'C'},stdout=subprocess.PIPE,stdin=subprocess.DEVNULL,close_fds=True)
  import threading
  errors=[]
  def stream():
   try:
    attach.stdin.write(frame(payload));attach.stdin.flush()
    while True:
     b=producer.stdout.read(65536)
     if not b:break
     attach.stdin.write(b)
    need(producer.wait(timeout=20)==0,'source tar producer failed');attach.stdin.close()
   except BaseException as error:errors.append(error)
   finally:
    try:attach.stdin.close()
    except BaseException as error:errors.append(error)
  writer=threading.Thread(target=stream,daemon=True);writer.start()
  status=attach.wait(timeout=2650);writer.join(timeout=20);need(not writer.is_alive(),'source writer stalled');need(not errors,'source transport error '+str(errors[:1]));need(status==0,'container attach/products failed '+str(status))
 except BaseException as error:primary=error
 finally:
  for child in [producer,attach]:
   if child is not None:
    if child.poll() is None:child.terminate()
    try:child.wait(timeout=5)
    except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
  if writer is not None:
   writer.join(timeout=5)
   if writer.is_alive() and primary is None:primary=ValueError('owned writer failed to reap')
  if cid is not None and owned:
   try:command(['rm','--force',cid],env)
   except BaseException as cleanup:
    if primary is None:primary=cleanup
    elif hasattr(primary,'add_note'):primary.add_note('owned-container cleanup failed: '+str(cleanup)[:128])
  elif cid is not None:print(json.dumps({'hostLsm':'UNVERIFIED_CREATED_ID_NO_DELETE','cid':cid}),flush=True)
 if primary is not None:raise primary

def main():
 need(len(sys.argv)==7 and sys.argv[1]=='host','fixed B host argv')
 need(not os.path.lexists('/nonexistent') and stat.S_ISSOCK(os.stat('/var/run/docker.sock').st_mode),'fixed local Docker endpoint/config');root,w,run,image,manifest=sys.argv[2:];env=docker_environment(os.environ);e,files=host_context(root,w,run,image,manifest)
 def stop(signum,frame):raise SystemExit(128+signum)
 signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop);lifecycle(e,files,Path(root),env)
if __name__=='__main__':main()

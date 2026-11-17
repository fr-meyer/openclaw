#!/usr/bin/env python3
"""Trusted post-close public receipts -> command-safe complete bounded log frames."""
import argparse,base64,hashlib,json,os,pathlib,re,stat,sys
NAMES=('domain.json','graph.json','provenance.json','resources.json','result.json')
RAW=1024*1024;OUT=2*1024*1024;CHUNK=4096
KEYS=('GITHUB_REPOSITORY','GITHUB_REF','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT')
def require(v):
 if not v:raise ValueError('public receipt delivery validation failed')
def identity(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def clean(value):
 if isinstance(value,dict):
  for k,v in value.items():
   require(re.sub(r'[-_ ]','',k.lower()) not in ['password','secret','apikey','authorization','accesstoken','refreshtoken','privatekey','credentials','rawprovider','stdout','stderr','environment','env']);clean(k);clean(v)
 elif isinstance(value,list):
  for v in value:clean(v)
 elif isinstance(value,str):require(not re.search(r'(?i)(-----BEGIN [A-Z ]*PRIVATE KEY|Bearer\s+|\bgh[pousr]_[A-Za-z0-9]{20,}|\bsk-[A-Za-z0-9_-]{16,})',value))
def public_json(raw):
 def pairs(entries):
  value={}
  for k,v in entries:require(k not in value);value[k]=v
  return value
 def invalid_constant(value):raise ValueError('nonfinite public JSON')
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=invalid_constant)
def source_pins():
 here=pathlib.Path(__file__).resolve().parent;root=here.parents[2];manifest=json.loads((here/'PAYLOAD-SHA256.json').read_text());require(str(pathlib.Path(__file__).resolve().relative_to(root)) in manifest)
 for name,digest in manifest.items():
  rel=pathlib.PurePosixPath(name);require(not rel.is_absolute() and '..' not in rel.parts);p=root/name;require(p.resolve()==p and p.is_file() and hashlib.sha256(p.read_bytes()).hexdigest()==digest)
def prepare(directory,project,expected,before_recheck=None):
 root=pathlib.Path(directory).absolute();require(root.resolve()==root and root.is_dir() and not root.is_symlink());rootstat=root.stat();require(set(os.listdir(root))==set(NAMES))
 flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|os.O_NONBLOCK;fd=os.open(root,flags|os.O_DIRECTORY);held=[];records=[];total=0
 try:
  for name in NAMES:
   f=os.open(name,flags,dir_fd=fd);held.append(f);st=os.fstat(f);require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and 0<st.st_size<=RAW);total+=st.st_size;require(total<=RAW)
   raw=b''
   while len(raw)<=st.st_size:
    part=os.read(f,min(65536,st.st_size+1-len(raw)))
    if not part:break
    raw+=part
   require(len(raw)==st.st_size);value=public_json(raw);clean(value);records.append((name,raw,identity(st),value,f))
  data={name:value for name,raw,st,value,f in records};domain=data['domain.json'];result=data['result.json']
  require(domain.get('close')=={'status':'CLOSED','absent':True} and domain.get('status')=='SOURCE_RECIPE_AND_DOMAIN_CLOSURE_PASS' and domain.get('project')==project and domain.get('identity')==expected and domain.get('productQualified') is False)
  require(result.get('status')=='PHASE1_IMAGE_FEASIBILITY_PASS' and result.get('ownedCleanupVerified') is True and result.get('project')==project and result.get('productQualified') is False)
  if before_recheck:before_recheck(root)
  require(identity(root.stat())==identity(rootstat) and root.resolve()==root and set(os.listdir(root))==set(NAMES))
  for name,raw,st,value,f in records:
   require(identity(os.stat(name,dir_fd=fd,follow_symlinks=False))==st and identity(os.fstat(f))==st);os.lseek(f,0,os.SEEK_SET);again=b''
   while len(again)<=len(raw):
    part=os.read(f,min(65536,len(raw)+1-len(again)))
    if not part:break
    again+=part
   require(again==raw and identity(os.fstat(f))==st)
  frames=[]
  def frame(v):
   line=b'OC_PHASE1_LOG_V1 '+json.dumps(v,separators=(',',':'),ensure_ascii=True).encode()+b'\n';require(len(line)<=8192);frames.append(line)
  frame({'type':'BEGIN','files':len(records),'rawBytes':total,'project':project,'identity':expected})
  for name,raw,st,value,f in records:
   chunks=[raw[i:i+CHUNK] for i in range(0,len(raw),CHUNK)];digest=hashlib.sha256(raw).hexdigest();frame({'type':'FILE','name':name,'bytes':len(raw),'sha256':digest,'chunks':len(chunks)})
   for i,chunk in enumerate(chunks):frame({'type':'CHUNK','name':name,'index':i,'base64':base64.b64encode(chunk).decode()})
  frame({'type':'COMPLETE','files':len(records),'rawBytes':total,'manifestSha256':hashlib.sha256(json.dumps([(n,len(r),hashlib.sha256(r).hexdigest()) for n,r,_,_,_ in records],separators=(',',':')).encode()).hexdigest()});output=b''.join(frames);require(len(output)<=OUT);return output
 finally:
  for f in held:os.close(f)
  os.close(fd)
def main(argv=None):
 p=argparse.ArgumentParser();p.add_argument('--directory',required=True);p.add_argument('--project',required=True,choices=['bfl','embeddings']);a=p.parse_args(argv)
 try:
  source_pins();output=prepare(a.directory,a.project,{k:os.environ.get(k) for k in KEYS});written=sys.stdout.buffer.write(output);sys.stdout.buffer.flush();require(written==len(output));return 0
 except Exception:
  # No exception/path/input/private bytes; no stdout before all validation succeeds.
  print('PUBLIC_RECEIPT_LOG_DELIVERY_FAILED_NONQUALIFYING',file=sys.stderr);return 1
if __name__=='__main__':sys.exit(main())

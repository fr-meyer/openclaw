#!/usr/bin/env python3
import argparse,hashlib,importlib.util,json,os,stat
from pathlib import Path
class Refusal(ValueError):pass
def need(x,msg):
 if not x:raise Refusal(msg)
SOURCE='2c4cec2e47930c7825e8256dc9526bf247fcf6b7'
TREE='8076f530775d9f25d398da31d70f954a011b0a90'
CHUNK=65536
MAX_ENTRIES=200000
MAX_BYTES=8*1024**3
MAX_DEPTH=64
MAX_PATH=2048
def signature(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink)
def directory(p):
 p=Path(p);need(p.is_absolute(),'relative directory');fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  for name in p.parts[1:]:
   need(name not in ('.','..'),'traversal');new=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=new
  return fd
 except BaseException:os.close(fd);raise
def stream(fd,size,put=None,git=False):
 h=hashlib.sha1() if git else hashlib.sha256()
 if git:h.update(b'blob '+str(size).encode()+b'\0')
 left=size
 while left:
  b=os.read(fd,min(CHUNK,left));need(bool(b),'short read');h.update(b)
  if put:put(b)
  left-=len(b)
 need(not os.read(fd,1),'growing input');return h.hexdigest()
def scan(roots):
 rows={};total=0
 def walk(fd,label,parts):
  nonlocal total
  need(len(parts)<=MAX_DEPTH,'depth bound');names=[]
  with os.scandir(fd) as entries:
   for entry in entries:
    need(len(names)<MAX_ENTRIES,'directory memory bound');names.append(entry.name)
  names.sort();initial=signature(os.fstat(fd))
  for name in names:
   key=label+'/'+('/'.join(parts+[name]));need(len(key)<=MAX_PATH and len(rows)<MAX_ENTRIES,'manifest bound')
   s=os.stat(name,dir_fd=fd,follow_symlinks=False);mode=stat.S_IMODE(s.st_mode);need(not mode&0o7000,'special permission bits');r={'signature':signature(s),'mode':mode}
   if stat.S_ISDIR(s.st_mode):
    r['kind']='dir';rows[key]=r;child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
    try:walk(child,label,parts+[name])
    finally:os.close(child)
   elif stat.S_ISLNK(s.st_mode):
    target=os.readlink(name,dir_fd=fd);need(len(target)<=MAX_PATH,'long symlink');r.update(kind='link',target=target);rows[key]=r
   elif stat.S_ISREG(s.st_mode):
    need(s.st_nlink==1,'hardlinked donor');total+=s.st_size;need(total<=MAX_BYTES,'data bound');f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
    try:
     need(signature(os.fstat(f))==signature(s),'open drift');digest=stream(f,s.st_size);need(signature(os.fstat(f))==signature(s),'read drift')
    finally:os.close(f)
    r.update(kind='file',bytes=s.st_size,sha256=digest);rows[key]=r
   else:raise Refusal('special node')
   need(signature(os.stat(name,dir_fd=fd,follow_symlinks=False))==signature(s),'entry drift')
  need(sorted(os.listdir(fd))==names and signature(os.fstat(fd))==initial,'directory mutation')
 for label,p in roots.items():
  f=directory(p)
  try:walk(f,label,[])
  finally:os.close(f)
 need(len(json.dumps(rows,separators=(',',':')))<=64*1024**2,'manifest serialization bound');return rows

def source_bindings(root,m):
 need(m['source']==SOURCE and m['tree']==TREE and m['entries'],'source identity');bindings={}
 for rel,row in m['entries'].items():
  if rel=='package.json' or rel.endswith('/package.json'):
   p=Path(root)/rel;fd=directory(p.parent)
   try:f=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
   finally:os.close(fd)
   try:
    s=os.fstat(f);before=signature(s);need(stat.S_ISREG(s.st_mode) and ('100755' if s.st_mode&0o111 else '100644')==row['mode'],'package tracked type/mode');need(s.st_size<=1024**2,'package bound');need(stream(f,s.st_size,git=True)==row['blob'],'package source hash');os.lseek(f,0,0);data=os.read(f,s.st_size);need(len(data)==s.st_size,'package read');pkg=json.loads(data);need(signature(os.fstat(f))==before,'package metadata drift')
   finally:os.close(f)
   if pkg.get('name'):
    relative=Path(rel).parent.as_posix();bindings['/app'+('/'+relative if relative!='.' else '')]=str(Path(root)/relative)
 return bindings

class Mapper:
 def __init__(self,roots,rows,bindings,checkout,final):self.roots={k:str(v) for k,v in roots.items()};self.rows=rows;self.bindings=bindings;self.checkout=Path(checkout);self.final=Path(final)
 def validate_workspace(self,key):
  p=Path(key[1:]);need(p.is_relative_to(self.checkout),'workspace lexical escape');need(p.resolve()==p,'workspace alias descendant')
  rel=p.relative_to(self.checkout).as_posix()
  if hasattr(self,'source_entries'):
   need(rel=='.' or rel in self.source_entries or any(q.startswith(rel+'/') for q in self.source_entries),'workspace expanded unauthenticated descendant')
  if hasattr(self,'source_manifest') and rel in self.source_manifest:
   row=self.source_manifest[rel];fd=directory(p.parent)
   try:f=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
   finally:os.close(fd)
   try:
    st=os.fstat(f);need(stat.S_ISREG(st.st_mode),'workspace tracked type');mode='100755' if st.st_mode&0o111 else '100644';need(mode==row['mode'],'workspace tracked mode');before=signature(st);need(stream(f,st.st_size,git=True)==row['blob'] and signature(os.fstat(f))==before,'workspace tracked blob drift')
   finally:os.close(f)
  return '@'+str(p)
 def classify(self,absolute):
  a=os.path.normpath(absolute)
  for label,root in sorted(self.roots.items(),key=lambda kv:len(kv[1]),reverse=True):
   if a==root:return label
   if a.startswith(root+'/'):return label+'/'+a[len(root)+1:]
  for origin,dest in sorted(self.bindings.items(),key=lambda kv:len(kv[0]),reverse=True):
   if a==origin or a.startswith(origin+'/'):
    result=Path(dest)/os.path.relpath(a,origin);need(result.resolve().is_relative_to(self.checkout),'workspace physical escape')
    if hasattr(self,'source_entries'):
     relative=result.relative_to(self.checkout).as_posix();need(relative=='.' or relative in self.source_entries or any(p.startswith(relative+'/') for p in self.source_entries),'workspace unauthenticated descendant')
    return self.validate_workspace('@'+str(result))
  raise Refusal('unknown donor target '+a)
 def link(self,key):
  label,rel=key.split('/',1);r=self.rows[key];return self.classify(os.path.normpath(os.path.join(os.path.dirname(self.roots[label]+'/'+rel),r['target'])))
 def resolve(self,key,seen=()):
  need(len(seen)<MAX_DEPTH and key not in seen,'symlink cycle')
  if key.startswith('@'):return self.validate_workspace(key)
  parts=key.split('/')
  for i in range(2,len(parts)+1):
   prefix='/'.join(parts[:i]);need(prefix in self.rows,'missing donor target');r=self.rows[prefix]
   if r['kind']=='link':
    suffix='/'.join(parts[i:]);target=self.link(prefix)
    if suffix:target+='/'+suffix
    return self.resolve(target,seen+(key,))
   if i<len(parts):need(r['kind']=='dir','not directory')
  return key
 def local(self,key):
  r=self.resolve(key)
  if hasattr(self,'shim_keys') and key in self.shim_keys:return self.final/'generated-shims'/key
  return Path(r[1:]) if r.startswith('@') else self.final/r
 def validate(self):
  for key,r in self.rows.items():
   if r['kind']=='link':self.resolve(key)

def generated_shim(data,mapper):
 import re
 m=re.fullmatch(b'#!/bin/sh\nexec node "(/app/[^"\n]+)" "\$@"\n',data);need(m is not None,'unknown shim grammar')
 target=mapper.local(mapper.classify(m[1].decode()));need(not any(c in str(target) for c in ['"','$',chr(96),'\n']),'unsafe shim target')
 return ('#!/bin/sh\nexec node "'+str(target)+'" "$@"\n').encode()

def executable_plan(roots,rows,mapper,policy):
 wrappers={};shim_dirs=set()
 for key,r in rows.items():
  parts=key.split('/')
  if '.bin' in parts:
   i=parts.index('.bin');shim_dirs.add('/'.join(parts[:i+1]))
  if r['kind']!='file':continue
  if '.bin' in parts:
   need(r['bytes']<=65536,'shim size bound');label,rel=key.split('/',1);p=Path(roots[label])/rel;fd=directory(p.parent)
   try:f=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
   finally:os.close(fd)
   try:
    need(signature(os.fstat(f))==tuple(r['signature']),'shim drift');data=os.read(f,r['bytes']);need(len(data)==r['bytes'] and hashlib.sha256(data).hexdigest()==r['sha256'],'shim hash')
   finally:os.close(f)
   wrappers[key]=generated_shim(data,mapper)
  elif r['mode']&0o111:
   # A package binary/script is admitted only by independently reviewed exact identity policy.
   policy.authorize_native_or_script(key,r['sha256'],r['mode'])
 # Every .bin child is represented locally; original donor files stay byte-identical.
 mapper.shim_keys={k for k in rows if any(k==d or k.startswith(d+'/') for d in shim_dirs)}
 return {'dirs':sorted(shim_dirs),'wrappers':wrappers}

def build_shims(stage,mapper,rows,plan,c):
 base=Path(stage)/'generated-shims';operation(c,'mkdir',0,lambda:base.mkdir(mode=0o700));made=set()
 def parents(relative):
  current=base
  for name in Path(relative).parts:
   current=current/name
   if str(current) not in made:
    operation(c,'mkdir',0,lambda current=current:current.mkdir(mode=0o700));made.add(str(current))
 for d in plan['dirs']:parents(d)
 for key in sorted(mapper.shim_keys):
  r=rows[key]
  if r['kind']=='dir':parents(key);continue
  p=base/key;parents(str(Path(key).parent))
  if key in plan['wrappers']:
   data=plan['wrappers'][key];fd=directory(p.parent)
   try:f=operation(c,'create',0,lambda:os.open(p.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd))
   finally:os.close(fd)
   try:
    def write():need(os.write(f,data)==len(data),'shim short write')
    operation(c,'write',len(data),write);operation(c,'chmod',0,lambda:os.fchmod(f,r['mode']))
   finally:os.close(f)
  else:
   # Link to exact physical target, not the original external .bin namespace.
   resolved=mapper.resolve(key);target=Path(resolved[1:]) if resolved.startswith('@') else (mapper.final/'generated-shims'/resolved if resolved in plan['wrappers'] else mapper.final/resolved)
   operation(c,'symlink',len(os.fsencode(str(target))),lambda p=p,target=target:os.symlink(str(target),p))

def verify_shims(final,mapper,rows,plan):
 for key in mapper.shim_keys:
  p=Path(final)/'generated-shims'/key;r=rows[key]
  if key in plan['wrappers']:
   need(p.stat().st_size<=65536,'generated shim bound');need(p.read_bytes()==plan['wrappers'][key] and stat.S_IMODE(p.stat().st_mode)==r['mode'],'generated shim drift')
  elif r['kind']=='link':need(p.resolve().is_relative_to(mapper.checkout),'generated bin alias escape')

class Contract:
 def __init__(self,path,pin,context):
  need(path and pin,'reviewed allocator adapter missing');p=Path(path);need(not p.is_symlink() and p.stat().st_size<=1024**2,'contract artifact')
  b=p.read_bytes();need(hashlib.sha256(b).hexdigest()==pin,'contract digest');spec=importlib.util.spec_from_file_location('reviewed_allocator',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);need(m.API_VERSION==1,'contract API');self.backend=m.open_contract(context)
 def __getattr__(self,name):return getattr(self.backend,name)
def operation(c,kind,size,fn):
 ticket=c.before(kind,size)
 try:result=fn()
 except BaseException as primary:
  try:c.after(ticket)
  except BaseException as accounting:
   if hasattr(primary,'add_note'):primary.add_note('after failure: '+str(accounting)[:256])
  if hasattr(c,'failure'):
   try:c.failure(primary)
   except BaseException as receipt:
    if hasattr(primary,'add_note'):primary.add_note('failure receipt: '+str(receipt)[:256])
  raise
 c.after(ticket);return result

def copy(roots,rows,mapper,stage,c,hook=None):
 stage=Path(stage);fd=directory(stage.parent)
 try:
  need(not os.path.lexists(stage),'existing stage');operation(c,'mkdir',0,lambda:os.mkdir(stage.name,0o700,dir_fd=fd))
 finally:os.close(fd)
 for label in roots:operation(c,'mkdir',0,lambda label=label:(stage/label).mkdir(mode=0o700))
 for key,r in sorted(rows.items(),key=lambda kv:(kv[0].count('/'),kv[0])):
  if r['kind']=='dir':operation(c,'mkdir',0,lambda key=key:(stage/key).mkdir(mode=0o700))
 for key,r in rows.items():
  p=stage/key
  if r['kind']=='file':
   label,rel=key.split('/',1);src=Path(roots[label])/rel;fd=directory(src.parent)
   try:f=os.open(src.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
   finally:os.close(fd)
   try:
    need(signature(os.fstat(f))==tuple(r['signature']),'source before copy drift');parent=directory(p.parent)
    try:g=operation(c,'create',0,lambda:os.open(p.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent))
    finally:os.close(parent)
    try:
     def put(data):
      if hook:hook('write',p)
      def write():need(os.write(g,data)==len(data),'partial write')
      operation(c,'write',len(data),write)
     need(stream(f,r['bytes'],put)==r['sha256'] and signature(os.fstat(f))==tuple(r['signature']),'source hash drift');operation(c,'chmod',0,lambda:os.fchmod(g,r['mode']))
    finally:os.close(g)
   finally:os.close(f)
  elif r['kind']=='link':
   target=os.path.relpath(mapper.local(key),mapper.final/key.rsplit('/',1)[0]);fd=directory(p.parent)
   try:operation(c,'symlink',len(os.fsencode(target)),lambda:os.symlink(target,p.name,dir_fd=fd))
   finally:os.close(fd)
 for key,r in sorted(rows.items(),key=lambda kv:kv[0].count('/'),reverse=True):
  if r['kind']=='dir':operation(c,'chmod',0,lambda key=key,r=r:os.chmod(stage/key,r['mode'],follow_symlinks=False))
 verify(rows,mapper,stage);need(scan(roots)==rows,'donor entryset drift');return stage

def verify(rows,mapper,stage):
 found=set()
 for label in mapper.roots:
  for base,dirs,files in os.walk(Path(stage)/label,followlinks=False):
   for name in dirs+files:found.add((Path(base)/name).relative_to(stage).as_posix())
 need(found==set(rows),'copy entryset')
 for key,r in rows.items():
  p=Path(stage)/key;s=p.lstat()
  if r['kind']=='file':
   need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==r['mode'],'copy mode/type');need((s.st_dev,s.st_ino)!=tuple(r['signature'][:2]),'donor inode alias');f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
   try:need(stream(f,s.st_size)==r['sha256'],'copy hash')
   finally:os.close(f)
  elif r['kind']=='link':need(stat.S_ISLNK(s.st_mode) and os.readlink(p)==os.path.relpath(mapper.local(key),mapper.final/key.rsplit('/',1)[0]),'copy link')
  else:need(stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode)==r['mode'],'copy directory')
def promote(stage,final,c):
 stage=Path(stage);final=Path(final);need(stage.parent==final.parent and not os.path.lexists(final),'rename destination');fd=directory(final.parent)
 try:operation(c,'rename',0,lambda:os.rename(stage.name,final.name,src_dir_fd=fd,dst_dir_fd=fd))
 finally:os.close(fd)
def replace_alias(path,target,record,tracked,c):
 path=Path(path);need(str(path) not in tracked,'tracked collision');fd=directory(path.parent)
 try:
  s=os.stat(path.name,dir_fd=fd,follow_symlinks=False);need(stat.S_ISLNK(s.st_mode) and signature(s)==tuple(record['signature']) and os.readlink(path.name,dir_fd=fd)==record['target'],'unexpected alias')
  operation(c,'unlink-link',0,lambda:os.unlink(path.name,dir_fd=fd));operation(c,'symlink',len(os.fsencode(str(target))),lambda:os.symlink(str(target),path.name,dir_fd=fd))
 finally:os.close(fd)

def runtime(args):
 import resource
 resource.setrlimit(resource.RLIMIT_AS,(768*1024**2,768*1024**2))
 root=Path.cwd();need(str(root)=='/tmp/openclaw-worktree-test','runtime checkout');mp=root/'.github/qualification/b-full-source.json';need(mp.stat().st_size<=64*1024**2,'source manifest bound');data=mp.read_bytes();need(hashlib.sha256(data).hexdigest()==args.manifest_sha256,'manifest digest');manifest=json.loads(data)
 roots={'root':'/app/node_modules','ui':'/app/ui/node_modules'}
 c=Contract(args.contract,args.contract_sha256,{'checkout':str(root),'donors':roots,'source':SOURCE,'tree':TREE,'imageId':args.image_id,'manifestSha256':args.manifest_sha256,'workflow':manifest['workflow'],'capacityReceipt':'/tmp/b-capacity-admission','capacityReceiptSha256':args.capacity_receipt_sha256})
 try:
  rows=scan(roots);c.bind_manifest(roots,rows);final=root/'node_modules/.b-physical-store';stage=final.with_name('.b-physical-stage');mapper=Mapper(roots,rows,source_bindings(root,manifest),root,final);mapper.source_entries=set(manifest['entries']);mapper.source_manifest=manifest['entries'];mapper.validate()
  shim_plan=executable_plan(roots,rows,mapper,c)
  tracked={str(root/p) for p in manifest['entries']};aliases=[]
  for dest in [stage,final]:
   need(not os.path.lexists(dest),'reserved generated destination exists')
   need(not any(p==str(dest) or p.startswith(str(dest)+'/') or str(dest).startswith(p+'/') for p in tracked),'tracked staging collision')
  # Only exact existing projector-created links to known donor graph can be replaced.
  for scope,label in [('node_modules','root'),('ui/node_modules','ui')]:
   top=root/scope;fd=directory(top)
   try:
    for name in sorted(os.listdir(fd)):
     p=top/name;s=os.stat(name,dir_fd=fd,follow_symlinks=False)
     if stat.S_ISLNK(s.st_mode):
      target=os.readlink(name,dir_fd=fd);a=os.path.normpath(os.path.join(str(top),target))
      if a.startswith(str(root)+'/'):continue
      key=mapper.classify(a);dest=mapper.local(key);need(str(p) not in tracked,'tracked alias')
      aliases.append((p,dest,{'signature':signature(s),'target':target}))
     elif name.startswith('@') and stat.S_ISDIR(s.st_mode):
      scoped=directory(p)
      try:
       for child in sorted(os.listdir(scoped)):
        q=p/child;t=os.stat(child,dir_fd=scoped,follow_symlinks=False);need(stat.S_ISLNK(t.st_mode),'unrecognized scoped generated entry');target=os.readlink(child,dir_fd=scoped);a=os.path.normpath(os.path.join(str(p),target))
        if a.startswith(str(root)+'/'):continue
        aliases.append((q,mapper.local(mapper.classify(a)),{'signature':signature(t),'target':target}))
      finally:os.close(scoped)
     else:raise Refusal('unrecognized generated entry '+name)
   finally:os.close(fd)
  # Unknown executable bytes are refused, not implicitly proved safe.
  # Contract supplies independently reviewed immutable native/shim policy evidence.
  need(all(str(p) not in tracked for p,t,r in aliases),'tracked alias before writes')
  c.preflight(rows,{'aliases':[{'path':str(p),'target':str(t),'before':r} for p,t,r in aliases],'stage':str(stage),'final':str(final),'receipt':'/tmp/b-physical-receipt','generatedShims':{k:{'bytes':len(v),'sha256':hashlib.sha256(v).hexdigest()} for k,v in shim_plan['wrappers'].items()},'generatedShimDirs':shim_plan['dirs'],'operations':full_ledger(roots,rows,mapper,shim_plan,aliases)})
  copy(roots,rows,mapper,stage,c);build_shims(stage,mapper,rows,shim_plan,c);promote(stage,final,c)
  for p,target,record in aliases:replace_alias(p,target,record,tracked,c)
  verify(rows,mapper,final);verify_shims(final,mapper,rows,shim_plan)
  for key,r in rows.items():
   if r['kind']=='link':need((final/key).resolve().is_relative_to(root),'postphysical external alias')
  c.finish({'source':SOURCE,'tree':TREE,'entries':len(rows),'final':str(final)})
 except BaseException as primary:
  try:c.failure(primary)
  except BaseException as secondary:
   if hasattr(primary,'add_note'):primary.add_note('finalizer: '+str(secondary)[:256])
  raise
def main():
 p=argparse.ArgumentParser();p.add_argument('--manifest-sha256',required=True);p.add_argument('--image-id',required=True);p.add_argument('--capacity-receipt-sha256',required=True);p.add_argument('--contract');p.add_argument('--contract-sha256');args=p.parse_args();runtime(args)
# Copied into copier module before runtime main by build step.
def shim_manifest(mapper,rows,plan):
 expected={'':{'kind':'dir','mode':0o700}}
 def dirs(rel):
  parts=Path(rel).parts
  for i in range(1,len(parts)+1):expected['/'.join(parts[:i])]={'kind':'dir','mode':0o700}
 for d in plan['dirs']:dirs(d)
 for key in sorted(mapper.shim_keys):
  r=rows[key];dirs(str(Path(key).parent))
  if r['kind']=='dir':dirs(key)
  elif key in plan['wrappers']:expected[key]={'kind':'file','mode':r['mode'],'bytes':plan['wrappers'][key]}
  else:
   resolved=mapper.resolve(key)
   target=Path(resolved[1:]) if resolved.startswith('@') else (mapper.final/'generated-shims'/resolved if resolved in plan['wrappers'] else mapper.final/resolved)
   expected[key]={'kind':'link','mode':0o777,'target':str(target)}
 return expected

def verify_shims(final,mapper,rows,plan):
 base=Path(final)/'generated-shims';expected=shim_manifest(mapper,rows,plan);found={''}
 for parent,dirs,files in os.walk(base,followlinks=False):
  for name in dirs+files:found.add((Path(parent)/name).relative_to(base).as_posix())
 need(found==set(expected),'generated shim exact entryset')
 for rel,e in expected.items():
  p=base/rel;st=p.lstat();need(stat.S_IMODE(st.st_mode)==e['mode'],'generated shim mode')
  if e['kind']=='dir':need(stat.S_ISDIR(st.st_mode),'generated dir type')
  elif e['kind']=='link':need(stat.S_ISLNK(st.st_mode) and os.readlink(p)==e['target'],'generated link target/type');need(p.resolve().is_relative_to(mapper.checkout),'generated link containment')
  else:
   need(stat.S_ISREG(st.st_mode) and st.st_size==len(e['bytes']),'generated wrapper type/size');f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
   try:need(stream(f,st.st_size)==hashlib.sha256(e['bytes']).hexdigest(),'generated wrapper bytes')
   finally:os.close(f)

def full_ledger(roots,rows,mapper,plan,aliases):
 ops=[]
 def add(k,n=0):ops.append([k,n])
 add('mkdir')
 for label in roots:add('mkdir')
 for key,r in sorted(rows.items(),key=lambda kv:(kv[0].count('/'),kv[0])):
  if r['kind']=='dir':add('mkdir')
 for key,r in rows.items():
  if r['kind']=='file':
   add('create');left=r['bytes']
   while left:n=min(CHUNK,left);add('write',n);left-=n
   add('chmod')
  elif r['kind']=='link':add('symlink',len(os.fsencode(os.path.relpath(mapper.local(key),mapper.final/key.rsplit('/',1)[0]))))
 for key,r in sorted(rows.items(),key=lambda kv:kv[0].count('/'),reverse=True):
  if r['kind']=='dir':add('chmod')
 add('mkdir');made=set()
 def parents(rel):
  parts=Path(rel).parts
  for i in range(1,len(parts)+1):
   prefix='/'.join(parts[:i])
   if prefix not in made:made.add(prefix);add('mkdir')
 for d in plan['dirs']:parents(d)
 for key in sorted(mapper.shim_keys):
  r=rows[key]
  if r['kind']=='dir':parents(key);continue
  parents(str(Path(key).parent))
  if key in plan['wrappers']:add('create');add('write',len(plan['wrappers'][key]));add('chmod')
  else:
   resolved=mapper.resolve(key);target=Path(resolved[1:]) if resolved.startswith('@') else (mapper.final/'generated-shims'/resolved if resolved in plan['wrappers'] else mapper.final/resolved)
   add('symlink',len(os.fsencode(str(target))))
 add('rename')
 for p,target,record in aliases:add('unlink-link');add('symlink',len(os.fsencode(str(target))))
 need(len(ops)<=2000000,'operation ledger bound')
 return ops

if __name__=='__main__':main()

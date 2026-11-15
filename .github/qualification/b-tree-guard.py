import hashlib,json,os,pathlib,re,stat,subprocess,sys
SOURCE='2c4cec2e47930c7825e8256dc9526bf247fcf6b7'
TREE='8076f530775d9f25d398da31d70f954a011b0a90'
BASE='30786562e236aab6a924981c62aa61b920132c76'
SUPPORT='.github/qualification/'
CHANGED=['ui/src/i18n/locales/en.ts','ui/src/pages/chat/chat-composer-queue.test.ts','ui/src/pages/chat/chat-thread-inputs.ts','ui/src/pages/chat/chat-thread-items.ts','ui/src/pages/chat/components/chat-composer-queue.ts','ui/src/pages/chat/user-message-content.ts']
def git(root,*args):
 return subprocess.check_output(['git','-C',str(root),*args],env={**os.environ,'GIT_NO_LAZY_FETCH':'1','GIT_OPTIONAL_LOCKS':'0'})
def blob(data): return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
def headers(raw):
 lines=raw.split(b'\n\n',1)[0].splitlines()
 return [x[5:].decode() for x in lines if x.startswith(b'tree ')],[x[7:].decode() for x in lines if x.startswith(b'parent ')]
def check_commit(root,sha,tree,parent):
 raw=git(root,'cat-file','commit',sha)
 actual=hashlib.sha1(b'commit '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
 trees,parents=headers(raw)
 if actual!=sha or trees!=[tree] or parents!=[parent]: raise ValueError('commit/tree/sole-parent mismatch')
def tracked(root):
 entries={}
 for row in git(root,'ls-files','-s','-z').split(b'\0'):
  if not row: continue
  meta,name=row.split(b'\t',1); mode,sha,stage=meta.decode().split(); name=name.decode()
  if stage!='0' or mode not in ('100644','100755','120000') or name in entries: raise ValueError('unsupported index entry')
  entries[name]={'mode':mode,'blob':sha}
 tree={}
 for row in git(root,'ls-tree','-r','-z','HEAD').split(b'\0'):
  if not row: continue
  meta,name=row.split(b'\t',1); mode,kind,sha=meta.decode().split()
  if kind!='blob': raise ValueError('unsupported tree kind')
  tree[name.decode()]={'mode':mode,'blob':sha}
 if entries!=tree: raise ValueError('index differs from source tree')
 return entries
def file_entry(root,name):
 p=root/name
 for parent in p.parents:
  if parent==root: break
  if parent.is_symlink(): raise ValueError('symlink ancestor')
 st=p.lstat()
 if stat.S_ISLNK(st.st_mode): mode='120000'; data=os.fsencode(os.readlink(p))
 elif stat.S_ISREG(st.st_mode): mode='100755' if st.st_mode & 0o111 else '100644'; data=p.read_bytes()
 else: raise ValueError('source type drift')
 return {'mode':mode,'blob':blob(data)}
def generated(name):
 # Only UNTRACKED generated namespaces. Tracked entries are NEVER excluded.
 return (name.startswith(('node_modules/','ui/node_modules/','.artifacts/','dist/control-ui/')) or name in ('node_modules','ui/node_modules') or bool(re.match(r'^dist/control-ui\.build-[1-9][0-9]*-[\w-]+(?:\.retired)?(?:/|$)',name)))
def verify(root,m):
 if m['source']!=SOURCE or m['tree']!=TREE or m['parent']!=BASE or not re.fullmatch('[0-9a-f]{40}',m['workflow']) or m['workflow']==SOURCE: raise ValueError('manifest identity mismatch')
 entries=m['entries']; allowed=set(m['supportFiles'])|{'scripts/openclaw-image-dependency-projector.mjs'}
 for name,expected in {**entries,**m.get('supportEntries',{})}.items():
  if file_entry(root,name)!=expected: raise ValueError('source mode/type/blob drift: '+name)
 projector=root/'scripts/openclaw-image-dependency-projector.mjs'
 if m.get('requireProjector') and not projector.is_file(): raise ValueError('missing runtime projector')
 if (projector.exists() or projector.is_symlink()) and 'scripts/openclaw-image-dependency-projector.mjs' not in entries:
  if projector.is_symlink() or hashlib.sha256(projector.read_bytes()).hexdigest()!='ac5e1c1d9f00ff0079a904cba21535c041bd9d4be9a7421b9e666c6c73b3dd7b': raise ValueError('injected projector drift')
 for base,dirs,files in os.walk(root,followlinks=False):
  rel=pathlib.Path(base).relative_to(root)
  for name in list(dirs):
   p=(rel/name).as_posix()
   if p=='.git' or generated(p+'/'): dirs.remove(name); continue
   if (pathlib.Path(base)/name).is_symlink(): dirs.remove(name); files.append(name)
  for name in files:
   p=(rel/name).as_posix()
   if p in entries or p in allowed or p=='.git' or generated(p): continue
   raise ValueError('unexpected source file: '+p)
def capture(root,workflow,out):
 if git(root,'rev-parse','HEAD').decode().strip()!=SOURCE: raise ValueError('wrong source HEAD')
 check_commit(root,SOURCE,TREE,BASE)
 w=git(workflow,'rev-parse','HEAD').decode().strip()
 if w==SOURCE: raise ValueError('workflow must differ from source')
 raw=git(workflow,'cat-file','commit',w); wt,parents=headers(raw)
 if len(wt)!=1: raise ValueError('workflow tree mismatch')
 check_commit(workflow,w,wt[0],SOURCE)
 changed=git(root,'diff-tree','--no-commit-id','--name-only','-r',SOURCE).decode().splitlines()
 if sorted(changed)!=sorted(CHANGED): raise ValueError('source diff not exact six')
 diff=git(workflow,'diff-tree','--no-commit-id','--name-only','-r',w).decode().splitlines()
 if not diff or any(not (p.startswith(SUPPORT) or p=='.github/workflows/unified-b-outbox-source307-qualification.yml') for p in diff): raise ValueError('workflow child changes feature source')
 support_entries={p:e for p,e in tracked(workflow).items() if p.startswith(SUPPORT)}
 for p,e in support_entries.items():
  if file_entry(workflow,p)!=e: raise ValueError('W support working-file drift')
 support=list(support_entries)
 if any(p in support for p in [SUPPORT+'b-full-source.json',SUPPORT+'b-full-source.sha256']): raise ValueError('reserved generated manifest path in W')
 support += [SUPPORT+'b-full-source.json',SUPPORT+'b-full-source.sha256']
 m={'source':SOURCE,'tree':TREE,'parent':BASE,'workflow':w,'entries':tracked(root),'supportEntries':support_entries,'supportFiles':sorted(set(support))}
 # Before injection there must be only the source tree and Git metadata.
 verify(root,{**m,'supportFiles':[],'supportEntries':{}})
 data=json.dumps(m,sort_keys=True,separators=(',',':')).encode()
 out.write_bytes(data); out.with_suffix('.sha256').write_text(hashlib.sha256(data).hexdigest())
 print(json.dumps({'source':SOURCE,'tree':TREE,'workflow':w,'trackedFiles':len(m['entries']),'manifestSha256':hashlib.sha256(data).hexdigest()}))
def load_manifest(path,expected=None):
 data=path.read_bytes()
 digest=hashlib.sha256(data).hexdigest()
 side=path.with_suffix('.sha256')
 if side.read_text()!=digest or (expected is not None and digest!=expected): raise ValueError('manifest digest mismatch')
 if path.is_symlink() or side.is_symlink() or file_entry(path.parent,path.name)['mode']!='100644' or file_entry(side.parent,side.name)['mode']!='100644': raise ValueError('manifest mode/type drift')
 return json.loads(data)
if __name__=='__main__':
 if sys.argv[1]=='capture': capture(pathlib.Path(sys.argv[2]).resolve(),pathlib.Path(sys.argv[3]).resolve(),pathlib.Path(sys.argv[4]))
 elif sys.argv[1]=='verify':
  path=pathlib.Path(sys.argv[3]) if len(sys.argv)>3 else pathlib.Path(__file__).with_name('b-full-source.json'); expected=sys.argv[4] if len(sys.argv)>4 else None; m=load_manifest(path,expected); m['requireProjector']=expected is not None; verify(pathlib.Path(sys.argv[2]).resolve(),m)
  print(json.dumps({'fullSource':'PASS','source':m['source'],'tree':m['tree'],'manifestSha256':hashlib.sha256(path.read_bytes()).hexdigest(),'trackedFiles':len(m['entries'])}))
 else: raise SystemExit('invalid mode')

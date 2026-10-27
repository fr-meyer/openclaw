"""Pure joins over authenticated-package evidence and injected installed views.

This code is not a signature verifier, package installer, dependency solver or
an operational capability. The checked build owner must establish signature,
index, install and context receipt provenance before it supplies these inputs.
No dpkg/ldd/archive/tool command is executed here. CLI is inert.
"""
import posixpath
import re
import runtime_prepare as runtime

ARMED=False
PROOF_KEYS={'schema','contextSha256','signatureProofSha256','installProofSha256','indexSha256',
 'installedShowSha256','filelistsSha256','ownershipSha256','resolutionsSha256','cacheInventorySha256'}
STAT_KEYS={'sourcePath','type','dev','ino','size','uid','gid','mode','nlink','mtimeNs','ctimeNs','aliasProofSha256'}
TOOL_PATHS={'/usr/bin/gcc-12','/usr/lib/gcc/x86_64-linux-gnu/12/cc1',
 '/usr/lib/gcc/x86_64-linux-gnu/12/collect2','/usr/bin/as','/usr/bin/ld'}
FILE_CAP=64*1024*1024
INDEX_CAP=128*1024*1024
MAX_FILES=30000
MAX_READ_BYTES=512*1024*1024
SITE_CUSTOMIZE=runtime.STDLIB+'sitecustomize.py'
DASH_DIVERSION={
 '/bin/sh':'package diverts others to: /bin/sh.distrib',
 '/usr/share/man/man1/sh.1.gz':'package diverts others to: /usr/share/man/man1/sh.distrib.1.gz',
}


def need(value,code):runtime.need(value,code)
def sha(raw):return runtime.sha(raw)
def canonical(value):return runtime.canonical(value)
def hexdigest(value):return runtime.hexsha(value)


def _mapping_digest(value):
 need(type(value)is dict and all(type(k)is str and type(v)is bytes for k,v in value.items()),'inventory.raw_mapping')
 return sha(canonical({k:sha(v) for k,v in value.items()}))


def input_binding(packages_raw,show,filelists,ownership,resolutions,cache_paths,*,context_sha256,signature_sha256,install_sha256):
 """Construct hash joins only; this does not establish trust/authority."""
 indexes=_indexes(packages_raw)
 return {'schema':'ocv-installed-file-input-binding-v1','contextSha256':context_sha256,
  'signatureProofSha256':signature_sha256,'installProofSha256':install_sha256,'indexSha256':sorted(indexes),
  'installedShowSha256':sha(show),'filelistsSha256':_mapping_digest(filelists),'ownershipSha256':_mapping_digest(ownership),
  'resolutionsSha256':_mapping_digest(resolutions),'cacheInventorySha256':sha(canonical(cache_paths))}


def _indexes(raw):
 values={sha(raw):raw} if type(raw)is bytes else raw
 need(type(values)is dict and 1<=len(values)<=8,'inventory.index_count')
 need(all(hexdigest(k) and type(v)is bytes and 0<len(v)<=INDEX_CAP and sha(v)==k for k,v in values.items()),
      'inventory.index_hash')
 need(sum(len(v) for v in values.values())<=INDEX_CAP,'inventory.index_total')
 return values


def parse_packages(indexes):
 result={}
 for index_sha,raw in indexes.items():
  try:lines=raw.decode('utf-8','strict').splitlines()
  except UnicodeError:raise runtime.Refusal('inventory.index_encoding') from None
  stanza={};records=0
  def finish():
   nonlocal records
   if not stanza:return
   required={'Package','Version','Architecture','Filename','Size','SHA256'}
   need(required<=set(stanza),'inventory.index_fields')
   name,version,arch=stanza['Package'],stanza['Version'],stanza['Architecture']
   need(re.fullmatch('[a-z0-9][a-z0-9+.-]{0,80}',name) and re.fullmatch('[A-Za-z0-9.+~:-]{1,128}',version)
        and arch in('amd64','all'),'inventory.index_identity')
   filename=stanza['Filename'];size=stanza['Size'];digest=stanza['SHA256']
   need(filename.startswith('pool/') and filename.endswith('.deb') and posixpath.normpath(filename)==filename
        and '..'not in filename.split('/') and len(filename)<=512 and hexdigest(digest)
        and re.fullmatch('[1-9][0-9]{0,9}',size) and int(size)<=16*1024*1024*1024,'inventory.index_archive')
   key=(name,version,arch);value={'filename':filename,'bytes':int(size),'sha256':digest,'indexSha256':[index_sha]}
   if key in result:
    need(all(result[key][k]==value[k] for k in('filename','bytes','sha256')),'inventory.index_conflict')
    result[key]['indexSha256'].append(index_sha)
   else:result[key]=value
   records+=1;need(records<=250000,'inventory.index_records')
  previous=None
  for line in lines+['']:
   if not line:
    finish();stanza={};previous=None;continue
   if line.startswith((' ','\t')):
    need(previous is not None,'inventory.index_continuation');continue
   need(':'in line,'inventory.index_line');key,value=line.split(':',1)
   need(re.fullmatch('[A-Za-z][A-Za-z0-9-]{0,63}',key) and key not in stanza,'inventory.index_duplicate')
   stanza[key]=value.strip();previous=key
 return result


def parse_show(raw):
 need(type(raw)is bytes and 0<len(raw)<=262144,'inventory.show_cap')
 try:lines=raw.decode('ascii').splitlines()
 except UnicodeError:raise runtime.Refusal('inventory.show_encoding') from None
 result={}
 for line in lines:
  fields=line.split('\t');need(len(fields)==4,'inventory.show_shape')
  binary,version,arch,state=fields
  need(re.fullmatch('[a-z0-9][a-z0-9+.-]{0,80}(?::(?:amd64|all))?',binary) and arch in('amd64','all')
       and re.fullmatch('[A-Za-z0-9.+~:-]{1,128}',version) and state=='installed','inventory.show_identity')
  name=binary.split(':')[0];need(name not in result and (':'not in binary or binary.rsplit(':',1)[1]==arch),
                              'inventory.show_duplicate')
  result[name]={'binaryName':binary,'name':name,'version':version,'architecture':arch}
 need(4<=len(result)<=512,'inventory.show_count');return result


def parse_listfiles(raw,*,binary_name=None):
 need(type(raw)is bytes and len(raw)<=4*1024*1024,'inventory.filelist_cap')
 try:lines=raw.decode('utf-8','strict').splitlines()
 except UnicodeError:raise runtime.Refusal('inventory.filelist_encoding') from None
 result=[];seen=set();previous=None;dash_diversions=set()
 for line in lines:
  if line in('/.','/'):continue
  # Bookworm dash records its two package-owned shell diversions immediately
  # after their paths. Annotations are not files; no other diversion is admitted.
  if line in DASH_DIVERSION.values():
   need(binary_name=='dash' and DASH_DIVERSION.get(previous)==line and line not in dash_diversions,
        'inventory.filelist_diversion')
   dash_diversions.add(line);continue
  need(line.startswith('/') and '\x00'not in line and posixpath.normpath(line)==line and '..'not in line.split('/')
       and len(line)<=1024 and line not in seen,'inventory.filelist_path')
  result.append(line);seen.add(line);previous=line;need(len(result)<=MAX_FILES,'inventory.filelist_count')
 return set(result)


def owner_lookup_path(path,lists,dependency_paths):
 """Select a package-recorded /usr path only for an ldd /lib alias.

 The fallback is limited to one signed installed-file-list entry. Actual
 alias and byte identity are checked independently by build_inventory().
 """
 need(type(path)is str and type(lists)is dict and type(dependency_paths)is set,
      'inventory.owner_lookup_inputs')
 if any(path in paths for paths in lists.values()):return path
 prefix='/lib/x86_64-linux-gnu/'
 if (path in dependency_paths and path.startswith(prefix) and
     re.fullmatch(r'[A-Za-z0-9_.+-]{1,128}\.so(?:\.[A-Za-z0-9_.+-]{1,64})?',path[len(prefix):])):
  recorded='/usr'+path
  if sum(recorded in paths for paths in lists.values())==1:return recorded
 return path


def _metadata(value,*,allow_directory=False):
 need(type(value)is dict and set(value)==STAT_KEYS,'inventory.metadata_schema')
 need(type(value['sourcePath'])is str and value['sourcePath'].startswith('/') and '\x00'not in value['sourcePath'] and len(value['sourcePath'])<=1024
      and posixpath.normpath(value['sourcePath'])==value['sourcePath'] and '..'not in value['sourcePath'].split('/')
      and all(type(value[k])is int and 0<=value[k]<1<<63 for k in('dev','ino','size','uid','gid','mode','nlink','mtimeNs','ctimeNs'))
      and value['uid']==value['gid']==0 and value['mode']<=0o7777 and value['mode']&0o022==0
      and value['ino']>0 and value['nlink']>=1 and hexdigest(value['aliasProofSha256'])
      and value['type']in(('regular','directory') if allow_directory else ('regular',)),'inventory.metadata_identity')
 return value


def _read_checked(reader,path,cap,before=None):
 before=_metadata(reader.stat_original(path) if before is None else before)
 need(before['size']<=cap,'inventory.file_size')
 view=reader.read_original(path,cap)
 need(type(view)is dict and set(view)=={'bytes','sourcePath','uid','gid','mode','regular','symlinkChainSha256'}
      and type(view['bytes'])is bytes and len(view['bytes'])<=cap and view['regular'] is True
      and view['sourcePath']==before['sourcePath'] and view['uid']==before['uid'] and view['gid']==before['gid']
      and view['mode']==before['mode'] and view['symlinkChainSha256']==before['aliasProofSha256'],
      'inventory.file_view')
 after=_metadata(reader.stat_original(path))
 need(before==after and len(view['bytes'])==before['size'],'inventory.file_changed')
 return view['bytes'],before


def build_inventory(packages_raw,installed_show_raw,filelists,ownership,resolutions,reader,proof,cache_paths=None):
 """Return (frozen-collector installed manifest, separate provenance evidence).

 Fixed show command format:
 dpkg-query --show --showformat='${binary:Package}\\t${Version}\\t${Architecture}\\t${db:Status-Status}\\n'
 filelists[binaryName] is actual dpkg-query --listfiles stdout. ownership[path]
 is actual dpkg-query --search stdout for the package-recorded original path.
 For an ldd /lib path missing from all package file lists, that query may use
 the exact package-listed /usr/lib alias; both paths must resolve to identical
 checked package bytes.
 resolutions[Python/each stdlib.so] is standard guest ldd stdout. None of these
 commands is invoked by this helper. proof is a checked owner's hash join to
 actual signature/install/context records, never a JSON passed verdict.
 """
 cache_paths={} if cache_paths is None else cache_paths
 indexes=_indexes(packages_raw)
 need(type(proof)is dict and set(proof)==PROOF_KEYS and proof['schema']=='ocv-installed-file-input-binding-v1',
      'inventory.proof_schema')
 need(all(hexdigest(proof[k]) for k in PROOF_KEYS-{'schema','indexSha256'}),'inventory.proof_hash')
 need(proof['indexSha256']==sorted(indexes),'inventory.index_binding')
 expected=input_binding(packages_raw,installed_show_raw,filelists,ownership,resolutions,cache_paths,
  context_sha256=proof['contextSha256'],signature_sha256=proof['signatureProofSha256'],install_sha256=proof['installProofSha256'])
 need(proof==expected,'inventory.input_binding')
 signed=parse_packages(indexes);installed=parse_show(installed_show_raw)
 need(runtime.REQUIRED_PACKAGES<=set(installed),'inventory.required_packages')
 need(type(filelists)is dict and set(filelists)=={r['binaryName'] for r in installed.values()},'inventory.list_roster')
 lists={name:parse_listfiles(filelists[row['binaryName']],binary_name=row['binaryName'])
        for name,row in installed.items()}
 # Debian's optional site hook is a packaged symlink into /etc/python3.11.
 # Every issued interpreter uses -I -S, so do not follow or copy this hook.
 need({name for name,paths in lists.items() if SITE_CUSTOMIZE in paths}=={'libpython3.11-minimal'},
      'inventory.site_hook_package')
 index_rows={};packages=[]
 for name,row in installed.items():
  key=(name,row['version'],row['architecture']);need(key in signed,'inventory.installed_version_unindexed')
  entry=signed[key];index_rows[name]=entry
  packages.append({'name':name,'version':row['version'],'architecture':row['architecture'],'debSha256':entry['sha256']})
 primary={p for rows in lists.values() for p in rows if p!=SITE_CUSTOMIZE and
          (p==runtime.PYTHON or p.startswith(runtime.STDLIB) and
           '__pycache__'not in p.split('/') and not p.endswith('.pyc'))}
 need(runtime.PYTHON in primary,'inventory.python_missing')
 metadata={};required=set(TOOL_PATHS)|{runtime.LOADER}
 for path in sorted(primary):
  info=_metadata(reader.stat_original(path),allow_directory=True)
  if info['type']=='regular':metadata[path]=info;required.add(path)
 elf_inputs={p for p in metadata if p==runtime.PYTHON or p.endswith('.so')}
 need(type(resolutions)is dict and set(resolutions)==elf_inputs,'inventory.resolution_roster')
 dependency_paths=set()
 for path,raw in resolutions.items():dependency_paths.update(runtime.parse_ldd(raw,allow_no_dependencies=path!=runtime.PYTHON))
 required.update(dependency_paths)
 need(type(ownership)is dict and set(ownership)==required,'inventory.ownership_roster')
 files=[];evidence=[];total=0
 for path in sorted(required):
  raw_owner=ownership[path]
  need(type(raw_owner)is bytes and len(raw_owner)<=8192,'inventory.owner_cap')
  try:owner_lines=raw_owner.decode('utf-8','strict').splitlines()
  except UnicodeError:raise runtime.Refusal('inventory.owner_encoding') from None
  need(len(owner_lines)==1 and ': 'in owner_lines[0],'inventory.owner_shape')
  binary,owned=owner_lines[0].split(': ',1)
  candidates=[name for name,row in installed.items() if binary==row['binaryName'] or ':'not in row['binaryName'] and binary==name]
  recorded=owner_lookup_path(path,lists,dependency_paths)
  need(len(candidates)==1 and owned==recorded,'inventory.owner_identity');name=candidates[0]
  need(recorded in lists[name],'inventory.owner_filelist')
  data,info=_read_checked(reader,path,FILE_CAP,metadata.get(path))
  if recorded!=path:
   recorded_data,recorded_info=_read_checked(reader,recorded,FILE_CAP)
   identity=('sourcePath','dev','ino','size','uid','gid','mode','nlink','mtimeNs','ctimeNs')
   need(info['sourcePath'].startswith('/usr/lib/x86_64-linux-gnu/') and
        all(info[k]==recorded_info[k] for k in identity) and data==recorded_data and
        _metadata(reader.stat_original(path))==info and
        _metadata(reader.stat_original(recorded))==recorded_info,
        'inventory.owner_alias_identity')
  total+=len(data);need(total<=MAX_READ_BYTES and len(files)<MAX_FILES,'inventory.total_file_cap')
  files.append({'path':path,'package':name,'version':installed[name]['version'],'sha256':sha(data),'bytes':len(data)})
  evidence.append({'path':path,'sourcePath':info['sourcePath'],'dev':info['dev'],'ino':info['ino'],
   'bytes':len(data),'sha256':sha(data),'aliasProofSha256':info['aliasProofSha256'],'restatMatched':True})
 need(type(cache_paths)is dict and set(cache_paths)<=set(installed),'inventory.cache_roster')
 archives=[]
 for name,entry in sorted(index_rows.items()):
  cached=cache_paths.get(name);observed=None
  if cached is not None:
   need(type(cached)is str and cached.startswith('/var/cache/apt/archives/') and cached.endswith('.deb')
        and posixpath.normpath(cached)==cached and len(cached)<=1024,'inventory.cache_path')
   data,info=_read_checked(reader,cached,128*1024*1024)
   need(info['sourcePath']==cached and len(data)==entry['bytes'] and sha(data)==entry['sha256'],'inventory.cached_deb_changed')
   observed=sha(data)
  archives.append({'package':name,'version':installed[name]['version'],'filename':entry['filename'],
   'expectedBytes':entry['bytes'],'expectedSha256':entry['sha256'],'indexSha256':entry['indexSha256'],
   'cachedPath':cached,'observedSha256':observed,'archiveBytesRehashed':observed is not None,
   'hashSource':'signed-index-and-cache-rehash' if observed is not None else 'signed-index-expectation'})
 manifest={'schema':'ocv-authenticated-installed-files-v1','sourceProofSha256':sha(canonical(proof)),
           'packages':sorted(packages,key=lambda r:r['name']),'files':files}
 return manifest,{'schema':'ocv-installed-file-inventory-evidence-v1','inputBinding':dict(proof),
   'installedManifestSha256':sha(canonical(manifest)),'archives':archives,'files':evidence,'readBytes':total,
   'authenticationPerformedHere':False,'nativeCommandsExecutedHere':False}


def main(_argv=None):
 need(ARMED is True,'inventory.disarmed')
 raise runtime.Refusal('inventory.checked_build_owner_required')


if __name__=='__main__':main()

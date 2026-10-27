"""Inert public Linux helper/runtime preparation; no native action on import.

Tests exercise byte fixtures only. Compilation/native imports must later occur
inside the authenticated Debian root with the reviewed CI controller; this
module never substitutes ambient Mac libraries or implements a package solver.
"""
import hashlib
import json
import posixpath
import re
import struct

ARMED=False
ELF_MAX=8*1024*1024
RUNTIME_MAX=256*1024*1024
FILE_MAX=32*1024*1024
SOURCE='/opt/ocv/source/native/static_entry.c'
OUTPUT='/opt/ocv/control/static-entry'
FLAGS=('-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pie','-fno-unwind-tables',
 '-fno-asynchronous-unwind-tables','-fno-ident','-fcf-protection=none','-mno-red-zone',
 '-nostdlib','-nostartfiles','-nodefaultlibs','-static','-no-pie','-Wl,-e,_start,--build-id=none,-z,noexecstack')
REQUIRED_PACKAGES={'python3.11-minimal','libpython3.11-minimal','libpython3.11-stdlib','libc6'}
PYTHON='/usr/bin/python3.11'
LOADER='/lib64/ld-linux-x86-64.so.2'
STDLIB='/usr/lib/python3.11/'


class Refusal(RuntimeError):
 def __init__(self,code):super().__init__(code);self.code=code


def need(value,code):
 if not value:raise Refusal(code)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def hexsha(value):return type(value)is str and re.fullmatch('[0-9a-f]{64}',value) is not None


def compile_argv(source=SOURCE,output=OUTPUT):
 need(source==SOURCE and output==OUTPUT,'runtime.compile_path')
 return ['/usr/bin/gcc-12',*FLAGS,'-x','c',source,'-o',output]


def validate_static_elf(raw):
 """Independent ELF64 parser; does not run readelf, loader or binary."""
 need(type(raw)is bytes and 64<=len(raw)<=ELF_MAX,'elf.size')
 hdr=struct.unpack_from('<16sHHIQQQIHHHHHH',raw)
 ident,etype,machine,version,entry,phoff,shoff,flags,ehsize,phsize,phnum,shsize,shnum,shstr=hdr
 need(ident[:7]==b'\x7fELF\x02\x01\x01' and ident[7]in(0,3) and ident[8:]==b'\0'*8,
      'elf.identity')
 need(etype==2 and machine==62 and version==1 and flags==0 and entry>0,'elf.target')
 need(ehsize==64 and phsize==56 and 1<=phnum<=32 and shsize==64 and 2<=shnum<=1024
      and 0<shstr<shnum,'elf.tables')
 def region(offset,size):
  need(type(offset)is int and type(size)is int and 0<=offset<=len(raw) and 0<=size<=len(raw)-offset,'elf.bounds')
  return raw[offset:offset+size]
 need(phoff>=64 and shoff>=64,'elf.tables');region(phoff,phnum*56);region(shoff,shnum*64)
 need(phoff+phnum*56<=shoff or shoff+shnum*64<=phoff,'elf.table_overlap')
 loads=[];stack=[];other=[]
 for index in range(phnum):
  typ,pflags,offset,vaddr,paddr,filesz,memsz,align=struct.unpack_from('<IIQQQQQQ',raw,phoff+index*56)
  need(typ not in(2,3),'elf.dynamic_or_interp')
  need(typ in(0,1,4,6,0x6474e551,0x6474e552,0x6474e553),'elf.program_type')
  need(pflags&~7==0 and not(pflags&2 and pflags&1),'elf.writable_executable')
  region(offset,filesz)
  need(memsz>=filesz and vaddr<1<<63 and memsz<(1<<63)-vaddr,'elf.segment_size')
  need(align in(0,1) or align<=2097152 and align&(align-1)==0,'elf.alignment')
  if align>1:need(offset%align==vaddr%align,'elf.alignment')
  if typ==1:
   need(memsz>0 and pflags&4,'elf.load_segment');loads.append((vaddr,vaddr+memsz,pflags,offset,filesz))
  elif typ==0x6474e551:
   need(pflags==6 and filesz==memsz==0,'elf.executable_stack');stack.append(index)
  else:other.append(typ)
 need(loads and len(stack)==1,'elf.load_or_stack_missing')
 ordered=sorted(loads)
 need(all(ordered[i][1]<=ordered[i+1][0] for i in range(len(ordered)-1)),'elf.load_overlap')
 need(sum(start<=entry<end and pflags&1 for start,end,pflags,_,_ in loads)==1,'elf.entry_mapping')
 sections=[struct.unpack_from('<IIQQQQIIQQ',raw,shoff+i*64) for i in range(shnum)]
 need(sections[0]==(0,)*10,'elf.null_section')
 strings=sections[shstr];need(strings[1]==3,'elf.section_names');names_raw=region(strings[4],strings[5])
 def string(table,offset):
  need(0<=offset<len(table),'elf.string_bounds');end=table.find(b'\0',offset)
  need(end>=offset and end-offset<=1024,'elf.string_bounds')
  try:return table[offset:end].decode('ascii')
  except UnicodeError:raise Refusal('elf.string_ascii') from None
 names=[];symbols=[];symtabs=0
 forbidden={'.init','.fini','.ctors','.dtors','.init_array','.fini_array','.preinit_array','.dynamic','.interp'}
 for i,row in enumerate(sections):
  name,typ,sflags,addr,offset,size,link,info,align,entsize=row
  names.append(string(names_raw,name));need(names[-1]not in forbidden and typ not in(6,11,14,15,16),'elf.dynamic_or_constructors')
  need(not(sflags&1 and sflags&4),'elf.writable_executable_section')
  if typ!=8:region(offset,size)
  if typ in(4,9):need(size==0,'elf.relocations')
  if sflags&2 and size:
   covering=[l for l in loads if l[0]<=addr and addr+size<=l[1]]
   need(len(covering)==1 and (not sflags&1 or covering[0][2]&2) and (not sflags&4 or covering[0][2]&1),'elf.section_mapping')
   if typ!=8:need(offset==covering[0][3]+addr-covering[0][0] and offset+size<=covering[0][3]+covering[0][4],'elf.section_mapping')
  if typ==2:
   symtabs+=1;need(entsize==24 and size%24==0 and 0<link<shnum and sections[link][1]==3,'elf.symbol_table')
   symraw=region(offset,size);strraw=region(sections[link][4],sections[link][5])
   for index in range(size//24):
    sn,si,so,ndx,value,ssize=struct.unpack_from('<IBBHQQ',symraw,index*24)
    if index==0:need((sn,si,so,ndx,value,ssize)==(0,)*6,'elf.null_symbol');continue
    need(ndx!=0,'elf.undefined_symbol');need(ndx<shnum or ndx==0xfff1,'elf.symbol_section')
    need((si&15)in(0,1,2,3,4),'elf.symbol_type')
    if (si&15)==2:
     need(ndx<shnum and sections[ndx][2]&4 and sections[ndx][3]<=value
          and ssize<=sections[ndx][3]+sections[ndx][5]-value,'elf.function_bounds')
    symbols.append((string(strraw,sn),si,ndx,value,ssize))
 need(symtabs==1,'elf.symbol_table_missing')
 start=[r for r in symbols if r[0]=='_start'];main=[r for r in symbols if r[0]=='entry_main']
 need(len(start)==1 and start[0][1]&15==2 and start[0][3]==entry and start[0][4]>0
      and start[0][2]<shnum and sections[start[0][2]][2]&4,'elf.entry_symbol')
 need(len(main)==1 and main[0][1]&15==2 and main[0][2]<shnum and sections[main[0][2]][2]&4,'elf.main_symbol')
 return {'schema':'ocv-static-entry-elf-v1','bytes':len(raw),'sha256':sha(raw),'architecture':'linux-amd64',
  'elfClass':64,'elfType':'ET_EXEC','entryAddress':entry,'loadSegments':len(loads),'sectionCount':shnum,
  'symbolCount':len(symbols),'interpreterPresent':False,'dynamicPresent':False,'undefinedSymbols':0,
  'constructorsPresent':False,'writableExecutablePresent':False,'executableStack':False,
  'nativeExecutionVerified':False,'syscallSemanticsVerified':False}


def build_helper(source_raw,source_sha256,toolchain,ops):
 """Future authenticated guest call; injected checked native ops only; no default executor."""
 need(type(source_raw)is bytes and len(source_raw)<=32768 and hexsha(source_sha256)
      and sha(source_raw)==source_sha256,'runtime.source')
 need(type(toolchain)is dict and set(toolchain)=={'schema','architecture','packageProofSha256','tools'}
      and toolchain['schema']=='ocv-toolchain-v1' and toolchain['architecture']=='linux-amd64'
      and hexsha(toolchain['packageProofSha256']),'runtime.toolchain')
 tools=toolchain['tools']
 required_tools={'compiler':'/usr/bin/gcc-12','cc1':'/usr/lib/gcc/x86_64-linux-gnu/12/cc1',
  'collect2':'/usr/lib/gcc/x86_64-linux-gnu/12/collect2','assembler':'/usr/bin/as','linker':'/usr/bin/ld'}
 need(type(tools)is list and len(tools)==len(required_tools)
      and all(type(r)is dict for r in tools) and {r.get('role') for r in tools}==set(required_tools), 'runtime.toolchain')
 for row in tools:
  need(set(row)=={'role','path','bytes','sha256','package','version','debSha256'} and hexsha(row['sha256'])
       and hexsha(row['debSha256']) and row['package'] and row['version'] and row['path']==required_tools[row['role']],'runtime.toolchain')
  data=ops.read(row['path'],64*1024*1024);need(len(data)==row['bytes'] and sha(data)==row['sha256'],'runtime.tool_changed')
 need(ops.facts()=={'platform':'linux','machine':'x86_64','euid':0},'runtime.guest_target')
 need(ops.read(SOURCE,32768)==source_raw,'runtime.source_changed')
 command=compile_argv();result=ops.run(command,{'PATH':'/usr/bin:/bin','HOME':'/','LANG':'C','LC_ALL':'C'},120)
 need(type(result)is dict and set(result)=={'returncode','timedOut','stdout','stderr'}
      and result['returncode']==0 and result['timedOut'] is False
      and all(type(result[k])is bytes and len(result[k])<=65536 for k in('stdout','stderr')),'runtime.compile_refused')
 raw=ops.read(OUTPUT,ELF_MAX);proof=validate_static_elf(raw)
 return {'path':'code/static-entry','sourceSha256':source_sha256,'command':command,
  'toolchainSha256':sha(canonical(toolchain)),'bytes':len(raw),'sha256':sha(raw),'elf':proof}


def parse_ldd(raw, *, allow_no_dependencies=False):
 """Parse bounded output of signed guest /usr/bin/ldd; never invoke it here."""
 need(type(raw)is bytes and len(raw)<=65536,'runtime.ldd_cap')
 if allow_no_dependencies is True and raw.strip()==b'statically linked':return []
 need(type(allow_no_dependencies)is bool,'runtime.ldd_policy')
 try:lines=raw.decode('ascii').splitlines()
 except UnicodeError:raise Refusal('runtime.ldd_ascii') from None
 paths=[]
 for line in lines:
  row=line.strip()
  if not row:continue
  if re.fullmatch(r'linux-vdso\.so\.1 \(0x[0-9a-f]+\)',row):continue
  match=re.fullmatch(r'(?:[A-Za-z0-9_.+-]+ => )?(/[^\s]+) \(0x[0-9a-f]+\)',row)
  need(match is not None,'runtime.ldd_unresolved');path=match[1]
  need(path.startswith(('/lib/','/lib64/','/usr/lib/','/usr/lib64/')) and '..'not in path.split('/'),'runtime.ldd_path')
  paths.append(path)
 need(paths and len(paths)<=64 and len(set(paths))==len(paths),'runtime.ldd_empty_or_duplicate')
 return sorted(paths)


def collect_runtime(installed,resolutions,reader,helper):
 """Collect package-owned bytes from authenticated guest metadata only.

    installed is issued by the normal signed-package bootstrap after install;
    package proof authentication belongs to that source-pinned bootstrap.
    resolutions are exact standard ldd outputs for Python/all packaged stdlib
    extension files. No dependency graph or ambient-library fallback exists.
    Reader.read_original(path,cap) must return a closed regular-file view plus
    the checked package/merged-/usr symlink-chain projection, never private data.
 """
 need(type(installed)is dict and set(installed)=={'schema','sourceProofSha256','packages','files'}
      and installed['schema']=='ocv-authenticated-installed-files-v1' and hexsha(installed['sourceProofSha256']),
      'runtime.installed_manifest')
 packages=installed['packages'];files=installed['files']
 need(type(packages)is list and 4<=len(packages)<=512 and type(files)is list and len(files)<=30000,'runtime.inventory_cap')
 by_package={};by_path={}
 for row in packages:
  need(set(row)=={'name','version','architecture','debSha256'} and type(row['name'])is str
       and re.fullmatch('[a-z0-9][a-z0-9+.-]{0,80}',row['name']) and row['architecture']in('amd64','all')
       and type(row['version'])is str and 0<len(row['version'])<=128 and hexsha(row['debSha256'])
       and row['name']not in by_package,'runtime.package_identity')
  by_package[row['name']]=row
 need(REQUIRED_PACKAGES<=set(by_package),'runtime.required_packages')
 for row in files:
  need(type(row)is dict and set(row)=={'path','package','version','sha256','bytes'} and row['package']in by_package
       and row['version']==by_package[row['package']]['version'] and type(row['path'])is str
       and row['path'].startswith('/') and posixpath.normpath(row['path'])==row['path']
       and '..'not in row['path'].split('/') and row['path']not in by_path and hexsha(row['sha256'])
       and type(row['bytes'])is int and 0<=row['bytes']<=FILE_MAX,'runtime.installed_file')
  by_path[row['path']]=row
 primary={p for p,r in by_path.items() if p==PYTHON or p.startswith(STDLIB) and '/__pycache__/'not in p and not p.endswith('.pyc')}
 need(PYTHON in primary and STDLIB+'encodings/__init__.py'in primary and STDLIB+'os.py'in primary,'runtime.python_prefix')
 need(all(by_path[p]['package']in('python3.11-minimal','libpython3.11-minimal','libpython3.11-stdlib') for p in primary),
      'runtime.python_owner')
 elf_inputs={p for p in primary if p==PYTHON or p.endswith('.so')}
 need(type(resolutions)is dict and set(resolutions)==elf_inputs,'runtime.resolution_roster')
 required=set(primary)|{LOADER}
 for path,out in resolutions.items():required.update(parse_ldd(out,allow_no_dependencies=path!=PYTHON))
 need(required<=set(by_path),'runtime.unowned_dependency')
 result=[];ownership=[];total=0
 for path in sorted(required):
  row=by_path[path];view=reader.read_original(path,FILE_MAX)
  need(type(view)is dict and set(view)=={'bytes','sourcePath','uid','gid','mode','regular','symlinkChainSha256'}
       and type(view['bytes'])is bytes and view['regular'] is True and view['uid']==view['gid']==0
       and type(view['mode'])is int and view['mode']&0o022==0 and hexsha(view['symlinkChainSha256'])
       and type(view['sourcePath'])is str and view['sourcePath'].startswith(('/usr/','/lib/','/lib64/'))
       and posixpath.normpath(view['sourcePath'])==view['sourcePath'],'runtime.source_identity')
  data=view['bytes'];need(len(data)==row['bytes'] and sha(data)==row['sha256'],'runtime.installed_bytes_changed')
  total+=len(data);need(total<=RUNTIME_MAX and len(result)<20000,'runtime.runtime_cap')
  # Materialize checked aliases as new regular copied bytes at original paths;
  # no hardlink or broad /usr,/lib bind is ever part of this manifest.
  result.append({'path':path.lstrip('/'),'sourcePath':view['sourcePath'],'bytes':len(data),'sha256':sha(data),
                 'mode':0o555 if path in(PYTHON,LOADER) else 0o444})
  ownership.append({'path':path.lstrip('/'),'package':row['package'],'version':row['version'],
                    'packageFileSha256':row['sha256'],'symlinkChainSha256':view['symlinkChainSha256']})
 need(type(helper)is dict and helper.get('path')=='code/static-entry' and hexsha(helper.get('sha256'))
      and type(helper.get('bytes'))is int and helper['bytes']>0,'runtime.helper_manifest')
 return {'schema':'ocv-runtime-v1','architecture':'linux-amd64','files':result,'helper':helper,
         'packageOwnership':ownership,'packages':packages,'sourceProofSha256':installed['sourceProofSha256'],
         'standardResolutionSha256':sha(canonical({k:sha(v) for k,v in resolutions.items()})),
         'runtimeBytes':total,'nativeImportsVerified':False,'maintainedConsumerCompatibilityVerified':False}


def main(_argv=None):
 need(ARMED is True,'runtime.disarmed')
 raise Refusal('runtime.reviewed_build_binding_required')


if __name__=='__main__':main()

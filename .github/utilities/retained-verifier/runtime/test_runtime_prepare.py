"""Synthetic ELF/file/process fixtures. No compiler or executable runs."""
import copy
import struct
import unittest
from unittest import mock
import runtime_prepare as m


def elf_fixture():
 raw=bytearray(0x1240)
 hdr=(b'\x7fELF\x02\x01\x01'+b'\0'*9,2,62,1,0x401000,64,0x1100,0,64,56,2,64,5,4)
 struct.pack_into('<16sHHIQQQIHHHHHH',raw,0,*hdr)
 struct.pack_into('<IIQQQQQQ',raw,64,1,5,0,0x400000,0x400000,0x1020,0x1020,4096)
 struct.pack_into('<IIQQQQQQ',raw,120,0x6474e551,6,0,0,0,0,0,16)
 raw[0x1000:0x1020]=b'\x90'*32
 symbols=b'\0_start\0entry_main\0';names=b'\0.text\0.symtab\0.strtab\0.shstrtab\0'
 raw[0x1088:0x1088+len(symbols)]=symbols;raw[0x10a0:0x10a0+len(names)]=names
 struct.pack_into('<IBBHQQ',raw,0x1040+24,1,0x12,2,1,0x401000,8)
 struct.pack_into('<IBBHQQ',raw,0x1040+48,8,0x12,2,1,0x401008,16)
 rows=[(0,)*10,(1,1,6,0x401000,0x1000,32,0,0,16,0),
       (7,2,0,0,0x1040,72,3,1,8,24),(15,3,0,0,0x1088,len(symbols),0,0,1,0),
       (23,3,0,0,0x10a0,len(names),0,0,1,0)]
 for i,row in enumerate(rows):struct.pack_into('<IIQQQQIIQQ',raw,0x1100+i*64,*row)
 return bytes(raw)


class ELF(unittest.TestCase):
 def test_positive_static_structure_not_native_syscall_execution(self):
  result=m.validate_static_elf(elf_fixture());self.assertEqual(result['elfType'],'ET_EXEC')
  self.assertFalse(result['nativeExecutionVerified']);self.assertFalse(result['syscallSemanticsVerified'])
  self.assertEqual(result['sha256'],m.sha(elf_fixture()));self.assertEqual(result['undefinedSymbols'],0)
 def refuse_mutation(self,offset,fmt,value,code=None):
  raw=bytearray(elf_fixture());struct.pack_into(fmt,raw,offset,value)
  with self.assertRaises(m.Refusal) as error:m.validate_static_elf(bytes(raw))
  if code:self.assertEqual(error.exception.code,code)
 def test_wrong_class_endian_machine_type_or_version_refuse(self):
  for offset,fmt,value in ((4,'B',1),(5,'B',2),(16,'H',3),(18,'H',3),(20,'I',2)):
   with self.subTest(offset=offset):self.refuse_mutation(offset,fmt,value)
 def test_interpreter_dynamic_unknown_program_headers_refuse(self):
  for typ in(2,3,0x12345):
   with self.subTest(typ=typ):self.refuse_mutation(120,'I',typ)
 def test_wx_or_executable_stack_missing_stack_refuse(self):
  self.refuse_mutation(68,'I',7,'elf.writable_executable')
  self.refuse_mutation(124,'I',7)
  self.refuse_mutation(120,'I',0,'elf.load_or_stack_missing')
 def test_undefined_import_even_weak_and_dynamic_symbol_table_refuse(self):
  self.refuse_mutation(0x1040+24+6,'H',0,'elf.undefined_symbol')
  self.refuse_mutation(0x1100+2*64+4,'I',11,'elf.dynamic_or_constructors')
  raw=bytearray(elf_fixture());struct.pack_into('B',raw,0x1040+24+4,0x22);struct.pack_into('<H',raw,0x1040+24+6,0)
  with self.assertRaisesRegex(m.Refusal,'elf.undefined_symbol'):m.validate_static_elf(bytes(raw))
 def test_init_fini_arrays_named_constructors_relocation_refuse(self):
  for typ in(6,14,15,16,4,9):
   with self.subTest(typ=typ):self.refuse_mutation(0x1100+2*64+4,'I',typ)
  raw=bytearray(elf_fixture());raw[0x10a0+1:0x10a0+6]=b'.init'
  with self.assertRaisesRegex(m.Refusal,'elf.dynamic_or_constructors'):m.validate_static_elf(bytes(raw))
 def test_entry_missing_or_wrong_start_and_no_symbol_proof_refuse(self):
  self.refuse_mutation(24,'Q',0x800000,'elf.entry_mapping')
  self.refuse_mutation(0x1040+24+8,'Q',0x401001,'elf.entry_symbol')
  self.refuse_mutation(0x1100+2*64+4,'I',1,'elf.symbol_table_missing')
 def test_table_segment_string_bounds_and_wrong_alignment_refuse(self):
  for offset,fmt,value in ((32,'Q',len(elf_fixture())),(40,'Q',len(elf_fixture())),
       (64+32,'Q',1<<63),(64+48,'Q',3),(0x1100+4*64+24,'Q',len(elf_fixture()))):
   with self.subTest(offset=offset):self.refuse_mutation(offset,fmt,value)
  for raw in(b'',b'x'*64,elf_fixture()[:100]):
   with self.subTest(size=len(raw)),self.assertRaises(m.Refusal):m.validate_static_elf(raw)
 def test_section_writable_executable_or_unmapped_refuse(self):
  self.refuse_mutation(0x1100+64+8,'Q',7,'elf.writable_executable_section')
  self.refuse_mutation(0x1100+64+16,'Q',0x900000,'elf.section_mapping')

 def test_ifunc_tls_or_out_of_bounds_function_symbols_refuse(self):
  self.refuse_mutation(0x1040+48+4,'B',0x1a,'elf.symbol_type')
  self.refuse_mutation(0x1040+48+4,'B',0x16,'elf.symbol_type')
  self.refuse_mutation(0x1040+48+16,'Q',0xffff,'elf.function_bounds')


class Build(unittest.TestCase):
 def setUp(self):
  self.source=b'/* public synthetic compiler input, never compiled */'
  required={'compiler':'/usr/bin/gcc-12','cc1':'/usr/lib/gcc/x86_64-linux-gnu/12/cc1',
   'collect2':'/usr/lib/gcc/x86_64-linux-gnu/12/collect2','assembler':'/usr/bin/as','linker':'/usr/bin/ld'}
  self.tools={'schema':'ocv-toolchain-v1','architecture':'linux-amd64','packageProofSha256':'f'*64,'tools':[]}
  self.files={m.SOURCE:self.source,m.OUTPUT:elf_fixture()}
  for role,path in required.items():
   data=('synthetic '+role).encode();self.files[path]=data
   self.tools['tools'].append({'role':role,'path':path,'bytes':len(data),'sha256':m.sha(data),
                              'package':'synthetic-tool','version':'fixture-1','debSha256':'e'*64})
  class Ops:
   def __init__(ops,outer):ops.outer=outer;ops.calls=[];ops.result={'returncode':0,'timedOut':False,'stdout':b'','stderr':b''}
   def read(ops,path,cap):return ops.outer.files[path]
   def facts(ops):return {'platform':'linux','machine':'x86_64','euid':0}
   def run(ops,*args):ops.calls.append(args);return ops.result
  self.ops=Ops(self)
 def build(self):return m.build_helper(self.source,m.sha(self.source),self.tools,self.ops)
 def test_exact_nonexecuted_compile_command_and_elf_bound(self):
  result=self.build();self.assertEqual(len(self.ops.calls),1)
  argv,env,timeout=self.ops.calls[0];self.assertEqual(argv,m.compile_argv())
  self.assertEqual(argv[0],'/usr/bin/gcc-12');self.assertIn('-nostdlib',argv);self.assertIn('-no-pie',argv)
  self.assertEqual(env,{'PATH':'/usr/bin:/bin','HOME':'/','LANG':'C','LC_ALL':'C'});self.assertEqual(timeout,120)
  self.assertEqual(result['path'],'code/static-entry');self.assertEqual(result['sha256'],m.sha(elf_fixture()))
 def test_wrong_tool_bytes_path_or_missing_frontend_refuse_before_compile(self):
  for mutator in (lambda:self.files.update({'/usr/bin/gcc-12':b'changed'}),
                  lambda:self.tools['tools'][0].update(path='/unverified/gcc'),lambda:self.tools['tools'].pop()):
   self.setUp();mutator()
   with self.assertRaises(m.Refusal):self.build()
   self.assertEqual(self.ops.calls,[])
 def test_timeout_or_nonzero_complete_elf_never_passes(self):
  for result in ({'returncode':1,'timedOut':False,'stdout':b'','stderr':b''},
                 {'returncode':0,'timedOut':True,'stdout':b'','stderr':b''}):
   self.setUp();self.ops.result=result
   with self.assertRaisesRegex(m.Refusal,'runtime.compile_refused'):self.build()
 def test_elf_refusal_after_compile_not_retried(self):
  self.files[m.OUTPUT]=b'not an ELF'
  with self.assertRaises(m.Refusal):self.build()
  self.assertEqual(len(self.ops.calls),1)
 def test_main_disarmed(self):
  with self.assertRaisesRegex(m.Refusal,'runtime.disarmed'):m.main([])
  self.assertFalse(m.ARMED)


class Runtime(unittest.TestCase):
 def setUp(self):
  self.installed={'schema':'ocv-authenticated-installed-files-v1','sourceProofSha256':'d'*64,'packages':[], 'files':[]}
  for name in sorted(m.REQUIRED_PACKAGES):
   self.installed['packages'].append({'name':name,'version':'synthetic-fixture-1','architecture':'amd64','debSha256':'e'*64})
  self.data={m.PYTHON:b'synthetic Python ELF',m.STDLIB+'encodings/__init__.py':b'# synthetic encoding',
             m.STDLIB+'os.py':b'# synthetic os',m.STDLIB+'lib-dynload/_struct.cpython-311-x86_64-linux-gnu.so':b'synthetic extension',
             m.LOADER:b'synthetic loader','/lib/x86_64-linux-gnu/libc.so.6':b'synthetic libc'}
  for path,data in self.data.items():
   owner='python3.11-minimal' if path==m.PYTHON else 'libpython3.11-stdlib' if path.startswith(m.STDLIB) else 'libc6'
   self.installed['files'].append({'path':path,'package':owner,'version':'synthetic-fixture-1','sha256':m.sha(data),'bytes':len(data)})
  ldd=b'linux-vdso.so.1 (0x0000ffff)\nlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00001000)\n/lib64/ld-linux-x86-64.so.2 (0x00002000)\n'
  self.resolutions={p:ldd for p in self.data if p==m.PYTHON or p.endswith('.so')}
  class Reader:
   def __init__(reader,outer):reader.outer=outer;reader.calls=[];reader.override={}
   def read_original(reader,path,cap):
    reader.calls.append(path);return {'bytes':reader.outer.data[path],'sourcePath':path,'uid':0,'gid':0,'mode':0o755,
                                     'regular':True,'symlinkChainSha256':'c'*64,**reader.override}
  self.reader=Reader(self);self.helper={'path':'code/static-entry','bytes':len(elf_fixture()),'sha256':m.sha(elf_fixture())}
 def collect(self):return m.collect_runtime(self.installed,self.resolutions,self.reader,self.helper)
 def test_exact_runtime_original_paths_owned_hashes_no_native_claim(self):
  result=self.collect();self.assertEqual(result['schema'],'ocv-runtime-v1')
  self.assertEqual({r['path'] for r in result['files']},{p.lstrip('/') for p in self.data})
  self.assertEqual(result['runtimeBytes'],sum(map(len,self.data.values())))
  self.assertFalse(result['nativeImportsVerified']);self.assertFalse(result['maintainedConsumerCompatibilityVerified'])
  self.assertTrue(all(r['mode']in(0o444,0o555) for r in result['files']))
 def test_missing_required_package_prefix_or_resolution_refuse(self):
  for fn in (lambda:self.installed['packages'].pop(),lambda:self.installed['files'].pop(0),lambda:self.resolutions.pop(m.PYTHON)):
   self.setUp();fn()
   with self.assertRaises(m.Refusal):self.collect()
 def test_std_ldd_not_found_static_ambient_and_duplicate_paths_refuse(self):
  for raw in (b'libx.so => not found\n',b'statically linked\n',b'/tmp/ambient.so (0x1234)\n',
              b'/lib64/ld-linux-x86-64.so.2 (0x1234)\n/lib64/ld-linux-x86-64.so.2 (0x1234)\n'):
   with self.subTest(raw=raw),self.assertRaises(m.Refusal):m.parse_ldd(raw)
 def test_unowned_dependency_and_changed_payload_refuse(self):
  self.resolutions[m.PYTHON]+=b'libevil.so => /lib/libevil.so (0x1234)\n'
  with self.assertRaisesRegex(m.Refusal,'runtime.unowned_dependency'):self.collect()
  self.setUp();self.data[m.PYTHON]=b'changed'
  with self.assertRaisesRegex(m.Refusal,'runtime.installed_bytes_changed'):self.collect()
 def test_root_ownership_regular_mode_chain_and_canonical_source_refuse(self):
  for override in ({'uid':501},{'mode':0o777},{'regular':False},{'sourcePath':'/tmp/ambient'},
                   {'sourcePath':'/usr/lib/../bin/python3.11'},{'symlinkChainSha256':'unknown'}):
   self.setUp();self.reader.override=override
   with self.subTest(override=override),self.assertRaises(m.Refusal):self.collect()
 def test_pycache_not_copied_and_foreign_python_prefix_owner_refused(self):
  path=m.STDLIB+'__pycache__/os.pyc';self.installed['files'].append({'path':path,'package':'libpython3.11-stdlib',
   'version':'synthetic-fixture-1','sha256':'a'*64,'bytes':10})
  self.assertNotIn(path,self.reader.calls);self.assertNotIn(path.lstrip('/'),{r['path'] for r in self.collect()['files']})
  self.setUp();self.installed['files'][0]['package']='libc6'
  with self.assertRaisesRegex(m.Refusal,'runtime.python_owner'):self.collect()
 def test_duplicate_file_inventory_or_package_version_refuse(self):
  self.installed['files'].append(copy.deepcopy(self.installed['files'][0]))
  with self.assertRaises(m.Refusal):self.collect()
  self.setUp();self.installed['files'][0]['version']='other'
  with self.assertRaises(m.Refusal):self.collect()

 def test_packaged_extension_only_can_have_no_external_ldd_dependencies(self):
  extension=next(path for path in self.resolutions if path!=m.PYTHON)
  self.resolutions[extension]=b'\tstatically linked\n'
  self.assertEqual(self.collect()['schema'],'ocv-runtime-v1')
  self.resolutions[m.PYTHON]=b'statically linked\n'
  with self.assertRaisesRegex(m.Refusal,'runtime.ldd_unresolved'):self.collect()


if __name__=='__main__':unittest.main()

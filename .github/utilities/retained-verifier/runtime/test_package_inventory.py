"""Synthetic package metadata/bytes only; no native package/tool calls."""
import copy
import unittest
import package_inventory as m
import runtime_prepare as runtime


class Inventory(unittest.TestCase):
 def setUp(self):
  self.names=sorted(runtime.REQUIRED_PACKAGES|{'gcc-12','binutils'})
  self.versions={name:'1.0~synthetic-fixture' for name in self.names}
  self.binaries={name:name+(':amd64' if name=='libc6' else '') for name in self.names}
  self.archive={name:('synthetic deb '+name).encode() for name in self.names}
  self.index=''.join('Package: '+n+'\nVersion: '+self.versions[n]+'\nArchitecture: amd64\nFilename: pool/main/f/fixture/'+n+'_fixture_amd64.deb\n'
   +'Size: '+str(len(self.archive[n]))+'\nSHA256: '+m.sha(self.archive[n])+'\nDescription: public synthetic fixture\n continuation\n\n' for n in self.names).encode()
  self.show=''.join(self.binaries[n]+'\t'+self.versions[n]+'\tamd64\tinstalled\n' for n in self.names).encode()
  self.data={runtime.PYTHON:b'synthetic python',runtime.STDLIB+'encodings/__init__.py':b'# synthetic encoding',
   runtime.STDLIB+'os.py':b'# synthetic os',runtime.STDLIB+'lib-dynload/test.so':b'synthetic extension',
   runtime.LOADER:b'synthetic loader','/lib/x86_64-linux-gnu/libc.so.6':b'synthetic libc'}
  self.data.update({path:('synthetic tool '+path).encode() for path in m.TOOL_PATHS})
  self.owners={p:'gcc-12' if p in m.TOOL_PATHS else 'python3.11-minimal' if p==runtime.PYTHON else
    'libpython3.11-stdlib' if p.startswith(runtime.STDLIB) else 'libc6' for p in self.data}
  self.filelists={self.binaries[n]:('\n'.join(['/.','/usr']+sorted(p for p,o in self.owners.items() if o==n))+'\n').encode() for n in self.names}
  self.filelists['libpython3.11-minimal']+=m.SITE_CUSTOMIZE.encode()+b'\n'
  # Directory rows are part of normal dpkg listfiles, never hashed as files.
  self.filelists['libpython3.11-stdlib']+=runtime.STDLIB.rstrip('/').encode()+b'\n'
  self.ownership={p:(self.binaries[n]+': '+p+'\n').encode() for p,n in self.owners.items()}
  ldd=b'linux-vdso.so.1 (0x1000)\nlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x2000)\n/lib64/ld-linux-x86-64.so.2 (0x3000)\n'
  self.resolutions={runtime.PYTHON:ldd,runtime.STDLIB+'lib-dynload/test.so':ldd}
  self.cache={}
  class Reader:
   def __init__(reader,outer):reader.outer=outer;reader.calls=[];reader.metadata_override={};reader.after_override={};reader.counts={};reader.view_override={}
   def stat_original(reader,path):
    reader.calls.append(('stat',path));reader.counts[path]=reader.counts.get(path,0)+1
    data=reader.outer.data.get(path,b'')
    info={'sourcePath':path,'type':'directory' if path==runtime.STDLIB.rstrip('/') else 'regular','dev':1,'ino':100,
      'size':len(data),'uid':0,'gid':0,'mode':0o755,'nlink':1,'mtimeNs':100,'ctimeNs':100,'aliasProofSha256':'c'*64,
      **reader.metadata_override}
    if reader.counts[path]>1:info.update(reader.after_override)
    return info
   def read_original(reader,path,cap):
    reader.calls.append(('read',path));info=reader.stat_original(path)
    return {'bytes':reader.outer.data[path],'sourcePath':info['sourcePath'],'uid':info['uid'],'gid':info['gid'],
     'mode':info['mode'],'regular':True,'symlinkChainSha256':info['aliasProofSha256'],**reader.view_override}
  self.reader=Reader(self);self.bind()
 def bind(self):
  self.proof=m.input_binding(self.index,self.show,self.filelists,self.ownership,self.resolutions,self.cache,
   context_sha256='a'*64,signature_sha256='b'*64,install_sha256='c'*64)
 def build(self):return m.build_inventory(self.index,self.show,self.filelists,self.ownership,self.resolutions,self.reader,self.proof,self.cache)
 def refused(self,code=None):
  with self.assertRaises(runtime.Refusal) as error:self.build()
  if code:self.assertEqual(error.exception.code,code)
  return error.exception
 def test_positive_exact_runtime_collector_input_and_hash_expectations_not_rehash(self):
  manifest,evidence=self.build()
  self.assertEqual(manifest['schema'],'ocv-authenticated-installed-files-v1')
  self.assertEqual({r['path'] for r in manifest['files']},set(self.data))
  self.assertTrue(all(r['sha256']==m.sha(self.data[r['path']]) for r in manifest['files']))
  self.assertTrue(all(r['hashSource']=='signed-index-expectation' and r['observedSha256']is None and not r['archiveBytesRehashed'] for r in evidence['archives']))
  self.assertFalse(evidence['authenticationPerformedHere']);self.assertFalse(evidence['nativeCommandsExecutedHere'])
  helper={'path':'code/static-entry','bytes':10,'sha256':'d'*64}
  result=runtime.collect_runtime(manifest,self.resolutions,self.reader,helper)
  self.assertEqual(result['schema'],'ocv-runtime-v1')
  self.assertNotIn('usr/bin/gcc-12',{r['path'] for r in result['files']})
 def test_index_and_all_raw_command_outputs_are_joined_before_file_reads(self):
  for part in ('index','show'):
   self.setUp();setattr(self,part,getattr(self,part)+b'changed')
   self.refused();self.assertEqual(self.reader.calls,[])
  self.setUp();self.ownership[runtime.PYTHON]+=b'changed';self.refused('inventory.input_binding');self.assertEqual(self.reader.calls,[])
 def test_passed_json_or_missing_signature_install_context_hash_not_authority(self):
  self.proof={'passed':True};self.refused('inventory.proof_schema')
  for key in ('signatureProofSha256','installProofSha256','contextSha256'):
   self.setUp();self.proof[key]=None;self.refused('inventory.proof_hash')
 def test_missing_changed_package_version_arch_or_state_refuse(self):
  for old,new in ((b'\tinstalled\n',b'\tunpacked\n'),(b'1.0~synthetic-fixture',b'2.0~synthetic-fixture'),
                  (b'\tamd64\t',b'\tarm64\t')):
   self.setUp();self.show=self.show.replace(old,new,1);self.bind();self.refused()
  self.setUp();self.show=b'\n'.join(line for line in self.show.splitlines() if not line.startswith(b'python3.11-minimal\t'))+b'\n'
  self.bind();self.refused('inventory.required_packages')
 def test_duplicate_index_fields_conflicting_index_tuple_or_bad_archive_path_refuse(self):
  for old,new in ((b'Package: binutils\n',b'Package: binutils\nPackage: binutils\n'),
                  (b'pool/main/f/fixture/',b'pool/../../escape/')):
   self.setUp();self.index=self.index.replace(old,new,1);self.bind();self.refused()
  self.setUp();other=self.index.replace(m.sha(self.archive['binutils']).encode(),b'0'*64,1)
  self.index={m.sha(self.index):self.index,m.sha(other):other};self.bind();self.refused('inventory.index_conflict')
 def test_unselected_large_package_metadata_does_not_disqualify_signed_index(self):
  self.index+=b'Package: public-large-data\nVersion: 1\nArchitecture: all\nFilename: pool/main/l/large.deb\nSize: 1000000000\nSHA256: '+b'f'*64+b'\n\n'
  self.bind();self.assertEqual(self.build()[0]['schema'],'ocv-authenticated-installed-files-v1')
 def test_multiple_signed_indexes_identical_tuple_deduplicates_without_solver(self):
  extra=self.index+b'\n';self.index={m.sha(self.index):self.index,m.sha(extra):extra};self.bind()
  manifest,evidence=self.build();self.assertEqual(len(manifest['packages']),len(self.names))
  self.assertEqual(len(evidence['archives'][0]['indexSha256']),2)
 def test_missing_ambiguous_or_diverted_ownership_and_filelist_refuse(self):
  self.ownership[runtime.PYTHON]=b'diversion by other: /usr/bin/python3.11\n';self.bind();self.refused('inventory.owner_identity')
  self.setUp();self.ownership[runtime.PYTHON]+=self.ownership[runtime.PYTHON];self.bind();self.refused('inventory.owner_shape')
  self.setUp();self.filelists['python3.11-minimal']=b'/usr/bin/other\n';self.bind();self.refused('inventory.python_missing')
 def test_only_exact_adjacent_bookworm_dash_diversion_annotation_is_ignored(self):
  raw=(b'/.\n/bin\n/bin/dash\n/bin/sh\npackage diverts others to: /bin/sh.distrib\n'
       b'/usr/share/man/man1/sh.1.gz\n'
       b'package diverts others to: /usr/share/man/man1/sh.distrib.1.gz\n')
  self.assertEqual(m.parse_listfiles(raw,binary_name='dash'),
                   {'/bin','/bin/dash','/bin/sh','/usr/share/man/man1/sh.1.gz'})
  for binary,changed,code in (
      ('other',raw,'inventory.filelist_diversion'),
      ('dash',raw.replace(b'/bin/sh\n',b'/bin/other\n'),'inventory.filelist_diversion'),
      ('dash',raw+b'package diverts others to: /bin/sh.distrib\n','inventory.filelist_diversion'),
      ('dash',raw.replace(b'/bin/sh.distrib',b'/tmp/unknown'),'inventory.filelist_path'),
      ('dash',raw.replace(b'/usr/share/man/man1/sh.1.gz\n',b'/usr/share/man/man1/other.1.gz\n'),
       'inventory.filelist_diversion'),
      ('dash',raw.replace(b'/usr/share/man/man1/sh.distrib.1.gz',b'/tmp/unknown.1.gz'),
       'inventory.filelist_path'),
      ('dash',raw.replace(b'package diverts others',b'locally diverted'),'inventory.filelist_path')):
   with self.subTest(binary=binary,changed=changed):
    with self.assertRaises(runtime.Refusal) as error:m.parse_listfiles(changed,binary_name=binary)
    self.assertEqual(error.exception.code,code)
 def test_optional_site_hook_is_not_followed_copied_or_reassigned(self):
  manifest,_=self.build()
  self.assertNotIn(m.SITE_CUSTOMIZE,{row['path'] for row in manifest['files']})
  self.assertFalse(any(m.SITE_CUSTOMIZE in row for row in self.reader.calls))
  self.setUp();self.filelists['libpython3.11-minimal']=self.filelists['libpython3.11-minimal'].replace(
   m.SITE_CUSTOMIZE.encode()+b'\n',b'');self.bind();self.refused('inventory.site_hook_package')
  self.setUp();self.filelists['binutils']+=m.SITE_CUSTOMIZE.encode()+b'\n';self.bind();self.refused('inventory.site_hook_package')
 def test_pycache_generated_bytes_not_read_and_required_tool_missing_refuses(self):
  self.filelists['libpython3.11-stdlib']+=runtime.STDLIB.encode()+b'__pycache__/unknown.pyc\n';self.bind();self.build()
  self.assertFalse(any('__pycache__'in row[1] for row in self.reader.calls))
  self.setUp();path=next(iter(m.TOOL_PATHS));del self.ownership[path];self.bind();self.refused('inventory.ownership_roster')
 def test_missing_unresolved_or_extra_ldd_output_refuses(self):
  self.resolutions.pop(runtime.PYTHON);self.bind();self.refused('inventory.resolution_roster')
  self.setUp();self.resolutions[runtime.PYTHON]=b'libmissing.so => not found\n';self.bind();self.refused('runtime.ldd_unresolved')
  self.setUp();self.resolutions['/tmp/ambient.so']=b'';self.bind();self.refused('inventory.resolution_roster')
 def test_source_uid_mode_alias_or_unstable_inode_refuse(self):
  for change in ({'uid':1},{'mode':0o777},{'aliasProofSha256':'unknown'},{'sourcePath':'/usr/../tmp/file'}):
   self.setUp();self.reader.metadata_override=change;self.refused('inventory.metadata_identity')
  for change in ({'ino':999},{'mtimeNs':999},{'size':999}):
   self.setUp();self.reader.after_override=change;self.refused('inventory.file_changed')
  self.setUp();self.reader.view_override={'symlinkChainSha256':'e'*64};self.refused('inventory.file_view')
 def test_existing_cache_deb_rehashed_only_when_actual_bytes_match_index(self):
  package='libc6';path='/var/cache/apt/archives/libc6_fixture_amd64.deb';self.cache={package:path};self.data[path]=self.archive[package];self.bind()
  _,evidence=self.build();row=next(r for r in evidence['archives'] if r['package']==package)
  self.assertTrue(row['archiveBytesRehashed']);self.assertEqual(row['observedSha256'],m.sha(self.archive[package]))
  self.assertEqual(row['hashSource'],'signed-index-and-cache-rehash')
  self.data[path]=b'changed cached archive';self.refused('inventory.cached_deb_changed')
 def test_cache_escape_or_canonical_alias_refuses(self):
  self.cache={'libc6':'/var/cache/apt/archives/../secret.deb'};self.bind();self.refused('inventory.cache_path')
 def test_disarmed_main_has_no_native_command_path(self):
  with self.assertRaisesRegex(runtime.Refusal,'inventory.disarmed'):m.main([])
  self.assertFalse(m.ARMED)


if __name__=='__main__':unittest.main()

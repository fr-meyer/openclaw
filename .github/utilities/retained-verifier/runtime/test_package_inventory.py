"""Synthetic package metadata/bytes only; no native package/tool calls."""
import copy
import unittest
import package_inventory as m
import runtime_prepare as runtime


class Inventory(unittest.TestCase):
 def setUp(self):
  self.names=sorted(runtime.REQUIRED_PACKAGES|{'gcc-12','binutils','libssl3'})
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
  self.cache={};self.aliases={}
  class Reader:
   def __init__(reader,outer):reader.outer=outer;reader.calls=[];reader.metadata_override={};reader.after_override={};reader.counts={};reader.view_override={}
   def stat_original(reader,path):
    reader.calls.append(('stat',path));reader.counts[path]=reader.counts.get(path,0)+1
    canonical=reader.outer.aliases.get(path,path)
    data=reader.outer.data.get(canonical,b'')
    info={'sourcePath':canonical,'type':'directory' if path==runtime.STDLIB.rstrip('/') else 'regular','dev':1,'ino':100,
      'size':len(data),'uid':0,'gid':0,'mode':0o755,'nlink':1,'mtimeNs':100,'ctimeNs':100,'aliasProofSha256':'c'*64,
      **reader.metadata_override}
    if reader.counts[path]>1:info.update(reader.after_override)
    return info
   def read_original(reader,path,cap):
    reader.calls.append(('read',path));info=reader.stat_original(path)
    return {'bytes':reader.outer.data[info['sourcePath']],'sourcePath':info['sourcePath'],'uid':info['uid'],'gid':info['gid'],
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
 def test_same_payload_filename_aliases_preserve_every_exact_index_path_join(self):
  main=self.index;other=main.replace(b'pool/main/f/fixture/',b'pool/updates/main/f/fixture/')
  expected={m.sha(raw):raw for raw in (main,other)}
  results=[]
  for raws in (expected,dict(reversed(list(expected.items())))):
   self.index=raws;self.bind();manifest,evidence=self.build();results.append((manifest,evidence))
   self.assertEqual(evidence['schema'],'ocv-installed-file-inventory-evidence-v2')
   for row in evidence['archives']:
    name=row['package'];self.assertNotIn('filename',row)
    self.assertEqual(row['indexSha256'],sorted(expected))
    self.assertEqual(row['filenameByIndexSha256'],{
     m.sha(main):'pool/main/f/fixture/'+name+'_fixture_amd64.deb',
     m.sha(other):'pool/updates/main/f/fixture/'+name+'_fixture_amd64.deb'})
    self.assertFalse(row['archiveBytesRehashed'])
  self.assertEqual(results[0],results[1])
 def test_same_payload_alias_with_actual_cached_bytes_keeps_both_signed_paths(self):
  main=self.index;other=main.replace(b'pool/main/f/fixture/',b'pool/updates/main/f/fixture/')
  path='/var/cache/apt/archives/libc6_fixture_amd64.deb'
  self.index={m.sha(main):main,m.sha(other):other};self.cache={'libc6':path};self.data[path]=self.archive['libc6'];self.bind()
  _,evidence=self.build();row=next(r for r in evidence['archives']if r['package']=='libc6')
  self.assertTrue(row['archiveBytesRehashed']);self.assertEqual(row['observedSha256'],m.sha(self.archive['libc6']))
  self.assertEqual(set(row['filenameByIndexSha256']),set(self.index))
  self.data[path]=b'wrong archive';self.refused('inventory.cached_deb_changed')
 def test_filename_alias_never_allows_size_or_sha_conflict_even_if_unselected(self):
  original=self.index
  for selected in (True,False):
   for field in ('Size','SHA256'):
    self.setUp();main=original
    if not selected:
     main+=b'Package: unselected-fixture\nVersion: 1\nArchitecture: all\nFilename: pool/main/f/fixture/unused.deb\nSize: 1\nSHA256: '+b'f'*64+b'\n\n'
    records=main.split(b'\n\n');position=0 if selected else len(records)-2
    row=records[position];line=next(v for v in row.splitlines()if v.startswith(field.encode()+b': '))
    replacement=b'Size: 999'if field=='Size'else b'SHA256: '+b'0'*64
    records[position]=row.replace(line,replacement)
    other=b'\n\n'.join(records).replace(b'pool/main/f/fixture/',b'pool/updates/main/f/fixture/')
    self.index={m.sha(main):main,m.sha(other):other};self.bind()
    self.refused('inventory.index_conflict');self.assertEqual(self.reader.calls,[])
 def test_one_index_duplicate_identity_and_forged_index_digest_refuse(self):
  first=self.index.split(b'\n\n')[0]+b'\n\n'
  for extra in (first,first.replace(b'pool/main/f/fixture/',b'pool/updates/main/f/fixture/')):
   self.setUp();self.index+=extra;self.bind();self.refused('inventory.index_duplicate_identity')
   self.assertEqual(self.reader.calls,[])
  with self.assertRaisesRegex(runtime.Refusal,'inventory.index_hash'):
   m.parse_packages({'0'*64:first})
 def test_malformed_alias_path_or_duplicate_field_stays_fatal(self):
  main=self.index
  for old,new in ((b'pool/main/f/fixture/',b'pool/../escape/'),
                  (b'Architecture: amd64\n',b'Architecture: amd64\nArchitecture: amd64\n')):
   self.setUp();other=main.replace(old,new,1);self.index={m.sha(main):main,m.sha(other):other};self.bind()
   self.refused('inventory.index_archive'if old.startswith(b'pool/')else'inventory.index_duplicate')
   self.assertEqual(self.reader.calls,[])
 def test_missing_ambiguous_or_diverted_ownership_and_filelist_refuse(self):
  self.ownership[runtime.PYTHON]=b'diversion by other: /usr/bin/python3.11\n';self.bind();self.refused('inventory.owner_identity')
  self.setUp();self.ownership[runtime.PYTHON]+=self.ownership[runtime.PYTHON];self.bind();self.refused('inventory.owner_shape')
  self.setUp();self.filelists['python3.11-minimal']=b'/usr/bin/other\n';self.bind();self.refused('inventory.python_missing')
 def test_authenticated_merged_usr_ldd_alias_requires_same_package_bytes(self):
  path='/lib/x86_64-linux-gnu/libcrypto.so.3';recorded='/usr'+path
  self.data[recorded]=b'public synthetic packaged crypto library'
  self.aliases[path]=recorded
  self.filelists['libssl3']+=recorded.encode()+b'\n'
  self.ownership[path]=('libssl3: '+recorded+'\n').encode()
  self.resolutions[runtime.PYTHON]+=('libcrypto.so.3 => '+path+' (0x4000)\n').encode()
  self.bind();manifest,evidence=self.build()
  row=next(r for r in manifest['files'] if r['path']==path)
  self.assertEqual((row['package'],row['sha256']),('libssl3',m.sha(self.data[recorded])))
  self.assertEqual(next(r for r in evidence['files'] if r['path']==path)['sourcePath'],recorded)
  self.ownership[path]=('libc6:amd64: '+recorded+'\n').encode();self.bind();self.refused('inventory.owner_filelist')
  self.ownership[path]=('libssl3: '+recorded+'\n').encode()
  self.data[recorded]=b'changed';self.aliases[path]='/lib/x86_64-linux-gnu/other.so'
  self.data[self.aliases[path]]=b'changed';self.bind();self.refused('inventory.owner_alias_identity')
 def test_owner_alias_selection_refuses_unlisted_or_unrelated_path(self):
  path='/lib/x86_64-linux-gnu/libcrypto.so.3';recorded='/usr'+path
  lists={'libssl3':{recorded},'libc6':{'/lib64/ld-linux-x86-64.so.2'}}
  self.assertEqual(m.owner_lookup_path(path,lists,{path}),recorded)
  self.assertEqual(m.owner_lookup_path(path,lists,set()),path)
  self.assertEqual(m.owner_lookup_path(path,{'libssl3':{recorded},'other':{recorded}},{path}),path)
  self.assertEqual(m.owner_lookup_path(path,{'libssl3':{recorded,'/lib/x86_64-linux-gnu/libcrypto.so.3'}},{path}),path)
  self.assertEqual(m.owner_lookup_path('/lib/x86_64-linux-gnu/../libcrypto.so.3',lists,{path}),
                   '/lib/x86_64-linux-gnu/../libcrypto.so.3')
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

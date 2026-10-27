"""Checked public CI guest inputs. Pure verification accepts injected readers;
only the separate native entry can issue authority from actual native facts.
"""
from dataclasses import dataclass
import datetime as dt
import hashlib,json,re
from pathlib import PurePosixPath

SOURCE='/opt/ocv/source'
CONTROL='/opt/ocv/control'
BUILD_KEYS={'schema','sourceManifestSha256','runtimeManifestSha256','toolManifestSha256','importManifestSha256',
 'aptMetadataManifestSha256','helperSha256','kernelVersion','systemdVersion','fixtureOnly','candidateImage','runIdentity'}
RUN_KEYS={'repository','workflowRef','sourceCommit','runId','runAttempt'}
MAX_SOURCE=1024*1024
_PLAN_SEAL=object()


class Refusal(RuntimeError):
 def __init__(self,code,facts=None):super().__init__(code);self.code=code;self.facts=facts or {}


def need(ok,code,facts=None):
 if not ok:raise Refusal(code,facts)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
def hex64(value):return type(value)is str and re.fullmatch('[0-9a-f]{64}',value) is not None

def decode(raw,cap):
 need(type(raw)is bytes and 0<len(raw)<=cap,'boot.json_size')
 def pairs(rows):
  out={}
  for key,value in rows:need(key not in out,'boot.duplicate_key');out[key]=value
  return out
 try:return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'boot.nonfinite'))
 except (ValueError,UnicodeError):raise Refusal('boot.json_encoding') from None

def closed(value,keys,code):need(type(value)is dict and set(value)==set(keys),code);return value

def file_bytes(io,path,cap,*,readonly=True):
 record=io.file(path,cap)
 closed(record,{'raw','uid','gid','mode','regular','canonicalPath'},'boot.file_contract')
 need(record['regular'] is True and record['uid']==record['gid']==0 and record['canonicalPath']==path and
  type(record['mode'])is int and not record['mode']&0o022 and (not readonly or record['mode']==0o444),'boot.file_identity',{'path':path})
 need(type(record['raw'])is bytes and len(record['raw'])<=cap,'boot.file_cap')
 return record['raw']

def marker_values(raw):
 need(type(raw)is bytes and len(raw)<=8192,'boot.cmdline_cap')
 try:tokens=raw.decode('ascii').strip().split()
 except UnicodeError:raise Refusal('boot.cmdline_encoding') from None
 found={}
 for token in tokens:
  if token.startswith('ocv.'):
   need(token.count('=')==1,'boot.marker_shape');key,value=token.split('=')
   need(key in ('ocv.source','ocv.build','ocv.session') and key not in found,'boot.marker_duplicate')
   found[key]=value
 need(set(found)=={'ocv.source','ocv.build','ocv.session'} and hex64(found['ocv.source']) and hex64(found['ocv.build']) and
  re.fullmatch('[0-9a-f]{32}',found['ocv.session']),'boot.marker_missing')
 return found


@dataclass(frozen=True)
class Plan:
 markers:dict
 build:dict
 source:dict
 controls:dict
 control_hashes:dict
 boot_id:str
 prepared_at:dt.datetime
 facts:dict
 native_authority:bool=False
 _seal:object=None
 _verified_io:object=None


def verify(io):
 facts=io.facts()
 closed(facts,{'platform','machine','euid','egid','pid','kernelVersion','rootFreeBytes','availableMemoryBytes','swapTotalBytes'},'boot.facts')
 need(facts['platform']=='linux' and facts['machine']=='x86_64' and facts['euid']==facts['egid']==0 and
  type(facts['pid'])is int and facts['pid']>1,'boot.target')
 need(facts['rootFreeBytes']>=2*1024**3 and facts['availableMemoryBytes']>=3*1024**3 and facts['swapTotalBytes']==0,'boot.resources')
 markers=marker_values(io.read('/proc/cmdline',8192))
 for name in ('mnt','user'):
  need(io.readlink('/proc/self/ns/'+name)==io.readlink('/proc/1/ns/'+name),'boot.manager_namespace')
 need(io.read('/proc/1/comm',64).strip()==b'systemd','boot.pid1')
 interfaces=[line.split(':',1)[0].strip() for line in io.read('/proc/net/dev',16384).decode().splitlines()if ':'in line]
 need(interfaces==['lo'],'boot.external_interface')
 boot=io.read('/proc/sys/kernel/random/boot_id',128).decode().strip()
 need(re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot),'boot.boot_id')
 source_raw=file_bytes(io,SOURCE+'/PUBLIC-SOURCE-MANIFEST.json',MAX_SOURCE)
 need(sha(source_raw)==markers['ocv.source'],'boot.source_manifest_pin')
 source=decode(source_raw,MAX_SOURCE);closed(source,{'schema','files'},'boot.source_schema')
 need(source['schema']=='ocv-public-source-v1' and type(source['files'])is list and 1<=len(source['files'])<=256,'boot.source_files')
 seen=set();total=0
 for row in source['files']:
  closed(row,{'path','bytes','sha256','mode'},'boot.source_row');relative=row['path'];p=PurePosixPath(relative)
  need(type(relative)is str and not p.is_absolute() and str(p)==relative and '..'not in p.parts and relative not in seen and
   row['mode']==0o444 and type(row['bytes'])is int and 0<=row['bytes']<=262144 and hex64(row['sha256']),'boot.source_path')
  raw=file_bytes(io,SOURCE+'/'+relative,262144);need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'boot.source_changed',{'path':relative})
  seen.add(relative);total+=len(raw);need(total<=4*1024*1024,'boot.source_total')
 need({'bootstrap/guest_boot.py','bootstrap/guard.py','bootstrap/issuer.py','bootstrap/worker_entry.py','bootstrap/native_io.py','bootstrap/result_frame.py','bootstrap/serial_io.py',
       'native/ci_native_port.py','native/ci_entry.py','native/ci_worker.py','native/ci_profile.py','native/CI-PROFILE.json',
       'native/ci_metadata.py','native/ci_fixture.py','native/ci_protocol.py','native/ci_probe.py','native/ci_anchors.py',
       'native/ci_custody.py','native/ci_adapter.py','native/ci_archive_policy.py','native/static_entry.c','runtime/runtime_prepare.py',
       'consumer/consumer_compat.py','consumer/native_cases.py','consumer/hosted_export.py','consumer/hosted_privacy.py',
       'consumer/public-member-comparisons-v105-workboard.json'}<=seen,'boot.source_incomplete')
 io.check_source_roster(seen|{'PUBLIC-SOURCE-MANIFEST.json'})
 build_raw=file_bytes(io,CONTROL+'/build.json',1048576);need(sha(build_raw)==markers['ocv.build'],'boot.build_pin')
 build=closed(decode(build_raw,1048576),BUILD_KEYS,'boot.build_schema')
 need(build['schema']=='ocv-build-v1' and build['sourceManifestSha256']==markers['ocv.source'] and build['fixtureOnly'] is True and
  build['candidateImage'] is False and build['systemdVersion']=='252.39-1~deb12u2' and build['kernelVersion']==facts['kernelVersion'],'boot.build_target')
 run=closed(build['runIdentity'],RUN_KEYS,'boot.run_identity')
 need(all(type(run[k])is str and 0<len(run[k])<=512 for k in RUN_KEYS) and re.fullmatch('[0-9a-f]{40}',run['sourceCommit']) and
  re.fullmatch('[1-9][0-9]*',run['runId']) and re.fullmatch('[1-9][0-9]*',run['runAttempt']),'boot.run_identity')
 # Source/build equality establishes only own synthetic guest identity, never
 # cryptographic authenticity without the host's attested build/source proof.
 io.own_guest_checkpoint(markers,build,boot)
 controls={};hashes={}
 for name,key in (('runtime','runtimeManifestSha256'),('tools','toolManifestSha256'),('imports','importManifestSha256'),('apt','aptMetadataManifestSha256')):
  raw=file_bytes(io,CONTROL+'/'+name+'.json',8*1024*1024);need(hex64(build[key]) and sha(raw)==build[key],'boot.control_pin',{'role':name})
  controls[name]=decode(raw,8*1024*1024);hashes[name]=sha(raw)
 now=io.utc();need(type(now)is dt.datetime and now.tzinfo is not None and now.utcoffset()==dt.timedelta(0),'boot.time')
 return Plan(markers,build,source,controls,hashes,boot,now,facts,False,_PLAN_SEAL,io)


def validate_runtime(io,plan):
 runtime=plan.controls['runtime']
 required={'schema','architecture','files','helper','packageOwnership','packages','sourceProofSha256','standardResolutionSha256',
           'runtimeBytes','nativeImportsVerified','maintainedConsumerCompatibilityVerified'}
 closed(runtime,required,'boot.runtime_schema')
 need(runtime['schema']=='ocv-runtime-v1' and runtime['architecture']=='linux-amd64' and
  type(runtime['files'])is list and 1<=len(runtime['files'])<=20000 and hex64(runtime['sourceProofSha256']),'boot.runtime_target')
 total=0;seen=set();aliases={}
 for row in runtime['files']:
  closed(row,{'path','sourcePath','bytes','sha256','mode'},'boot.runtime_row')
  p=PurePosixPath(row['path']);source=row['sourcePath']
  need(not p.is_absolute() and str(p)==row['path'] and '..'not in p.parts and row['path']not in seen and
   type(source)is str and source.startswith(('/usr/','/lib/','/lib64/')) and row['mode']in(0o444,0o555),'boot.runtime_path')
  raw=file_bytes(io,source,32*1024*1024,readonly=False)
  need(type(row['bytes'])is int and len(raw)==row['bytes'] and sha(raw)==row['sha256'],'boot.runtime_changed')
  total+=len(raw);need(total<=256*1024*1024,'boot.runtime_total');seen.add(row['path']);aliases['/seed/'+row['path']]=dict(row)
 need({'usr/bin/python3.11','lib64/ld-linux-x86-64.so.2','usr/lib/python3.11/encodings/__init__.py','usr/lib/python3.11/os.py'}<=seen,'boot.python_runtime')
 need(runtime['runtimeBytes']==total,'boot.runtime_total')
 helper=runtime['helper'];need(type(helper)is dict and helper.get('path')=='code/static-entry' and
  helper.get('sha256')==plan.build['helperSha256'] and type(helper.get('bytes'))is int,'boot.helper')
 raw=file_bytes(io,CONTROL+'/static-entry',8*1024*1024,readonly=False)
 need(len(raw)==helper['bytes'] and sha(raw)==helper['sha256'],'boot.helper_changed')
 aliases['/seed/code/static-entry']={'path':'code/static-entry','sourcePath':CONTROL+'/static-entry','bytes':len(raw),
                                  'sha256':sha(raw),'mode':0o555}
 tools=closed(plan.controls['tools'],{'schema','tools'},'boot.tool_schema')
 need(tools['schema']=='ocv-tools-v1' and type(tools['tools'])is list and 8<=len(tools['tools'])<=32,'boot.tools')
 found={}
 for row in tools['tools']:
  closed(row,{'role','path','bytes','sha256','package','version','debSha256'},'boot.tool_row')
  need(row['role']not in found and row['path'].startswith(('/usr/','/lib/')) and hex64(row['debSha256']),'boot.tool_path')
  raw=file_bytes(io,row['path'],64*1024*1024,readonly=False)
  need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'boot.tool_changed')
  found[row['role']]=row
 need({'python','systemd','gpgv','busctl','systemctl','systemd-run','selinuxenabled','dpkg-query'}<=set(found),'boot.tools_incomplete')
 fixed={'python':'/usr/bin/python3.11','systemd':'/usr/lib/systemd/systemd','gpgv':'/usr/bin/gpgv','busctl':'/usr/bin/busctl',
  'systemctl':'/usr/bin/systemctl','systemd-run':'/usr/bin/systemd-run','selinuxenabled':'/usr/sbin/selinuxenabled','dpkg-query':'/usr/bin/dpkg-query'}
 need(all(found[role]['path']==path for role,path in fixed.items()),'boot.tool_fixed_path')
 return aliases,found

"""Copied-controller startup origin proof. Pure builders; explicit CI issuer.

The fixed child never spawns another process. It reports bounded compressed raw
startup/maps/module facts; the caller independently checks the same closed
runtime roster. This does not issue private VM or bootstrap authority.
"""
from __future__ import annotations

import base64
from io import BytesIO
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import zlib
import math

from protocol import Refusal, canonical, decode, read_regular, require, sha

RAW_CAP=128*1024
WIRE_CAP=16384
FAILURE_FACTS_CAP=31*1024
MODULES=('encodings','json','hashlib','os','sys','struct','zlib','ssl','socket',
         'selectors','subprocess','tarfile','ctypes','fcntl','stat','time',
         'datetime','threading','ipaddress','decimal','base64','ast','types',
         'pathlib','resource','shutil','inspect','collections','math')
PSEUDO=frozenset(('[heap]','[stack]','[vvar]','[vvar_vclock]','[vdso]','[vsyscall]'))
_SCRIPT=r'''
import base64,hashlib,importlib,json,os,sys,zlib
ROOT=__ROOT__
for name in __MODULES__:importlib.import_module(name)
def read_proc_complete(path,cap):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  chunks=[];total=0
  for _ in range(cap+2):
   wanted=min(4096,cap+1-total)
   block=os.read(fd,wanted)
   if type(block) is not bytes or len(block)>wanted:raise RuntimeError('copied.proc_read_type')
   if not block:return b''.join(chunks)
   total+=len(block)
   if total>cap:raise RuntimeError('copied.proc_cap')
   chunks.append(block)
  raise RuntimeError('copied.proc_no_eof')
 finally:os.close(fd)
def read_maps_complete():
 data=read_proc_complete('/proc/self/maps',65536)
 if not data or not data.endswith(b'\n'):raise RuntimeError('copied.maps_malformed')
 return data
children=read_proc_complete('/proc/self/task/'+str(os.getpid())+'/children',4096)
if children.strip():raise RuntimeError('copied.children_present')
data=read_maps_complete()
origins={}
for name,module in sorted(sys.modules.items()):
 path=getattr(module,'__file__',None)
 if path is not None:
  if not isinstance(path,str):raise RuntimeError('copied.origin_type')
  origins[name]=path
facts={'schema':'ocv.copied-controller-startup.v1','root':ROOT,
 'prefix':sys.prefix,'basePrefix':sys.base_prefix,
 'execPrefix':sys.exec_prefix,'baseExecPrefix':sys.base_exec_prefix,
 'executable':sys.executable,'path':sys.path,'origins':origins,
 'maps':data.decode('ascii'),'flags':{'isolated':sys.flags.isolated,
 'noSite':sys.flags.no_site,'ignoreEnvironment':sys.flags.ignore_environment,
 'dontWriteBytecode':sys.dont_write_bytecode},'version':list(sys.version_info[:3]),
 'childrenSpawned':bool(children.strip())}
raw=json.dumps(facts,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
if len(raw)>131072:raise RuntimeError('copied.raw_cap')
wire=json.dumps({'schema':'ocv.copied-controller-envelope.v1','rawBytes':len(raw),
 'rawSha256':hashlib.sha256(raw).hexdigest(),
 'zlibBase64':base64.b64encode(zlib.compress(raw,9)).decode('ascii')},
 sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
if len(wire)>16384:raise RuntimeError('copied.wire_cap')
sys.stdout.buffer.write(wire);sys.stdout.buffer.flush()
'''


def _root(root):
    require(type(root) is str and root.startswith('/') and
            re.fullmatch('/[A-Za-z0-9_./-]{1,240}',root) and
            str(PurePosixPath(root))==root and
            not set(PurePosixPath(root).parts)&{'.','..'},'copied.root')
    return root


def _rows(rows):
    # Representation only: the sealed origin still supplies the exact roster.
    # 8192/100MiB are the existing upstream runtime envelope, not authority.
    require(type(rows) is list and 0<len(rows)<=8192,'copied.runtime_count')
    result={}
    for row in rows:
        require(type(row) is dict and {'path','bytes','sha256','mode'}<=set(row) and
                set(row)<={'path','archivePath','bytes','sha256','mode'} and
                type(row['path']) is str and not row['path'].startswith('/') and
                str(PurePosixPath(row['path']))==row['path'] and
                not set(PurePosixPath(row['path']).parts)&{'.','..'} and
                re.fullmatch('[A-Za-z0-9_./+-]+',row['path']) and
                row['path'] not in result and type(row['bytes']) is int and
                0<=row['bytes']<=32*1024*1024 and
                type(row['mode']) is int and row['mode'] in (0o444,0o555) and
                type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),
                'copied.runtime_row')
        result[row['path']]=dict(row)
    require({'usr/bin/python3.11','lib64/ld-linux-x86-64.so.2','code/static-entry'}<=set(result) and
            sum(r['bytes'] for r in result.values())<=100*1024*1024,
            'copied.runtime_closure')
    return result


def probe_script(root,rows):
    _root(root);_rows(rows)
    return _SCRIPT.replace('__ROOT__',repr(root)).replace('__MODULES__',repr(MODULES)).encode('ascii')


def build_argv(root,script):
    root=_root(root)
    require(type(script) is bytes and 0<len(script)<=32768 and script.isascii(),
            'copied.script_cap')
    return (root+'/lib64/ld-linux-x86-64.so.2','--inhibit-cache',
            '--library-path',root+'/lib/x86_64-linux-gnu:'+root+'/lib64',
            '--argv0',root+'/usr/bin/python3.11',root+'/usr/bin/python3.11',
            '-I','-S','-B','-c',script.decode('ascii'))


def capture_failure_evidence(result,root,script,rows,owned_commands,placement=None,*,capture_origin='genuine-command-capture'):
    """Bounded synthetic-child custody, constructed before any adjudication."""
    root=_root(root);_rows(rows)
    require(type(result) is dict and type(owned_commands) is int and 0<=owned_commands<=1,
            'copied.failure_result')
    controls={'exitCode','timedOut','spawned','spawnOutcome','captureComplete','streamsEOF',
        'streamsClosed','ownedChildExited','ownershipRetained','refusalCode','failurePhase','operationId','errors'}
    require(controls|{'stdout','stderr','stdoutFacts','stderrFacts'}<=set(result) and
        set(result)<=controls|{'stdout','stderr','stdoutFacts','stderrFacts','childPid'},
        'copied.failure_result_schema')
    require(result['exitCode'] is None or type(result['exitCode']) is int,'copied.failure_exit')
    for name in ('timedOut','spawned','captureComplete','streamsEOF','streamsClosed',
                 'ownedChildExited','ownershipRetained'):
        require(type(result[name]) is bool,'copied.failure_control')
    require(type(result['operationId']) is int and 0<result['operationId']<=1 and
        result['spawnOutcome'] in ('not_attempted','unknown','handle_returned'),
        'copied.failure_operation')
    for name in ('refusalCode','failurePhase'):
        require(result[name] is None or type(result[name]) is str and
                re.fullmatch('[A-Za-z0-9_.-]{1,96}',result[name]),'copied.failure_control')
    errors=result['errors']
    require(type(errors) is list and len(errors)<=16,'copied.failure_errors')
    for error in errors:
        require(type(error) is dict and set(error)=={'phase','type','errno'} and
            all(type(error[k]) is str and re.fullmatch('[A-Za-z0-9_.-]{1,48}',error[k])
                for k in ('phase','type')) and
            (error['errno'] is None or type(error['errno']) is int), 'copied.failure_error')
    evidence={'schema':'ocv.copied-controller-command-failure.v1','syntheticOnly':True,
        'privateInputs':False,'environmentIncluded':False,'root':root,
        'scriptSha256':sha(script),'argvSha256':sha(canonical(list(build_argv(root,script)))),
        'runtimeRosterSha256':sha(canonical(rows)),'ownedCommandsRemaining':owned_commands,
        'capture':{name:result[name] for name in sorted(controls)},'streams':{}}
    require(capture_origin in ('genuine-command-capture','placement-not-attempted'),
            'copied.failure_origin')
    evidence['captureOrigin']=capture_origin
    if placement is not None:
        require(type(placement) is dict and set(placement)<={'beforeStage','beforeSpawn'} and
            len(canonical(placement))<=2*8192+64,'copied.failure_placement_cap')
        evidence['placement']=placement
    if 'childPid' in result:
        require(result['childPid'] is None or type(result['childPid']) is int,
                'copied.failure_child_pid')
        evidence['capture']['childPid']=result['childPid']
    for name,cap in (('stdout',16384),('stderr',4096)):
        raw=result[name];facts=result[name+'Facts']
        require(type(raw) is bytes and len(raw)<=cap and type(facts) is dict and
            set(facts)=={'bytes','sha256','truncated','complete'} and
            type(facts['bytes']) is int and len(raw)<=facts['bytes']<=2**63-1 and
            type(facts['sha256']) is str and re.fullmatch('[0-9a-f]{64}',facts['sha256']) and
            type(facts['truncated']) is bool and type(facts['complete']) is bool,
            'copied.failure_stream')
        evidence['streams'][name]={'viewBase64':base64.b64encode(raw).decode('ascii'),
            'viewBytes':len(raw),'viewSha256':sha(raw),'viewTruncated':len(raw)!=facts['bytes'],
            'captureFacts':dict(facts)}
    # Extra placement metadata never expands capture/pass limits or the32KiB
    # failure budget. Shorten only the rendered stdout head/tail if necessary;
    # preserve its complete original source count/hash and all stderr bytes.
    raw=result['stdout'];limit=len(raw)
    while len(canonical(evidence))>FAILURE_FACTS_CAP and limit>0:
        limit=max(0,limit-1024);half=limit//2
        view=raw[:half]+raw[-(limit-half):] if limit else b''
        evidence['streams']['stdout'].update(viewBase64=base64.b64encode(view).decode('ascii'),
            viewBytes=len(view),viewSha256=sha(view),viewTruncated=len(view)!=result['stdoutFacts']['bytes'])
    require(len(canonical(evidence))<=FAILURE_FACTS_CAP,'copied.failure_facts_cap')
    return evidence


def not_attempted_capture(phase,error):
    require(phase in ('placement_prewrite','placement_stage','placement_prespawn'),
            'copied.not_attempted_phase')
    result={'exitCode':None,'timedOut':False,'spawned':False,'spawnOutcome':'not_attempted',
        'captureComplete':False,'streamsEOF':False,'streamsClosed':True,'ownedChildExited':False,
        'ownershipRetained':False,'refusalCode':'copied.placement_refused','failurePhase':phase,
        'operationId':1,'errors':[{'phase':phase,'type':type(error).__name__[:48],
            'errno':error.errno if isinstance(error,OSError) else None}],'stdout':b'','stderr':b''}
    for name in ('stdout','stderr'):
        result[name+'Facts']={'bytes':0,'sha256':sha(b''),'truncated':False,'complete':False}
    return result


def observe_location(parent,prepared,runtime_source,root,rows,*,final):
    """Actual readonly metadata, admitted by the same opaque genuine parent."""
    import ci_authority
    import copied_location
    import guest_storage
    require(type(runtime_source) is ci_authority.CIRuntimeSource,'copied.location_authority')
    runtime_source.require_parent(parent,prepared);parent.check()
    plan=runtime_source.inspect_materials(runtime_source.materials)
    require(rows==plan['files'],'copied.location_runtime_changed')
    session=sha(('integrated:'+parent.plan.markers['ocv.session']).encode('ascii'))[:32]
    require(root==copied_location.root_for(rows,session),'copied.location_scope')
    root_info=Path('/').lstat();ancestors=[]
    for name in copied_location.ancestor_paths(root):
        try:info=Path(name).lstat()
        except FileNotFoundError:break
        ancestors.append({'path':name,'device':info.st_dev,'inode':info.st_ino,
            'uid':info.st_uid,'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode),
            'directory':stat.S_ISDIR(info.st_mode),'symlink':stat.S_ISLNK(info.st_mode)})
    kernel=guest_storage.NativeStorageIO()
    raw=kernel._read_kernel(Path('/proc/self/mountinfo'),1048576)
    metadata={'schema':copied_location.META_SCHEMA,'metadataOnly':True,'executionObserved':False,
        'root':root,'bootId':parent.plan.boot_id,'rootDevice':root_info.st_dev,
        'rootMajorMinor':str(os.major(root_info.st_dev))+':'+str(os.minor(root_info.st_dev)),
        'ancestors':ancestors,'mountInfoSha256':sha(raw),
        'mounts':copied_location.covering_mounts(raw,root),
        'statvfsFlags':os.statvfs(ancestors[-1]['path']).f_flag,'executables':[]}
    if final:
        roster=_rows(rows)
        for name in copied_location.EXECUTABLES:
            path=Path(root)/name;info=path.lstat();row=roster[name]
            raw=read_regular(path,row['bytes'],expected_size=row['bytes'],expected_sha=row['sha256'])
            metadata['executables'].append({'path':name,'device':info.st_dev,'inode':info.st_ino,
                'uid':info.st_uid,'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode),
                'bytes':len(raw),'sha256':sha(raw),'links':info.st_nlink,
                'executeAccess':os.access(path,os.X_OK,effective_ids=True,follow_symlinks=False)})
    parent.check()
    return metadata


def check_probe_dispatch(check,now,deadline):
    check()
    instant=now()
    require(type(deadline) in (int,float) and type(instant) in (int,float) and
        math.isfinite(deadline) and math.isfinite(instant) and instant<deadline,
        'copied.dispatch_deadline')


def refuse_captured(code,evidence):
    # The checked guest graph resolves this import to the same genuine outer
    # bootstrap guard module. Its failure handler intentionally trusts only
    # that exact Refusal class when carrying structured diagnostic facts.
    import guard
    require(type(code) is str and re.fullmatch('copied[.][a-z0-9_.]{1,80}',code) and
            type(evidence) is dict and evidence.get('schema')==
                'ocv.copied-controller-command-failure.v1' and
            len(canonical(evidence))<=FAILURE_FACTS_CAP,'copied.failure_refusal')
    raise guard.Refusal(code,{'copiedChild':evidence})


def decode_result(raw):
    require(type(raw) is bytes and len(raw)<=WIRE_CAP,'copied.envelope_cap')
    value=decode(raw,WIRE_CAP)
    require(type(value) is dict and set(value)=={'schema','rawBytes','rawSha256','zlibBase64'} and
            value['schema']=='ocv.copied-controller-envelope.v1' and
            type(value['rawBytes']) is int and 0<value['rawBytes']<=RAW_CAP and
            type(value['rawSha256']) is str and re.fullmatch('[0-9a-f]{64}',value['rawSha256']) and
            type(value['zlibBase64']) is str,'copied.envelope_schema')
    try:compressed=base64.b64decode(value['zlibBase64'],validate=True)
    except (ValueError,TypeError):raise Refusal('copied.base64') from None
    inflater=zlib.decompressobj()
    try:body=inflater.decompress(compressed,RAW_CAP+1)
    except zlib.error:raise Refusal('copied.zlib') from None
    require(inflater.eof and not inflater.unused_data and not inflater.unconsumed_tail and
            len(body)==value['rawBytes']<=RAW_CAP and sha(body)==value['rawSha256'],
            'copied.compression_bounds')
    return decode(body,RAW_CAP),body


def validate_result(raw,root,rows):
    root=_root(root);roster=_rows(rows)
    value,body=decode_result(raw)
    keys={'schema','root','prefix','basePrefix','execPrefix','baseExecPrefix','executable',
          'path','origins','maps','flags','version','childrenSpawned'}
    require(type(value) is dict and set(value)==keys and value['schema']==
            'ocv.copied-controller-startup.v1' and value['root']==root and
            all(value[k]==root+'/usr' for k in
                ('prefix','basePrefix','execPrefix','baseExecPrefix')) and
            value['executable']==root+'/usr/bin/python3.11' and
            value['flags']=={'isolated':1,'noSite':1,'ignoreEnvironment':1,'dontWriteBytecode':True} and
            type(value['version']) is list and len(value['version'])==3 and
            value['version'][:2]==[3,11] and type(value['version'][2]) is int and
            value['childrenSpawned'] is False,'copied.startup_origin')
    require(type(value['path']) is list and 1<=len(value['path'])<=8 and
            all(type(v) is str and v.startswith(root+'/usr/lib/') and
                str(PurePosixPath(v))==v and '..' not in v.split('/') for v in value['path']) and
            root+'/usr/lib/python3.11' in value['path'] and
            root+'/usr/lib/python3.11/lib-dynload' in value['path'],
            'copied.host_search_path')
    origins=value['origins']
    require(type(origins) is dict and 1<=len(origins)<=512 and
            'encodings' in origins,'copied.module_roster')
    for name,path in origins.items():
        require(type(name) is str and type(path) is str and path.startswith(root+'/') and
                path[len(root)+1:] in roster,'copied.host_module_origin')
    require(type(value['maps']) is str and len(value['maps'].encode('ascii'))<=65536,
            'copied.maps_cap')
    mapped=set()
    for line in value['maps'].splitlines():
        fields=line.split(None,5)
        require(5<=len(fields)<=6,'copied.maps_shape')
        if len(fields)==5:continue
        path=fields[5]
        if path.startswith('['):require(path in PSEUDO,'copied.maps_pseudo');continue
        require(path.startswith(root+'/') and path[len(root)+1:] in roster,
                'copied.host_mapped_object')
        mapped.add(path[len(root)+1:])
    require({'usr/bin/python3.11','lib64/ld-linux-x86-64.so.2'}<=mapped,
            'copied.mapped_interpreter_loader')
    return {'schema':'ocv.copied-controller-proof.v1','status':'passed',
            'rawBytes':len(body),'rawSha256':sha(body),'root':root,
            'runtimeRosterSha256':sha(canonical(rows)),
            'mappedObjects':sorted(mapped),'moduleOrigins':len(origins),
            'hostFallbackObserved':False,'privateActivationAuthority':False}


def run_native_proof(parent,prepared,runtime_source):
    """Exactly one genuine CI-owned, fixed-child proof; never called on Mac."""
    import ci_authority
    ci_authority._parent(parent,prepared)
    import issuer
    import native_io
    require(type(parent) is issuer.NativeCapability and parent.seal is issuer._SEAL and
            type(prepared) is issuer.Prepared and prepared._seal is issuer._PREPARED_SEAL and
            type(parent.io) is native_io.NativeEvidenceIO and prepared.io is parent.io and
            prepared.plan is parent.plan,'copied.genuine_parent_required')
    runtime_source.require_parent(parent,prepared)
    parent.check();require(parent.expires-parent.io.monotonic()>1560,'copied.phase_reserve')
    require(not hasattr(parent.io,'_copied_probe_capture'),'copied.attempt_consumed')
    # Claim before any staging so a failed/uncertain partial copy is not reused.
    parent.io._copied_probe_capture=None
    materials=runtime_source.materials;plan=runtime_source.inspect_materials(materials)
    rows=plan['files'];roster=_rows(rows)
    archive=materials['archive']
    require(sha(archive)==plan['archiveSha256'],'copied.archive_pin')
    import copied_location
    session=sha(('integrated:'+parent.plan.markers['ocv.session']).encode('ascii'))[:32]
    root=Path(copied_location.root_for(rows,session));base=root.parent
    script=probe_script(str(root),rows);argv=build_argv(str(root),script)
    placement={};phase='placement_prewrite'
    try:
        placement['beforeStage']=observe_location(parent,prepared,runtime_source,str(root),rows,final=False)
        copied_location.validate(placement['beforeStage'],str(root),rows,parent.plan.boot_id,final=False)
        phase='placement_stage'
        root_device=placement['beforeStage']['rootDevice']
        for index,name in enumerate(copied_location.ancestor_paths(str(root))[3:],3):
            directory=Path(name)
            if index in (3,4):
                try:directory.mkdir(mode=0o700)
                except FileExistsError:pass
            else:directory.mkdir(mode=0o700)  # Session and root are O_EXCL.
            info=directory.lstat()
            require(stat.S_ISDIR(info.st_mode) and not directory.is_symlink() and
                info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700 and
                info.st_dev==root_device,'copied.location_created_directory')
        with tarfile.open(fileobj=BytesIO(archive),mode='r:gz') as source:
            seen=set();total=0
            for member in source:
                matches=[r for r in rows if r.get('archivePath',
                    'static-entry' if r['path']=='code/static-entry' else 'runtime/'+r['path'])==member.name]
                require(len(matches)==1,'copied.archive_roster')
                row=matches[0];name=row['path']
                require(name not in seen and member.isreg() and
                        set(member.pax_headers)<={'path'} and
                        member.pax_headers.get('path',member.name)==member.name and
                        member.size==row['bytes'] and member.mode==row['mode'],
                        'copied.archive_member')
                seen.add(name);handle=source.extractfile(member)
                require(handle is not None,'copied.archive_stream')
                raw=handle.read(row['bytes']+1);handle.close()
                require(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'copied.copied_pin')
                target=root/name
                target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                for directory in (target.parent,*target.parent.parents):
                    if directory==base:break
                    require(directory.is_dir() and not directory.is_symlink() and
                            directory.stat().st_uid==0 and directory.stat().st_dev==base.stat().st_dev,
                            'copied.destination_parent')
                    os.chmod(directory,0o700)
                fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,row['mode'])
                try:
                    os.fchmod(fd,row['mode']);view=memoryview(raw)
                    while view:
                        count=os.write(fd,view);require(count>0,'copied.write_progress');view=view[count:]
                    os.fsync(fd)
                finally:os.close(fd)
                total+=len(raw);require(total<=100*1024*1024,'copied.expanded_cap')
        require(seen==set(roster),'copied.incomplete_copy')
        for name,row in roster.items():
            read_regular(root/name,row['bytes'],expected_size=row['bytes'],expected_sha=row['sha256'])
        phase='placement_prespawn'
        placement['beforeSpawn']=observe_location(parent,prepared,runtime_source,str(root),rows,final=True)
        copied_location.validate_pair(placement,str(root),rows,parent.plan.boot_id)
    except BaseException as error:
        result=not_attempted_capture(phase,error)
        evidence=capture_failure_evidence(result,str(root),script,rows,0,placement,
            capture_origin='placement-not-attempted')
        code=error.code if isinstance(error,Refusal) else 'copied.location_io_refused'
        refuse_captured(code,evidence)
    program=parent.io.program
    class ProbeIO(program.native.NativeCommandIO):
        def __init__(self):self.used=False;self.deadline=None
        def now(self):
            instant=super().now()
            if self.deadline is None:self.deadline=instant+30
            return instant
        def spawn(self,supplied):
            check_probe_dispatch(parent.check,super().now,self.deadline)
            require(tuple(supplied)==argv and not self.used,'copied.fixed_child')
            self.used=True
            return super().spawn(argv)
    class ProbeCapture(program.native.CommandCapture):
        def _allowed_command(self,supplied):
            parent.check()
            return type(supplied) is tuple and supplied==argv
    require(callable(getattr(program.native.CommandCapture,'_allowed_command',None)),
            'copied.fixed_capture_catalog_missing')
    capture=ProbeCapture(ProbeIO());parent.io._copied_probe_capture=capture
    result=capture.command(argv,timeout=30)
    evidence=capture_failure_evidence(result,str(root),script,rows,len(capture.owned_commands),placement)
    try:
        require(program.native.command_capture_ok(result) and result['exitCode']==0 and
                not result['stdoutFacts']['truncated'] and not result['stderrFacts']['truncated'] and
                result['stderr']==b'' and not capture.owned_commands,'copied.child_not_successful')
        proof=validate_result(result['stdout'],str(root),rows)
    except BaseException as error:
        code=error.code if isinstance(error,Refusal) else 'copied.adjudication_failed'
        refuse_captured(code,evidence)
    provided=run_provided_selinux_proof(parent,prepared,runtime_source,str(root),rows)
    return {'proof':proof,'raw':result['stdout'],'scriptSha256':sha(script),'placement':placement,
        'providedSelinux':provided}


def run_provided_selinux_proof(parent,prepared,runtime_source,root,rows):
    """Actual fixed Linux physical path; no private role/admission is issued.

    Reuse the already authenticated copied BOOT runtime and the exact public
    HostOps/Collector/CommandCapture entry. Mutations below are negative tests
    solely on that synthetic owned copy, after both read-only children close.
    """
    import ci_authority, copied_location, host_admission
    ci_authority._parent(parent,prepared);runtime_source.require_parent(parent,prepared)
    session=sha(('integrated:'+parent.plan.markers['ocv.session']).encode('ascii'))[:32]
    require(root==copied_location.root_for(rows,session),'provided.ci_copy_origin')
    indexed={r['path']:r for r in rows}
    for name,(size,digest)in host_admission.PROVIDED_SELINUX_FILES.items():
        row=indexed.get(name)
        require(type(row)is dict and row['bytes']==size and row['sha256']==digest and
            row['mode']==host_admission.PROVIDED_SELINUX_MODES[name], 'provided.ci_member_origin')
    selected=host_admission.ProvidedSelinuxProbe(root)
    ops=host_admission.HostOps('/var/lib/openclaw-retained-verifier/'+session,
        'ocv-'+session+'.service',provided_selinux=selected)
    collector=host_admission.Collector(ops,parent.plan.boot_id)
    base=host_admission._GuestCommandIO
    class CheckedIO(base):
        def spawn(self,argv):
            parent.check();runtime_source.require_parent(parent,prepared)
            require(argv in selected.commands,'provided.ci_fixed_command')
            selected.validate()
            return super().spawn(argv)
    ops.command_port.io=CheckedIO()
    before=collector.before()
    require(not ops.command_port.owned_commands and len(ops.command_port.command_results)==2,
        'provided.ci_commands_not_closed')
    outcomes=[]
    for argv,result in ((selected.argv(True),selected._loader_result),(selected.argv(False),selected._probe_result)):
        require(host_admission._capture_ok(result),'provided.ci_capture')
        outcomes.append({'argv':list(argv),'exitCode':result['exitCode'],
            'stdoutFacts':result['stdoutFacts'],'stderrFacts':result['stderrFacts'],
            'captureComplete':result['captureComplete'],'streamsEOF':result['streamsEOF'],
            'streamsClosed':result['streamsClosed'],'ownedChildExited':result['ownedChildExited'],
            'ownershipRetained':result['ownershipRetained'],'childPid':result['childPid']})
    refused=[]
    def reject(label,action):
        try:action()
        except Refusal:refused.append(label)
        else:raise Refusal('provided.ci_negative_accepted')
    # Same real entry denies installed fallback even when the legacy tool exists.
    reject('installed-command-fallback',lambda:ops.command(('/usr/sbin/selinuxenabled',),5))
    reject('installed-read-fallback',lambda:ops.read('/usr/sbin/selinuxenabled',1048576))
    denied=ops.command_port.command(('/tmp/ld.so','--list',selected.binary),5)
    require(denied.get('spawned')is False and denied.get('spawnOutcome')=='not_attempted'and
        denied.get('captureComplete')is False and not ops.command_port.owned_commands,
        'provided.ci_arbitrary_loader_accepted')
    refused.append('arbitrary-loader')
    # Real filesystem negative: special/writable mode cannot satisfy the pin.
    binary=Path(selected.binary)
    try:
        os.chmod(binary,0o755)
        reject('altered-executable-mode',lambda:host_admission.ProvidedSelinuxProbe(root))
    finally:os.chmod(binary,0o555)
    library=Path(selected.library)/'libpcre2-8.so.0';saved=library.with_name('provided-negative-original')
    require(not os.path.lexists(saved),'provided.ci_negative_collision')
    try:
        os.replace(library,saved);os.symlink(saved.name,library)
        reject('library-symlink-substitution',lambda:host_admission.ProvidedSelinuxProbe(root))
    finally:
        if library.is_symlink():library.unlink()
        if saved.exists():os.replace(saved,library)
    # Parser and capture negatives use genuine complete result shapes, never an
    # authority token. Loader formats are pinned to the same authenticated file.
    import copy
    genuine=selected._loader_result
    for label,text in (('standalone-loader',selected.loader),
                       ('interpreter-alias','/lib64/ld-linux-x86-64.so.2 => '+selected.loader)):
        probe=host_admission.ProvidedSelinuxProbe(root);changed=copy.deepcopy(genuine)
        lines=changed['stdout'].decode('ascii').splitlines()
        lines=[line for line in lines if 'ld-linux-x86-64.so.2'not in line]
        changed['stdout']=('\n'.join(lines)+'\n\t'+text+' (0x1234)\n').encode('ascii')
        changed['stdoutFacts']={'bytes':len(changed['stdout']),'sha256':sha(changed['stdout']),
            'truncated':False,'complete':True}
        require(probe.loader_result(changed),'provided.ci_loader_variant')
    probe=host_admission.ProvidedSelinuxProbe(root);bad=copy.deepcopy(genuine)
    bad['stdout']=bad['stdout'].replace(selected.loader.encode(),b'/tmp/untrusted-loader')
    bad['stdoutFacts']={'bytes':len(bad['stdout']),'sha256':sha(bad['stdout']),'truncated':False,'complete':True}
    reject('loader-resolution-substitution',lambda:probe.loader_result(bad))
    probe=host_admission.ProvidedSelinuxProbe(root);bad=copy.deepcopy(genuine)
    text=bad['stdout'].decode('ascii');lines=[line for line in text.splitlines()if 'ld-linux-x86-64.so.2'not in line]
    bad['stdout']=('\n'.join(lines)+'\n/evil/interpreter => '+selected.loader+' (0x1234)\n').encode('ascii')
    bad['stdoutFacts']={'bytes':len(bad['stdout']),'sha256':sha(bad['stdout']),'truncated':False,'complete':True}
    reject('interpreter-alias-substitution',lambda:probe.loader_result(bad))
    probe=host_admission.ProvidedSelinuxProbe(root);probe._loader_result=genuine
    bad=copy.deepcopy(selected._probe_result);bad['exitCode']=1;bad['stderr']=b'loader failure'
    bad['stderrFacts']={'bytes':len(bad['stderr']),'sha256':sha(bad['stderr']),'truncated':False,'complete':True}
    reject('exit-one-loader-diagnostic',lambda:probe.probe_result(bad))
    final=host_admission.ProvidedSelinuxProbe(root);final.validate()
    require(final.host_view()==selected._view,'provided.ci_final_host_view')
    proof={'schema':'ocv.provided-selinux-physical-host-probe-proof.v1','status':'passed',
        'syntheticOnly':True,'privateRoleIssued':False,'privateVmAdmission':False,
        'root':root,'members':{n:indexed[n]for n in host_admission.PROVIDED_SELINUX_FILES},
        'hostView':final._view,'physicalCommands':outcomes,'collectorBefore':before,
        'negativeCases':refused,'loaderFormatCases':['standalone-loader','interpreter-alias'],
        'ownedCommandsRemaining':0,'validationBudget':32}
    return validate_provided_selinux_proof(proof,root,rows,parent.plan.boot_id)


def validate_provided_selinux_proof(value,root,rows,boot_id):
    import host_admission
    require(type(value)is dict and set(value)=={'schema','status','syntheticOnly','privateRoleIssued',
        'privateVmAdmission','root','members','hostView','physicalCommands','collectorBefore',
        'negativeCases','loaderFormatCases','ownedCommandsRemaining','validationBudget'}and
        value['schema']=='ocv.provided-selinux-physical-host-probe-proof.v1'and value['status']=='passed'and
        value['syntheticOnly']is True and value['privateRoleIssued']is False and
        value['privateVmAdmission']is False and value['root']==root and value['ownedCommandsRemaining']==0 and
        value['validationBudget']==32,'provided.proof_scope')
    indexed={r['path']:r for r in rows}
    require(value['members']=={n:indexed[n]for n in host_admission.PROVIDED_SELINUX_FILES},'provided.proof_members')
    for name,(size,digest)in host_admission.PROVIDED_SELINUX_FILES.items():
        row=value['members'][name]
        require(row['bytes']==size and row['sha256']==digest and row['mode']==host_admission.PROVIDED_SELINUX_MODES[name],
            'provided.proof_origin')
    expected=(root+'/lib64/ld-linux-x86-64.so.2','--inhibit-cache','--library-path',root+'/lib/x86_64-linux-gnu')
    commands=value['physicalCommands'];require(type(commands)is list and len(commands)==2,'provided.proof_commands')
    for index,outcome in enumerate(commands):
        argv=expected+(('--list',root+'/usr/sbin/selinuxenabled')if index==0 else(root+'/usr/sbin/selinuxenabled',))
        require(type(outcome)is dict and set(outcome)=={'argv','exitCode','stdoutFacts','stderrFacts',
            'captureComplete','streamsEOF','streamsClosed','ownedChildExited','ownershipRetained','childPid'}and
            outcome['argv']==list(argv)and type(outcome['childPid'])is int and outcome['childPid']>1 and
            type(outcome['exitCode'])is int and outcome['exitCode']in((0,)if index==0 else(0,1))and
            all(outcome[k]is True for k in('captureComplete','streamsEOF','streamsClosed','ownedChildExited'))and
            outcome['ownershipRetained']is False,'provided.proof_capture')
        for stream in('stdout','stderr'):
            fact=outcome[stream+'Facts']
            require(type(fact)is dict and set(fact)=={'bytes','sha256','truncated','complete'}and
                type(fact.get('sha256'))is str and re.fullmatch('[0-9a-f]{64}',fact['sha256'])and
                fact.get('truncated')is False and fact.get('complete')is True and type(fact.get('bytes'))is int and 0<=fact['bytes']<=(16384 if stream=='stdout' else 4096),
                'provided.proof_stream')
            if index==1 or stream=='stderr':require(fact['bytes']==0 and fact['sha256']==sha(b''),'provided.proof_empty_stream')
    view=value['hostView'];require(type(view)is dict and set(view)=={'namespaces','root'}and
        type(view['root'])in(list,tuple)and len(view['root'])==2 and all(type(x)is int and x>0 for x in view['root'])and
        type(view['namespaces'])is dict and set(view['namespaces'])=={'mnt','net','ipc','pid','user','uts','cgroup'}and
        all(re.fullmatch(name+r':\[[1-9][0-9]*\]',text)for name,text in view['namespaces'].items()),'provided.proof_host_view')
    before=value['collectorBefore'];session=root.split('/')[-2]
    require(type(before)is dict and set(before)=={'managerNamespaces','selinuxExitCode','root','unit','bootId'}and
        before['managerNamespaces']=={n:view['namespaces'][n]for n in('mnt','user')}and
        before['selinuxExitCode']==commands[1]['exitCode']and before['root']=='/var/lib/openclaw-retained-verifier/'+session and
        before['unit']=='ocv-'+session+'.service'and before['bootId']==boot_id,'provided.proof_collector_before')
    require(value['negativeCases']==['installed-command-fallback','installed-read-fallback','arbitrary-loader',
        'altered-executable-mode','library-symlink-substitution','loader-resolution-substitution',
        'interpreter-alias-substitution','exit-one-loader-diagnostic']and
        value['loaderFormatCases']==['standalone-loader','interpreter-alias'],'provided.proof_cases')
    return value


if __name__=='__main__':raise SystemExit('copied_bootstrap_probe_no_cli')

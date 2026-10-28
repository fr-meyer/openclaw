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
fd=os.open('/proc/self/task/'+str(os.getpid())+'/children',os.O_RDONLY|os.O_NOFOLLOW)
try:
 children=os.read(fd,4097)
 if len(children)>4096 or children.strip():raise RuntimeError('copied.children_present')
finally:os.close(fd)
fd=os.open('/proc/self/maps',os.O_RDONLY|os.O_NOFOLLOW)
try:
 data=os.read(fd,65537)
 if len(data)>65536:raise RuntimeError('copied.maps_cap')
finally:os.close(fd)
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
    require(type(rows) is list and len(rows)==626,'copied.runtime_count')
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


def capture_failure_evidence(result,root,script,rows,owned_commands):
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
    require(len(canonical(evidence))<=FAILURE_FACTS_CAP,'copied.failure_facts_cap')
    return evidence


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
    base=Path('/run/ocv')/('copied-controller-'+parent.plan.markers['ocv.session'])
    require(base.parent.is_dir() and not base.parent.is_symlink() and
            base.parent.stat().st_uid==0 and not stat.S_IMODE(base.parent.stat().st_mode)&0o077,
            'copied.fixed_parent')
    base.mkdir(mode=0o700);os.chmod(base,0o700)
    root=base/'root';root.mkdir(mode=0o755);os.chmod(root,0o755)
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
            target.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
            for directory in (target.parent,*target.parent.parents):
                if directory==base:break
                require(directory.is_dir() and not directory.is_symlink() and
                        directory.stat().st_uid==0 and directory.stat().st_dev==base.stat().st_dev,
                        'copied.destination_parent')
                os.chmod(directory,0o755)
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
    script=probe_script(str(root),rows);argv=build_argv(str(root),script)
    program=parent.io.program
    class ProbeIO(program.native.NativeCommandIO):
        def __init__(self):self.used=False
        def spawn(self,supplied):
            parent.check()
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
    evidence=capture_failure_evidence(result,str(root),script,rows,len(capture.owned_commands))
    try:
        require(program.native.command_capture_ok(result) and result['exitCode']==0 and
                not result['stdoutFacts']['truncated'] and not result['stderrFacts']['truncated'] and
                result['stderr']==b'' and not capture.owned_commands,'copied.child_not_successful')
        proof=validate_result(result['stdout'],str(root),rows)
    except BaseException as error:
        code=error.code if isinstance(error,Refusal) else 'copied.adjudication_failed'
        refuse_captured(code,evidence)
    return {'proof':proof,'raw':result['stdout'],'scriptSha256':sha(script)}


if __name__=='__main__':raise SystemExit('copied_bootstrap_probe_no_cli')

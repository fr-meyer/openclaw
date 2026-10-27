"""Disarmed native CI port SOURCE. No NativeOps can currently be constructed.

All OS/command work is injectable and unused on import. Only a future exact
reviewed CI manifest/capability may bind NativeOps; no JSON or CLI issues it.
"""
import datetime as dt
import copy
import hashlib
import json
import os
from pathlib import Path,PurePosixPath
import selectors
import stat
import subprocess
import time
import ci_probe as probe
import ci_profile as profile
import ci_fixture as fixture
import ci_anchors
from ci_protocol import Refusal,canonical,closed,decode,require,sha,write_once
_ISSUED_CAPABILITY=None
MANIFEST_SHA256=None


class NativeCommandIO:
    """Fixed native primitives, still gated before construction; no test issuer."""
    def __init__(self,capability):
        require(_ISSUED_CAPABILITY is not None and capability is _ISSUED_CAPABILITY and MANIFEST_SHA256 is not None,
                'ci.native_capability_unissued')
    def now(self):return time.monotonic()
    def spawn(self,argv):return subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        env={'PATH':'/usr/bin','LANG':'C','LC_ALL':'C'},close_fds=True)
    def selector(self):return selectors.DefaultSelector()
    def nonblocking(self,stream):os.set_blocking(stream.fileno(),False)
    def register(self,selector,stream,label):selector.register(stream,selectors.EVENT_READ,label)
    def events(self,selector,seconds):return selector.select(seconds)
    def mapped(self,selector):return bool(selector.get_map())
    def read(self,stream):return os.read(stream.fileno(),65536)
    def unregister(self,selector,stream):selector.unregister(stream)
    def close_selector(self,selector):selector.close()
    def close_stream(self,stream):stream.close()
    def poll(self,child):return child.poll()
    def terminate(self,child):child.terminate()
    def kill(self,child):child.kill()
    def wait(self,child,seconds):return child.wait(timeout=seconds)


def command_boundary_refusal(error):
    """Evidence for an unexpected opaque port exception, never an exit verdict."""
    result={'exitCode':None,'timedOut':False,'spawned':None,'spawnOutcome':'unknown',
      'captureComplete':False,'streamsEOF':False,'streamsClosed':False,'ownedChildExited':False,
      'ownershipRetained':True,'refusalCode':'ci.command_boundary_raised','failurePhase':'boundary',
      'errors':[{'phase':'boundary','type':type(error).__name__[:48],
                 'errno':error.errno if isinstance(error,OSError) else None}]}
    for name in ('stdout','stderr'):
        result[name]=b'';result[name+'Facts']={'bytes':0,'sha256':sha(b''),'truncated':False,'complete':False}
    return result


def command_capture_ok(result):
    return (type(result) is dict and result.get('captureComplete') is True and result.get('streamsEOF') is True and
      result.get('streamsClosed') is True and result.get('ownedChildExited') is True and
      result.get('ownershipRetained') is False and result.get('refusalCode') is None and result.get('timedOut') is False)


class CommandCapture:
    """One-call capture/ownership core; injected I/O grants no native authority.

    NativeOps inherits this exact method. Tests construct this core with inert
    process/selector I/O, never NativeOps or NativeCommandIO capability objects.
    """
    def __init__(self,io):
        self.io=io;self.owned_commands={};self.command_results={};self.command_sequence=0
    def command(self,argv,timeout=5):
        import math
        self.command_sequence+=1;number=self.command_sequence
        records={name:{'h':hashlib.sha256(),'bytes':0,'head':bytearray(),'tail':bytearray(),'cap':cap}
                 for name,cap in (('stdout',16384),('stderr',4096))}
        state={'process':None,'selector':None,'streams':{'stdout':None,'stderr':None},'nonblocking':set(),
               'eof':set(),'operationId':number,'closed':set()}
        # Ownership slot exists BEFORE spawn. As soon as spawn returns, the
        # returned object is stored before any selector, fd or clock operation.
        self.owned_commands[number]=state
        result={'exitCode':None,'timedOut':False,'spawned':False,'spawnOutcome':'not_attempted',
                'captureComplete':False,'streamsEOF':False,'streamsClosed':False,'ownedChildExited':False,
                'ownershipRetained':False,'refusalCode':None,'failurePhase':None,'operationId':number,'errors':[]}
        phase='precondition';selector_closed=False;waited=False;last=None
        def error(exc,where):
            if result['failurePhase'] is None:result['failurePhase']=where
            result['refusalCode']='ci.command_capture_refused'
            if len(result['errors'])<16:result['errors'].append({'phase':where,'type':type(exc).__name__[:48],
              'errno':exc.errno if isinstance(exc,OSError) else None})
        def now():
            nonlocal last
            value=self.io.now()
            require(type(value) in (int,float) and math.isfinite(value) and (last is None or value>=last),'ci.command_clock')
            last=value;return value
        def append(label,raw):
            require(type(raw) is bytes,'ci.command_read_type')
            row=records[label];row['h'].update(raw);row['bytes']+=len(raw);half=row['cap']//2
            row['head'].extend(raw[:max(0,half-len(row['head']))]);row['tail'].extend(raw)
            if len(row['tail'])>half:del row['tail'][:-half]
        def drain(seconds):
            for key,_ in self.io.events(state['selector'],seconds):
                label=key.data;require(label in records,'ci.command_channel')
                try:raw=self.io.read(key.fileobj)
                except BlockingIOError:continue
                if not raw:
                    state['eof'].add(label);self.io.unregister(state['selector'],key.fileobj)
                else:append(label,raw)
        try:
            require(type(argv) is tuple and argv and all(type(v) is str and v and '\x00' not in v for v in argv) and
              argv[0] in ('/usr/bin/systemd-run','/usr/bin/systemctl','/usr/bin/busctl','/usr/bin/gpgv','/usr/sbin/selinuxenabled'),
              'ci.native_command')
            require(type(timeout) in (int,float) and math.isfinite(timeout) and 0<timeout<=300,'ci.command_timeout')
            deadline=now()+timeout;phase='spawn';result['spawnOutcome']='unknown'
            state['process']=self.io.spawn(argv)
            result['spawned']=True;result['spawnOutcome']='handle_returned'
            child=state['process'];result['childPid']=getattr(child,'pid',None)
            phase='spawn_identity';require(child is not None and type(result['childPid']) is int and result['childPid']>0,'ci.command_child_identity')
            phase='selector_create';state['selector']=self.io.selector()
            for label in ('stdout','stderr'):
                phase='stream_'+label;stream=getattr(child,label);state['streams'][label]=stream
                phase='nonblocking_'+label;self.io.nonblocking(stream);state['nonblocking'].add(label)
                phase='register_'+label;self.io.register(state['selector'],stream,label)
            phase='capture'
            for _ in range(65536):
                if not self.io.mapped(state['selector']):break
                remaining=deadline-now()
                if remaining<=0:result['timedOut']=True;break
                drain(min(.05,remaining))
            else:raise Refusal('ci.command_read_budget')
            phase='wait';code=self.io.wait(child,1)
            require(type(code) is int,'ci.command_exit_shape');result['exitCode']=code;waited=True
        except BaseException as exc:error(exc,phase)
        finally:
            child=state['process']
            if child is not None:
                # Failure of any one observation/signal/wait/close never skips
                # the other exact-child cleanup attempts. No unit/group signal.
                code=None
                try:
                    code=self.io.poll(child)
                    require(code is None or type(code) is int,'ci.command_poll_shape')
                except BaseException as exc:error(exc,'cleanup_poll')
                if not waited and code is None:
                    try:self.io.terminate(child)
                    except BaseException as exc:error(exc,'cleanup_terminate')
                if not waited:
                    try:
                        code=self.io.wait(child,1);require(type(code) is int,'ci.command_exit_shape')
                        result['exitCode']=code;waited=True
                    except BaseException as exc:error(exc,'cleanup_wait')
                if not waited:
                    try:self.io.kill(child)
                    except BaseException as exc:error(exc,'cleanup_kill')
                    try:
                        code=self.io.wait(child,1);require(type(code) is int,'ci.command_exit_shape')
                        result['exitCode']=code;waited=True
                    except BaseException as exc:error(exc,'cleanup_wait_after_kill')
                # Capture available queued bytes after exit; each read is known
                # nonblocking. A broken selector cannot suppress fd closure.
                if state['selector'] is not None:
                    try:
                        for _ in range(64):
                            if not self.io.mapped(state['selector']):break
                            before=sum(r['bytes'] for r in records.values())+len(state['eof'])
                            drain(0)
                            if before==sum(r['bytes'] for r in records.values())+len(state['eof']):break
                    except BaseException as exc:error(exc,'cleanup_drain')
                    try:self.io.close_selector(state['selector']);selector_closed=True
                    except BaseException as exc:error(exc,'cleanup_selector_close')
                else:selector_closed=True
                for label in ('stdout','stderr'):
                    try:
                        stream=state['streams'][label]
                        if stream is None:stream=getattr(child,label);state['streams'][label]=stream
                        self.io.close_stream(stream);state['closed'].add(label)
                    except BaseException as exc:error(exc,'cleanup_close_'+label)
                result['ownedChildExited']=waited
                result['streamsClosed']=selector_closed and state['closed']=={'stdout','stderr'}
                result['streamsEOF']=state['eof']=={'stdout','stderr'}
                result['ownershipRetained']=not(waited and result['streamsClosed'])
            else:
                result['ownershipRetained']=result['spawnOutcome']=='unknown'
                result['streamsClosed']=True
            result['captureComplete']=(result['spawned'] is True and result['ownedChildExited'] and result['streamsEOF'] and
              result['streamsClosed'] and not result['errors'] and not result['timedOut'])
            if not result['captureComplete'] and result['refusalCode'] is None:
                result['refusalCode']='ci.command_capture_incomplete';result['failurePhase']=phase
            for label,row in records.items():
                overlap=max(0,len(row['head'])+len(row['tail'])-row['bytes']) if row['bytes']<=row['cap'] else 0
                view=bytes(row['head'])+bytes(row['tail'][overlap:])
                result[label]=view;result[label+'Facts']={'bytes':row['bytes'],'sha256':row['h'].hexdigest(),
                  'truncated':row['bytes']>row['cap'],'complete':result['streamsEOF'] and not result['errors']}
            self.command_results[number]=result
            if not result['ownershipRetained']:self.owned_commands.pop(number,None)
        return result


class NativeOps(CommandCapture):
    def __init__(self,capability):
        require(_ISSUED_CAPABILITY is not None and capability is _ISSUED_CAPABILITY and MANIFEST_SHA256 is not None,
                'ci.native_capability_unissued')
        super().__init__(NativeCommandIO(capability))
    def read(self,path,cap):
        fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NONBLOCK|os.O_NOFOLLOW)
        try:
            before=os.fstat(fd)
            public=path.startswith(('/seed/','/var/lib/apt/lists/','/usr/share/keyrings/','/usr/sbin/selinuxenabled'))
            if public:require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and before.st_nlink==1 and
                              not stat.S_IMODE(before.st_mode)&0o022,'ci.native_public_file')
            out=bytearray()
            while len(out)<=cap:
                raw=os.read(fd,min(65536,cap+1-len(out)))
                if not raw:break
                out.extend(raw)
            require(len(out)<=cap,'ci.native_read_cap')
            after=os.fstat(fd)
            if public:require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
                              (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) and len(out)==before.st_size,
                              'ci.native_public_changed')
            return bytes(out)
        finally:os.close(fd)
    def readlink(self,path):return os.readlink(path)
    def stat(self,path):return os.stat(path)
    def lstat(self,path):return os.lstat(path)
    def listdir(self,path,cap):
        out=[]
        with os.scandir(path) as entries:
            for entry in entries:
                require(len(out)<cap,'ci.native_directory_cap');out.append(entry.name)
        return out
    def mkdir(self,path,mode):Path(path).mkdir(parents=True,exist_ok=False,mode=mode)
    def chmod(self,path,mode):os.chmod(path,mode,follow_symlinks=False)
    def stage_file(self,path,raw,mode):
        p=Path(path);p.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
        write_once(p,raw,mode=mode)
    def unlink_file(self,path):os.unlink(path)
    def rmdir(self,path):os.rmdir(path)
    def monotonic(self):return time.monotonic()
    def sleep(self,seconds):time.sleep(seconds)


class Port:
    """Fixed source/command mappings; defaults cannot acquire OS authority."""
    def __init__(self,ops,manifest,*,session_root,clock,metadata_admission=None):
        require(ops is not None,'ci.ops_required')
        require(type(manifest) is dict and set(manifest)=={'files','code','tools'} and
          type(manifest['files']) is list and 1<=len(manifest['files'])<=8192,'ci.manifest')
        require(type(session_root) is str and session_root.startswith('/var/lib/ci-verifier/') and
          str(PurePosixPath(session_root))==session_root and '..' not in PurePosixPath(session_root).parts,'ci.session_root')
        self.metadata_admission=metadata_admission
        self.ops=self.kernel=ops;self.manifest=manifest;self.root=session_root;self.clock=clock
        self.command_evidence=[];self.command_count=0;self.primary_command_failure=None;self.unit_issued=False;self.effect_intents=set();self.files=[];self.context=None;self.unit=None
        self.outputs=None;self.code=manifest['code'];self.created=False
    def remember_command(self,argv,result,*,failed=False):
        row={'argv':list(argv),'result':copy.deepcopy(result)}
        self.command_count+=1;self.command_evidence.append(row);self.command_evidence=self.command_evidence[-16:]
        if failed and self.primary_command_failure is None:self.primary_command_failure=copy.deepcopy(row)
        return row
    def admit_metadata_before_unit(self):
        require(self.metadata_admission is not None,'ci.native_metadata_context_unissued')
        refused=False
        try:return self.metadata_admission.run()
        except BaseException as error:
            refused=True
            code=str(error) if type(error).__module__=='ci_archive_policy' else 'metadata_process_or_context_failed'
            raise Refusal('ci.metadata_refused',{'subcheck':code[:96]}) from None
        finally:
            evidence=self.metadata_admission.evidence
            if evidence is not None:self.remember_command(evidence['argv'],evidence['outcome'],failed=refused)
    def command(self,argv):
        try:result=self.ops.command(tuple(argv),5)
        except BaseException as error:result=command_boundary_refusal(error)
        # Freeze the first cause BEFORE adjudication or any supplemental query.
        failed=not command_capture_ok(result) or type(result.get('exitCode')) is not int or result['exitCode']!=0 or any(
          result.get(k,{}).get('truncated') is not False for k in ('stdoutFacts','stderrFacts'))
        self.remember_command(argv,result,failed=failed)
        require(command_capture_ok(result),'ci.native_command_capture_refused',
          {'command':argv[0],'phase':result.get('failurePhase'),'ownershipRetained':result.get('ownershipRetained')})
        require(type(result.get('exitCode')) is int and result['exitCode']==0,
                'ci.native_command_failed',{'command':argv[0],'exitCode':result.get('exitCode'),'timedOut':result.get('timedOut')})
        require(all(result.get(k,{}).get('truncated') is False for k in ('stdoutFacts','stderrFacts')),
                'ci.native_command_truncated')
        return result['stdout']
    def effect(self,name):
        require(name not in self.effect_intents,'ci.native_effect_once');self.effect_intents.add(name)
    def stage_public_inputs(self,context):
        self.effect('stage')
        require(self.root=='/var/lib/ci-verifier/'+context['sessionId'],'ci.root_session_join')
        self.context=context;self.unit=context['unitName']
        require(self.unit=='ocv-'+context['sessionId']+'.service','ci.unit_name')
        self.ops.mkdir(self.root,0o700);self.created=True
        self.ops.mkdir(self.root+'/root',0o755);self.ops.mkdir(self.root+'/evidence',0o700)
        for relative in ('run','tmp','var/tmp','dev/mqueue','proc','sys','input/oci','control'):
            self.ops.mkdir(self.root+'/root/'+relative,0o755)
        seen=set();total=0;dependency_rows={}
        for row in self.manifest['files']:
            closed(row,{'path','seedPath','bytes','sha256','mode'},'ci.runtime_row')
            relative=row['path'];p=PurePosixPath(relative)
            require(type(relative) is str and not p.is_absolute() and str(p)==relative and '..' not in p.parts and
              relative not in seen and row['mode'] in (0o444,0o555),'ci.runtime_path')
            require(type(row['seedPath']) is str and row['seedPath'].startswith('/seed/') and '..' not in PurePosixPath(row['seedPath']).parts,
              'ci.seed_path')
            raw=self.ops.read(row['seedPath'],row['bytes']+1)
            require(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'ci.runtime_pin')
            total+=len(raw);require(total<=268435456,'ci.runtime_cap')
            target=self.root+'/root/'+relative;self.ops.stage_file(target,raw,row['mode']);self.files.append(target);seen.add(relative)
            if relative in ('code/ci_protocol.py','code/ci_profile.py','code/ci_fixture.py'):
                dependency_rows[relative.split('/')[-1]]={'bytes':len(raw),'sha256':sha(raw)}
        require({'usr/bin/python3.11','lib64/ld-linux-x86-64.so.2','code/static-entry','code/worker.py',
                 'code/ci_protocol.py','code/ci_profile.py','code/ci_fixture.py'}<=seen,'ci.runtime_incomplete')
        require(sha(canonical(self.manifest['files']))==self.code['runtimeManifestSha256'],'ci.runtime_manifest_binding')
        imports=canonical({'schema':'ci.public-imports.v1','codeFiles':dependency_rows})
        self.imports_sha=sha(imports)
        self.ops.stage_file(self.root+'/root/control/imports.json',imports,0o444)
        self.files.append(self.root+'/root/control/imports.json')
        for relative,raw in (('input/privacy.json',fixture.REPORT),('input/oci/synthetic.bin',fixture.BLOB),
                             ('control/context.json',canonical(context))):
            path=self.root+'/root/'+relative;self.ops.stage_file(path,raw,0o444);self.files.append(path)
        self.ops.chmod(self.root+'/root/input',0)
        for name in ('worker.stdout','worker.stderr'):
            p=self.root+'/evidence/'+name;self.ops.stage_file(p,b'',0o600);self.files.append(p)
        props=profile.properties(self.ops.read('/seed/CI-PROFILE.json',16384),context['sessionId'],self.root)
        self.properties=props
        require(sum(v=='MountFlags=private' for v in props)==1 and not any(v.startswith('MountFlags=') and v!='MountFlags=private' for v in props),'ci.private_profile_required')
        self.anchors=ci_anchors.Sources(self.ops,self.root,self.unit,context['bootId'],self.manifest['tools'].get('selinuxenabledSha256'),propagation_policy=context['mountPropagation'])
        try:self.anchors.before()
        finally:
            capture=getattr(self.anchors,'selinux_evidence',None)
            if capture is not None:
                failed=not command_capture_ok(capture) or capture.get('exitCode') not in (0,1) or any(
                  capture.get(k,{}).get('truncated') is not False for k in ('stdoutFacts','stderrFacts'))
                self.remember_command(('/usr/sbin/selinuxenabled',),capture,failed=failed)
        manifest={'report':fixture.REPORT_SHA,'blob':fixture.BLOB_SHA}
        return {'manifest':manifest,'propertiesSha256':sha(canonical(props))}
    def start_unit_once(self,context):
        self.effect('start')
        absent=self.command(('/usr/bin/systemctl','list-units','--all','--full','--plain','--no-legend','--no-pager',self.unit))
        require(absent.strip()==b'','ci.unit_already_present')
        self.unit_issued=True
        args=['/usr/bin/systemd-run','--unit='+self.unit]
        for value in self.properties:
            if value.startswith('ExecStart='):continue
            args.extend(('--property',value))
        args.extend(('/code/static-entry',context['identityName']))
        self.command(args)
    def typed(self,interface,name,kind):
        # systemd's public object-path escaping, no Manager.GetUnit residency call.
        escaped=''.join(c if c.isascii() and c.isalnum() else '_'+format(ord(c),'02x') for c in self.unit)
        value=decode(self.command(('/usr/bin/busctl','--system','--json=short','get-property','org.freedesktop.systemd1',
          '/org/freedesktop/systemd1/unit/'+escaped,interface,name)),16384)
        closed(value,{'type','data'},'ci.typed_schema')
        require(value['type']==kind,'ci.typed_shape')
        data=value['data']
        # busctl get-property emits the D-Bus property's value directly. Its
        # JSON `data` is a scalar for basic types and a list for an array.
        # Never unwrap a synthetic single-element envelope as authority.
        if kind=='b':require(type(data) is bool,'ci.typed_shape')
        elif kind=='s':require(type(data) is str,'ci.typed_shape')
        elif kind=='u':require(type(data) is int and 0<=data<2**32,'ci.typed_shape')
        elif kind=='t':require(type(data) is int and 0<=data<2**64,'ci.typed_shape')
        elif kind=='i':require(type(data) is int and -(2**31)<=data<2**31,'ci.typed_shape')
        elif kind=='ay':require(type(data) is list and len(data)==16 and
                                all(type(byte) is int and 0<=byte<256 for byte in data),'ci.typed_shape')
        else:raise Refusal('ci.typed_signature_unsupported')
        return data
    def owned_observation(self,context):
        # Exact scalar readback. Missing/unsupported rendering refuses; no absent->empty inference.
        service='org.freedesktop.systemd1.Service';unit='org.freedesktop.systemd1.Unit'
        values={name:self.typed(service,name,kind) for name,kind in
          (('DynamicUser','b'),('User','s'),('Group','s'),('MainPID','u'),('NoNewPrivileges','b'),
           ('PrivateNetwork','b'),('PrivateIPC','b'),('CapabilityBoundingSet','t'),('AmbientCapabilities','t'),('MountFlags','t'))}
        require(values['DynamicUser'] is True and values['NoNewPrivileges'] is True and values['PrivateNetwork'] is True and
          values['PrivateIPC'] is True and values['CapabilityBoundingSet']==values['AmbientCapabilities']==0,'ci.unit_security_readback')
        require(type(values['MountFlags']) is int and values['MountFlags']==ci_anchors.MS_PRIVATE,'ci.unit_propagation_readback')
        pid=values['MainPID'];require(type(pid) is int and pid>1,'ci.unit_pid')
        invocation=self.typed(unit,'InvocationID','ay');group=self.typed(unit,'ControlGroup','s')
        require(type(invocation) is list and len(invocation)==16 and all(type(x) is int and 0<=x<=255 for x in invocation),'ci.invocation')
        status=probe.status(self.ops.read('/proc/'+str(pid)+'/status',16384).decode(),full=True)
        uid,gid=int(status['Uid'][0]),int(status['Gid'][0])
        generation=probe.proc_stat(self.ops.read('/proc/'+str(pid)+'/stat',8192).decode(),pid)
        expected=self.anchors.collect(context)
        expected.update(schema=probe.EXPECTED_SCHEMA,sessionId=context['sessionId'],bootId=context['bootId'],pid=pid,
          startTimeTicks=generation['startTimeTicks'],unitName=self.unit,identityName=context['identityName'],
          invocationId=bytes(invocation).hex(),uid=uid,gid=gid,dynamicIdRange=[61184,65519],cgroupPath=group,
          hostNamespaces={name:int(self.ops.readlink('/proc/self/ns/'+name).split('[')[1][:-1]) for name in probe.NAMESPACE_NAMES},
          limits={'memoryMaxBytes':2147483648,'memorySwapMaxBytes':0,'cpuQuota':100000,'cpuPeriod':100000,'pidsMax':64},
          environmentSha256=sha(canonical(probe.ENVIRONMENT)),profileSha256=profile.DESIGN_PROFILE_SHA)
        self.cgroup=group
        unit_value={'unitName':self.unit,'DynamicUser':values['DynamicUser'],'User':values['User'],'Group':values['Group'],
          'MainPID':pid,'UID':uid,'GID':gid,'InvocationID':bytes(invocation).hex(),'ControlGroup':group,
          'propertiesSha256':sha(canonical(self.properties)),'staticNameAbsent':True,'MountFlags':values['MountFlags']}
        # staticNameAbsent must be measured: no same-name passwd/group record.
        name=context['identityName']
        for path in ('/etc/passwd','/etc/group'):
            require(not any(line.split(':',1)[0]==name for line in self.ops.read(path,65536).decode().splitlines()),'ci.static_identity_present')
        return expected,unit_value
    def source_anchor_recheck(self):return self.anchors.recheck()
    def ready_once(self):
        raw=self.ops.read(self.root+'/evidence/worker.stderr',4096)
        rows=raw.splitlines();require(len(rows)==1,'ci.ready_count');return rows[0]
    def release_inputs_and_gate(self,raw):
        self.effect('gate');self.ops.chmod(self.root+'/root/input',0o555)
        self.ops.stage_file(self.root+'/root/control/admission.json',raw,0o444);self.files.append(self.root+'/root/control/admission.json')
    def wait_once(self,seconds):
        self.effect('wait');require(type(seconds) in (int,float) and 0<seconds<=240,'ci.wait_budget');deadline=self.ops.monotonic()+min(seconds,240)
        while True:
            state=self.typed('org.freedesktop.systemd1.Unit','SubState','s')
            if state in ('exited','dead','failed'):
                exit_code=self.typed('org.freedesktop.systemd1.Service','ExecMainCode','i')
                status=self.typed('org.freedesktop.systemd1.Service','ExecMainStatus','i')
                result=self.typed('org.freedesktop.systemd1.Service','Result','s')
                self.outputs=self.collect_owned_outputs()
                self.outputs.update(returncode=status if exit_code==1 else 1,timedOut=result=='timeout')
                return self.outputs
            if self.ops.monotonic()>=deadline:
                self.outputs=self.collect_owned_outputs();self.outputs.update(returncode=None,timedOut=True)
                return self.outputs
            self.ops.sleep(min(.05,max(0,deadline-self.ops.monotonic())))
    def copied_report_once(self):return self.ops.read(self.root+'/root/input/privacy.json',4096)
    def collect_owned_outputs(self):
        def view(name):return self.ops.read(self.root+'/evidence/'+name,65536)
        if self.outputs:return dict(self.outputs)
        return {'stdout':view('worker.stdout'),'stderr':view('worker.stderr'),'returncode':1,'timedOut':False}
    def stop_owned_unit_normally(self,unit):
        self.effect('stop');require(unit==self.unit and self.unit_issued,'ci.stop_identity');self.command(('/usr/bin/systemctl','stop',self.unit))
    def owned_cgroup_empty(self):
        group=getattr(self,'cgroup',None)
        require(group=='/system.slice/'+self.unit,'ci.cgroup_identity')
        try:raw=self.ops.read('/sys/fs/cgroup'+group+'/cgroup.events',4096).decode()
        except FileNotFoundError:return True  # Exact previously joined owned cgroup, host reader only.
        return 'populated 0' in raw.splitlines()
    def retire_only_copied_inputs(self):
        self.effect('retire')
        # Fixed two copied synthetic inputs; no root/runtime/host recursive deletion.
        for relative in ('input/privacy.json','input/oci/synthetic.bin'):self.ops.unlink_file(self.root+'/root/'+relative)
    def normal_guest_shutdown(self):
        self.effect('shutdown')
        # Defer actual poweroff until the trusted outer entry has retained and
        # emitted its result. In-guest success never establishes QEMU exit.
        return {'shutdownRequested':True,'outerExitPending':True}
    def poweroff_after_result_custody(self):
        require('shutdown' in self.effect_intents,'ci.shutdown_not_requested')
        self.effect('poweroff')
        self.command(('/usr/bin/systemctl','poweroff','--no-block'))
        return {'poweroffRequestSettled':True,'outerExitPending':True}

    def failure_evidence(self):
        import base64
        # Supplemental reads must never evict or replace the primary failed
        # command, including when every supplemental query succeeds.
        primary=copy.deepcopy(self.primary_command_failure)
        setup={}
        if self.unit_issued and self.outputs is None:
            for name,kind in (('ExecMainCode','i'),('ExecMainStatus','i'),('Result','s')):
                try:setup[name]=self.typed('org.freedesktop.systemd1.Service',name,kind)
                except BaseException:setup[name]='unavailable'
        selected=[]
        if primary is not None:selected.append(('primary',primary))
        for row in self.command_evidence[-2:]:
            if primary is None or row!=primary:selected.append(('supplemental',row))
        out=[]
        for role,row in selected:
            result=row['result']
            item={'role':role,'argv':row['argv'][:8],'exitCode':result.get('exitCode'),'timedOut':result.get('timedOut'),
              'captureComplete':result.get('captureComplete'),'ownershipRetained':result.get('ownershipRetained'),
              'refusalCode':result.get('refusalCode'),'failurePhase':result.get('failurePhase'),
              'errors':result.get('errors',[])[:4],
              'commandOperationId':result.get('operationId') if type(result.get('operationId')) is int else None,
              'childPid':result.get('childPid') if type(result.get('childPid')) is int else None,
              'spawnOutcome':result.get('spawnOutcome')}
            for name in ('stdout','stderr'):
                raw=result.get(name,b'');view=raw if len(raw)<=512 else raw[:256]+raw[-256:]
                item[name]={'viewBase64':base64.b64encode(view).decode(),'capturedBytes':len(raw),
                            'source':result.get(name+'Facts',{})}
            out.append(item)
        return {'schema':'ci.fixed-command-evidence.v1','commandCount':self.command_count,'ownedSetup':setup,'commands':out}

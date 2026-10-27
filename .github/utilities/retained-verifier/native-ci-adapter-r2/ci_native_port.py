"""Disarmed native CI port SOURCE. No NativeOps can currently be constructed.

All OS/command work is injectable and unused on import. Only a future exact
reviewed CI manifest/capability may bind NativeOps; no JSON or CLI issues it.
"""
import datetime as dt
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


class NativeOps:
    def __init__(self,capability):
        require(_ISSUED_CAPABILITY is not None and capability is _ISSUED_CAPABILITY and MANIFEST_SHA256 is not None,
                'ci.native_capability_unissued')
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
    def command(self,argv,timeout=5):
        require(type(argv) is tuple and argv and argv[0] in ('/usr/bin/systemd-run','/usr/bin/systemctl','/usr/bin/busctl','/usr/bin/gpgv','/usr/sbin/selinuxenabled'),
                'ci.native_command')
        process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            env={'PATH':'/usr/bin','LANG':'C','LC_ALL':'C'},close_fds=True)
        selector=selectors.DefaultSelector();records={};deadline=time.monotonic()+timeout;timed=False
        for label,stream,cap in (('stdout',process.stdout,16384),('stderr',process.stderr,4096)):
            os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,label)
            records[label]={'h':hashlib.sha256(),'bytes':0,'head':bytearray(),'tail':bytearray(),'cap':cap}
        try:
            while selector.get_map():
                if time.monotonic()>=deadline:
                    timed=True;process.kill();break  # Exact owned metadata/submit child only; never the unit.
                for key,_ in selector.select(min(.05,max(0,deadline-time.monotonic()))):
                    raw=os.read(key.fileobj.fileno(),65536)
                    if not raw:selector.unregister(key.fileobj);continue
                    row=records[key.data];row['h'].update(raw);row['bytes']+=len(raw);half=row['cap']//2
                    row['head'].extend(raw[:max(0,half-len(row['head']))]);row['tail'].extend(raw)
                    if len(row['tail'])>half:del row['tail'][:-half]
            code=process.wait(timeout=1)
        finally:
            selector.close();process.stdout.close();process.stderr.close()
            if process.poll() is None:process.kill();process.wait(timeout=1)
        result={'exitCode':code,'timedOut':timed}
        for label,row in records.items():
            view=bytes(row['head']+row['tail'])
            # Small output's head/tail overlap; preserve exact small output by
            # trimming the duplicated overlap, including before acceptance.
            if row['bytes']<=row['cap']:
                overlap=max(0,len(row['head'])+len(row['tail'])-row['bytes'])
                view=bytes(row['head'])+bytes(row['tail'][overlap:])
            result[label]=view;result[label+'Facts']={'bytes':row['bytes'],'sha256':row['h'].hexdigest(),
                'truncated':row['bytes']>row['cap']}
        return result
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
        self.command_evidence=[];self.command_count=0;self.unit_issued=False;self.effect_intents=set();self.files=[];self.context=None;self.unit=None
        self.outputs=None;self.code=manifest['code'];self.created=False
    def admit_metadata_before_unit(self):
        require(self.metadata_admission is not None,'ci.native_metadata_context_unissued')
        try:return self.metadata_admission.run()
        except BaseException as error:
            code=str(error) if type(error).__module__=='ci_archive_policy' else 'metadata_process_or_context_failed'
            raise Refusal('ci.metadata_refused',{'subcheck':code[:96]}) from None
        finally:
            evidence=self.metadata_admission.evidence
            if evidence is not None:
                self.command_count+=1;self.command_evidence.append({'argv':evidence['argv'],'result':evidence['outcome']})
                self.command_evidence=self.command_evidence[-16:]
    def command(self,argv):
        result=self.ops.command(tuple(argv),5)
        # Preserve command identity and bounded bytes before exit/JSON judgement.
        self.command_count+=1
        self.command_evidence.append({'argv':list(argv),'result':result})
        self.command_evidence=self.command_evidence[-16:]
        require(result.get('timedOut') is False and type(result.get('exitCode')) is int and result['exitCode']==0,
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
        self.anchors=ci_anchors.Sources(self.ops,self.root,self.unit,context['bootId'],self.manifest['tools'].get('selinuxenabledSha256'),propagation_policy=context['mountPropagation']);self.anchors.before()
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
        require(value['type']==kind and type(value['data']) is list and len(value['data'])==1,'ci.typed_shape')
        return value['data'][0]
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
        setup={}
        if self.unit_issued and self.outputs is None:
            for name,kind in (('ExecMainCode','i'),('ExecMainStatus','i'),('Result','s')):
                try:setup[name]=self.typed('org.freedesktop.systemd1.Service',name,kind)
                except BaseException:setup[name]='unavailable'
        out=[]
        for row in self.command_evidence[-2:]:
            result=row['result']
            item={'argv':row['argv'][:8],'exitCode':result.get('exitCode'),'timedOut':result.get('timedOut')}
            for name in ('stdout','stderr'):
                raw=result.get(name,b'');view=raw if len(raw)<=512 else raw[:256]+raw[-256:]
                item[name]={'viewBase64':base64.b64encode(view).decode(),'capturedBytes':len(raw),
                            'source':result.get(name+'Facts',{})}
            out.append(item)
        return {'schema':'ci.fixed-command-evidence.v1','commandCount':self.command_count,'ownedSetup':setup,'commands':out}

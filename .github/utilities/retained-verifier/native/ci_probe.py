"""Disarmed factual admission for one owned non-root verifier process.

collect_and_validate(reader, expected) reads bounded host /proc metadata only
through the injected reader. It never starts a process/service, changes state,
connects to a socket or reads private input contents. NativeReader is inert on
construction and unavailable unless this module is separately memory-armed.
The expected mount roster MUST come from reviewed source/staging anchors, not
from copying the process's observed mount table into an allowlist.

Manager DynamicUser/property validation, ELF/runtime provenance and syscall
filter contents remain controller/source obligations. /proc proves numeric
identity and seccomp mode/count, not the origin of the UID or filter program.
"""
from __future__ import annotations

import errno
import os
import re
import stat
from pathlib import PurePosixPath
from ci_protocol import Refusal, require, sha, canonical

ARMED = False
EXPECTED_SCHEMA = 'openclaw.nonroot-verifier-probe-expected.v1'
FACT_SCHEMA = 'openclaw.nonroot-verifier-probe-facts.v1'
ENVIRONMENT = {'PATH': '/usr/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/'}
NAMESPACE_NAMES = ('mnt', 'net', 'ipc', 'pid', 'user', 'uts', 'cgroup')
EXPECTED_KEYS = {'schema','sessionId','bootId','pid','startTimeTicks','unitName','identityName',
    'invocationId','uid','gid','dynamicIdRange','cgroupPath','executable','jailRoot',
    'hostNamespaces','mounts','stdio','limits','environmentSha256','profileSha256'}
MOUNT_KEYS = {'role','target','fsroot','majorMinor','fsType','source','vfsOptions','fsOptions',
              'optionalFields','identity'}
IDENTITY_KEYS = {'dev','ino','type','mode','uid','gid'}
MOUNT_TARGETS = {'/','/run','/tmp','/var/tmp','/dev','/dev/mqueue','/proc','/sys','/input','/control','/code',
                 '/run/systemd/incoming'}
FIXED_ROLES = {'/':'jail_root','/tmp':'private_tmp','/var/tmp':'private_var_tmp',
               '/run/systemd/incoming':'systemd_incoming'}
LIMIT_KEYS = {'memoryMaxBytes','memorySwapMaxBytes','cpuQuota','cpuPeriod','pidsMax'}
CAP_KEYS = ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')
STATUS_REQUIRED = {'Name','State','Tgid','Pid','PPid','TracerPid','Uid','Gid','Groups','Threads',
                   'NoNewPrivs','Seccomp','Seccomp_filters',*CAP_KEYS}
MAX_PIDS = 4096
MAX_READS = 4500
MAX_BYTES = 20 * 1024 * 1024


def integer(value, low=0, high=(1 << 63)-1):
    return type(value) is int and low <= value <= high


def path(value):
    return (type(value) is str and 0 < len(value) <= 1024 and value.startswith('/')
            and '\x00' not in value and str(PurePosixPath(value)) == value
            and '..' not in PurePosixPath(value).parts)


def kind(mode):
    for label, check in (('directory',stat.S_ISDIR),('regular',stat.S_ISREG),('char',stat.S_ISCHR),
                         ('socket',stat.S_ISSOCK),('fifo',stat.S_ISFIFO),('block',stat.S_ISBLK),('symlink',stat.S_ISLNK)):
        if check(mode):return label
    return 'unknown'


def identity(info):
    return {'dev':info.st_dev,'ino':info.st_ino,'type':kind(info.st_mode),'mode':stat.S_IMODE(info.st_mode),
            'uid':info.st_uid,'gid':info.st_gid}


def closed(value, keys, code):
    require(type(value) is dict and set(value) == set(keys), code)


def positive_identity(value):
    closed(value, IDENTITY_KEYS, 'probe.expected_identity')
    require(all(integer(value[k]) for k in ('dev','ino','mode','uid','gid')) and value['ino'] > 0
            and value['type'] == 'directory' and value['mode'] <= 0o7777
            and value['uid'] == value['gid'] == 0, 'probe.expected_identity')


def tokens(value, code):
    require(type(value) is list and len(value) <= 32 and len(set(value)) == len(value)
            and all(type(v) is str and re.fullmatch(r'[A-Za-z0-9_.=:+-]{1,80}',v) for v in value),code)


def validate_expected(value):
    closed(value,EXPECTED_KEYS,'probe.expected_schema')
    require(value['schema'] == EXPECTED_SCHEMA,'probe.expected_schema')
    session = value['sessionId']
    require(type(session) is str and re.fullmatch('[0-9a-f]{32}',session)
            and value['unitName'] == 'ocv-'+session+'.service'
            and value['identityName'] == 'ocv-'+session[:24], 'probe.expected_session')
    require(type(value['bootId']) is str and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',value['bootId'])
            and type(value['invocationId']) is str and re.fullmatch('[0-9a-f]{32}',value['invocationId']),
            'probe.expected_generation')
    require(integer(value['pid'],2,4194304) and integer(value['startTimeTicks'],1)
            and value['dynamicIdRange'] == [61184,65519]
            and integer(value['uid'],61184,65519) and integer(value['gid'],61184,65519), 'probe.expected_dynamic_identity')
    require(value['cgroupPath'] == '/system.slice/'+value['unitName'], 'probe.expected_cgroup')
    for key in ('executable','jailRoot'):
        closed(value[key],{'path','dev','ino'},'probe.expected_path_identity')
        require(path(value[key]['path']) and integer(value[key]['dev']) and integer(value[key]['ino'],1),
                'probe.expected_path_identity')
    require(value['executable']['path'] == value['jailRoot']['path']+'/usr/bin/python3.11',
            'probe.expected_executable')
    require(value['jailRoot']['path'] != '/', 'probe.expected_jail')
    closed(value['hostNamespaces'],NAMESPACE_NAMES,'probe.expected_namespaces')
    require(all(integer(n,1) for n in value['hostNamespaces'].values()), 'probe.expected_namespaces')
    require(type(value['mounts']) is list and 4 <= len(value['mounts']) <= 32, 'probe.expected_mounts')
    seen = set()
    for row in value['mounts']:
        closed(row,MOUNT_KEYS,'probe.expected_mounts')
        require(type(row['role']) is str and re.fullmatch('[a-z][a-z0-9_]{0,39}',row['role'])
                and path(row['target']) and row['target'] not in seen and path(row['fsroot'])
                and type(row['majorMinor']) is str and re.fullmatch(r'(0|[1-9][0-9]*):(0|[1-9][0-9]*)',row['majorMinor'])
                and row['fsType'] in ('ext4','tmpfs') and type(row['source']) is str
                and 0 < len(row['source']) <= 1024 and '\x00' not in row['source'], 'probe.expected_mounts')
        seen.add(row['target']);positive_identity(row['identity'])
        for label in ('vfsOptions','fsOptions','optionalFields'):tokens(row[label],'probe.expected_mount_flags')
        require('ro' in row['vfsOptions'] and 'rw' not in row['vfsOptions']
                and not any(x.startswith('shared:') for x in row['optionalFields']), 'probe.expected_mount_flags')
        if row['target'] in FIXED_ROLES:
            require(row['role'] == FIXED_ROLES[row['target']], 'probe.expected_mount_role')
        if row['target'] in ('/input','/control'):
            require('noexec' in row['vfsOptions'], 'probe.expected_mount_flags')
        if row['target'] == '/input':require(row['identity']['mode'] == 0,'probe.expected_input_closed')
        if row['target'] == '/run/systemd/incoming':
            require(row['identity']['mode'] & 0o077 == 0,'probe.expected_incoming')
    # The profile declares these mounts positively. No arbitrary descendant
    # mounts or omitted private-tmp/incoming exceptions may be admitted.
    require(seen == MOUNT_TARGETS,'probe.expected_mount_roster')
    closed(value['stdio'],('stdin','stdout','stderr'),'probe.expected_stdio')
    for label, row in value['stdio'].items():
        closed(row,{'dev','ino','rdev'} if label == 'stdin' else {'dev','ino'},'probe.expected_stdio')
        require(all(integer(v) for v in row.values()) and row['ino'] > 0,'probe.expected_stdio')
    require(value['stdio']['stdin']['rdev'] == os.makedev(1,3),'probe.expected_null')
    require(value['stdio']['stdout'] != value['stdio']['stderr'],'probe.expected_distinct_outputs')
    closed(value['limits'],LIMIT_KEYS,'probe.expected_limits')
    require(value['limits'] == {'memoryMaxBytes':2147483648,'memorySwapMaxBytes':0,
        'cpuQuota':100000,'cpuPeriod':100000,'pidsMax':64},'probe.expected_limits')
    require(value['environmentSha256'] == sha(canonical(ENVIRONMENT)), 'probe.expected_environment')
    require(type(value['profileSha256']) is str and re.fullmatch('[0-9a-f]{64}',value['profileSha256']),
            'probe.expected_profile')


class NativeReader:
    """No reads occur on import/construction. Caller must separately arm."""
    def __init__(self):require(ARMED is True,'probe.disarmed')
    def read(self, filename, cap):
        fd = os.open(filename, os.O_RDONLY | os.O_CLOEXEC)
        try:
            parts=[];total=0
            for _ in range(4096):
                raw=os.read(fd,min(65536,cap+1-total))
                require(type(raw) is bytes,'probe.read_type')
                if not raw:return b''.join(parts)
                parts.append(raw);total+=len(raw);require(total<=cap,'probe.read_cap')
            raise Refusal('probe.read_budget')
        finally:os.close(fd)
    def readlink(self, filename):return os.readlink(filename)
    def stat(self, filename):return os.stat(filename)
    def listdir(self, filename, cap):
        require(integer(cap,0,MAX_PIDS+64),'probe.directory_cap')
        result=[]
        with os.scandir(filename) as entries:
            for item in entries:
                require(len(result)<cap,'probe.directory_roster')
                result.append(item.name)
        return result


class Observation:
    def __init__(self,reader):self.reader=reader;self.records=[];self.reads=0;self.bytes=0;self.role='entry';self.omitted=0
    def add(self,role,**fields):
        self.role=role
        def bounded(value,depth=0):
            if type(value) in (bool,int) or value is None:return value
            if type(value) is str:
                return value if len(value)<=128 else {'prefix':value[:128],'bytes':len(value.encode()),'sha256':sha(value.encode())}
            if type(value) is list and depth<3:return [bounded(v,depth+1) for v in value[:12]]+([{'truncatedEntries':len(value)-12}] if len(value)>12 else [])
            if type(value) is dict and depth<3:return {k:bounded(v,depth+1) for k,v in list(value.items())[:16]}
            return 'unavailable'
        record={'role':role,'facts':bounded(fields)}
        if len(canonical(record))>2500:
            record={'role':role,'facts':{'truncated':True,'originalFactsSha256':sha(canonical(record)),
                                      'keys':sorted(fields),'observationTooLarge':True}}
        self.records.append(record)
        while len(self.records)>32 or len(canonical(self.records))>6500:
            self.records.pop(0);self.omitted+=1
    def fail(self,error):
        code=error.code if isinstance(error,Refusal) else 'probe.observation_failed'
        num=getattr(error,'errno',None)
        self.add(self.role,operation='failed',errno=num if integer(num,1,4095) else None)
        return Refusal(code,{'schema':'openclaw.nonroot-probe-failure.v1','failedRole':self.role,
            'records':self.records,'omittedRecords':self.omitted,'readCalls':self.reads,'readBytes':self.bytes})
    def read(self,path,cap,role):
        self.role=role;self.reads+=1;require(self.reads<=MAX_READS,'probe.read_budget')
        raw=self.reader.read(path,cap)
        require(type(raw) is bytes and len(raw)<=cap,'probe.read_cap')
        self.bytes+=len(raw);require(self.bytes<=MAX_BYTES,'probe.total_read_cap')
        self.add(role,bytes=len(raw),sha256=sha(raw))
        return raw
    def text(self,path,cap,role):
        raw=self.read(path,cap,role)
        try:return raw.decode('ascii','strict')
        except UnicodeError:raise Refusal('probe.ascii') from None
    def link(self,path,role):
        self.role=role;value=self.reader.readlink(path)
        require(type(value) is str and 0<len(value)<=2048 and '\x00' not in value,'probe.link_shape')
        self.add(role,bytes=len(value),sha256=sha(value.encode()))
        return value
    def stat(self,path,role):
        self.role=role;info=self.reader.stat(path);self.add(role,**identity(info));return info
    def names(self,path,cap,role):
        self.role=role;rows=self.reader.listdir(path,cap)
        require(type(rows) is list and len(rows)<=cap and all(type(x) is str for x in rows)
                and len(set(rows))==len(rows),'probe.directory_roster')
        self.add(role,count=len(rows));return rows


def proc_stat(raw,pid):
    require(type(raw) is str and len(raw)<=8192 and raw.endswith('\n') and raw.count('\n')==1,
            'probe.stat_shape')
    end=raw.rfind(')');start=raw.find(' (')
    require(start>0 and end>start and raw[:start]==str(pid),'probe.stat_pid')
    fields=raw[end+2:].strip().split()
    require(len(fields)>=50 and len(fields[0])==1 and fields[0] in 'RSDI'
            and all(re.fullmatch(r'-?\d+',x) for x in fields[1:]),'probe.stat_shape')
    require(int(fields[19])>0,'probe.stat_start')
    return {'pid':pid,'state':fields[0],'parentPid':int(fields[1]),'startTimeTicks':int(fields[19])}


def status(raw, *, full=True):
    require(type(raw) is str and raw.endswith('\n'),'probe.status_shape')
    rows={}
    for line in raw.splitlines():
        require(':' in line,'probe.status_shape');key,value=line.split(':',1)
        require(re.fullmatch('[A-Za-z_0-9]+',key) and key not in rows,'probe.status_duplicate')
        rows[key]=value.strip()
    require((STATUS_REQUIRED if full else {'Uid','Gid'})<=set(rows),'probe.status_missing')
    for key in ('Uid','Gid'):
        values=rows[key].split();require(len(values)==4 and all(re.fullmatch(r'0|[1-9]\d*',v) for v in values),'probe.status_ids')
        rows[key]=[int(v) for v in values]
    return rows


def mount_table(raw):
    require(type(raw) is str and len(raw)<=1048576 and raw.endswith('\n'),'probe.mount_cap')
    lines=raw.splitlines();require(0<len(lines)<=4096,'probe.mount_cap')
    rows=[];ids=set();targets=set()
    def unescape(value):
        replacements={'040':' ','011':'\t','012':'\n','134':'\\'}
        require(re.search(r'\\(?!040|011|012|134)',value) is None,'probe.mount_escape')
        return re.sub(r'\\(040|011|012|134)',lambda m:replacements[m.group(1)],value)
    for line in lines:
        values=line.split(' ');require(values.count('-')==1,'probe.mount_shape');split=values.index('-')
        require(split>=6 and len(values)==split+4 and all(re.fullmatch(r'[1-9]\d*',v) for v in values[:2])
                and re.fullmatch(r'(0|[1-9]\d*):(0|[1-9]\d*)',values[2]),'probe.mount_shape')
        mount_id=int(values[0]);parent_id=int(values[1]);target=unescape(values[4]);root=unescape(values[3])
        require(mount_id not in ids and target not in targets and path(target) and path(root),'probe.mount_stacked_or_invalid')
        ids.add(mount_id);targets.add(target)
        vfs=values[5].split(',');fs=values[split+3].split(',');optional=values[6:split]
        for wordlist in (vfs,fs,optional):tokens(wordlist,'probe.mount_flags')
        require(all(re.fullmatch(r'(?:shared|master|propagate_from):[1-9]\d*|unbindable',v) for v in optional),
                'probe.mount_optional')
        rows.append({'mountId':mount_id,'parentId':parent_id,'target':target,'fsroot':root,'majorMinor':values[2],
            'fsType':values[split+1],'source':unescape(values[split+2]),'vfsOptions':sorted(vfs),
            'fsOptions':sorted(fs),'optionalFields':sorted(optional)})
    return rows


def fdinfo(raw):
    rows={}
    for line in raw.splitlines():
        require(':' in line,'probe.fdinfo_shape');key,value=line.split(':',1)
        require(key not in rows,'probe.fdinfo_duplicate');rows[key]=value.strip()
    require({'pos','flags','mnt_id','ino'}<=set(rows) and re.fullmatch('[0-7]+',rows['flags'])
            and all(re.fullmatch(r'0|[1-9]\d*',rows[k]) for k in ('pos','mnt_id','ino')),'probe.fdinfo_shape')
    return {'flags':int(rows['flags'],8),'pos':int(rows['pos']),'mountId':int(rows['mnt_id']),'ino':int(rows['ino'])}


def _snapshot(obs,expected,label):
    base='/proc/'+str(expected['pid'])
    generation=proc_stat(obs.text(base+'/stat',8192,label+'.stat'),expected['pid'])
    current=status(obs.text(base+'/status',16384,label+'.status'))
    require(generation['startTimeTicks']==expected['startTimeTicks'],'probe.pid_generation_changed')
    require(current['Pid']==current['Tgid']==str(expected['pid']) and current['TracerPid']=='0'
            and current['Threads']=='1','probe.process_shape')
    require(current['Uid']==[expected['uid']]*4 and current['Gid']==[expected['gid']]*4,'probe.identity_changed')
    require(current['Groups']=='','probe.supplementary_groups')
    require(current['NoNewPrivs']=='1' and current['Seccomp']=='2'
            and re.fullmatch('[1-9]\d*',current['Seccomp_filters']),'probe.process_filters')
    require(all(re.fullmatch('[0-9A-Fa-f]{1,16}',current[k]) and int(current[k],16)==0 for k in CAP_KEYS),'probe.capabilities')
    group=obs.text(base+'/cgroup',4096,label+'.cgroup')
    require(group=='0::'+expected['cgroupPath']+'\n','probe.cgroup_changed')
    obs.add(label+'.identity',pid=expected['pid'],startTimeTicks=generation['startTimeTicks'],uid=current['Uid'],gid=current['Gid'],
            supplementaryGroupCount=0,capabilitiesZero=True,noNewPrivileges=1,seccompMode=2,seccompFilterCount=int(current['Seccomp_filters']))
    namespace={}
    for name in NAMESPACE_NAMES:
        value=obs.link(base+'/ns/'+name,label+'.namespace.'+name)
        match=re.fullmatch(name+r':\[([1-9]\d*)\]',value);require(match is not None,'probe.namespace_shape')
        namespace[name]=int(match[1])
        require((namespace[name]!=expected['hostNamespaces'][name]) if name in ('mnt','net','ipc')
                else (namespace[name]==expected['hostNamespaces'][name]),'probe.namespace_shared_or_changed')
    return {'generation':{k:generation[k] for k in ('pid','parentPid','startTimeTicks')},'ids':{'uid':current['Uid'],'gid':current['Gid']},
            'caps':{k:current[k] for k in CAP_KEYS},'nnp':current['NoNewPrivs'],'seccomp':current['Seccomp'],
            'filters':current['Seccomp_filters'],'cgroup':group,'namespaces':namespace}


def collect_and_validate(reader,expected):
    """Return positive measured proof or Refusal with bounded private facts.

    Expected IDs/invocation/profile and source-derived mount entries are issued
    by the trusted host controller after its independent unit-properties read.
    A caller's desired facts, worker-echoed roster or a boolean passed verdict
    are not suitable expected evidence. Live qualification is still mandatory.
    """
    obs=Observation(reader)
    try:
        validate_expected(expected)
        base='/proc/'+str(expected['pid'])
        boot=obs.text('/proc/sys/kernel/random/boot_id',128,'boot').strip()
        require(boot==expected['bootId'],'probe.boot_changed')
        first=_snapshot(obs,expected,'before')
        pids=obs.names('/proc',MAX_PIDS+64,'peer_roster.before')
        peers=sorted(int(x) for x in pids if re.fullmatch('[1-9]\d*',x))
        require(0<len(peers)<=MAX_PIDS and expected['pid'] in peers,'probe.peer_roster')
        for index,pid in enumerate(peers):
            if pid==expected['pid']:continue
            peer=status(obs.text('/proc/'+str(pid)+'/status',16384,'peer.status'),full=False)
            require(expected['uid'] not in peer['Uid'] and expected['gid'] not in peer['Gid'],'probe.shared_dynamic_identity')
        obs.add('peer_exclusivity',processesChecked=len(peers),matchingPeers=0)
        exe=obs.link(base+'/exe','executable.path');exei=obs.stat(base+'/exe','executable.identity')
        require(exe==expected['executable']['path'] and stat.S_ISREG(exei.st_mode)
                and exei.st_dev==expected['executable']['dev'] and exei.st_ino==expected['executable']['ino']
                and exei.st_uid==exei.st_gid==0 and not stat.S_IMODE(exei.st_mode)&0o022,'probe.executable_changed')
        jail=obs.link(base+'/root','jail.path');ji=obs.stat(base+'/root','jail.identity')
        require(jail==expected['jailRoot']['path'] and stat.S_ISDIR(ji.st_mode)
                and ji.st_dev==expected['jailRoot']['dev'] and ji.st_ino==expected['jailRoot']['ino']
                and ji.st_uid==ji.st_gid==0,'probe.jail_changed')
        require(obs.link(base+'/cwd','cwd.path')==jail,'probe.cwd_changed')
        environment=obs.read(base+'/environ',8192,'environment')
        require(environment.endswith(b'\0') and environment.count(b'\0')==4,'probe.environment_closed')
        parts=environment[:-1].split(b'\0');env={}
        for row in parts:
            require(row.count(b'=')==1,'probe.environment_closed')
            key,val=row.split(b'=',1);require(key not in env,'probe.environment_duplicate');env[key]=val
        fixed={k.encode():v.encode() for k,v in ENVIRONMENT.items()}
        require(env==fixed,'probe.environment_closed')
        env_proof={'entryCount':4,'bytes':len(environment),'sha256':sha(environment),
                   'canonicalSha256':sha(canonical(ENVIRONMENT))}
        mounts=mount_table(obs.text(base+'/mountinfo',1048576,'mounts'))
        require(len(mounts)==len(expected['mounts']),'probe.mount_roster_changed')
        indexed={r['target']:r for r in mounts};positive=[]
        for row in expected['mounts']:
            role='mount.'+row['role'];obs.role=role
            require(row['target'] in indexed,'probe.mount_missing');actual=indexed[row['target']]
            obs.add(role,observed={k:actual[k] for k in ('mountId','fsroot','majorMinor','fsType','source','vfsOptions','fsOptions','optionalFields')})
            require(all(actual[k]==sorted(row[k]) if k in ('vfsOptions','fsOptions','optionalFields') else actual[k]==row[k]
                        for k in ('fsroot','majorMinor','fsType','source','vfsOptions','fsOptions','optionalFields')),'probe.mount_source_or_flags')
            info=obs.stat(base+'/root'+('' if row['target']=='/' else row['target']),role+'.identity')
            require(identity(info)==row['identity'],'probe.mount_identity')
            require(str(os.major(info.st_dev))+':'+str(os.minor(info.st_dev))==row['majorMinor'],'probe.mount_device')
            if row['role'] in ('private_tmp','private_var_tmp','systemd_incoming'):
                require(obs.names(base+'/root'+row['target'],128,role+'.empty')==[],'probe.mount_exception_not_empty')
            positive.append({**actual,'role':row['role'],'identity':identity(info)})
        root_mount=indexed['/'];require(root_mount['majorMinor']==str(os.major(ji.st_dev))+':'+str(os.minor(ji.st_dev))
            and next(r for r in expected['mounts'] if r['target']=='/')['identity']['ino']==ji.st_ino,'probe.jail_mount_join')
        dev=obs.text(base+'/net/dev',16384,'network.interfaces')
        interfaces=[r.split(':',1)[0].strip() for r in dev.splitlines() if ':' in r]
        require(interfaces==['lo'],'probe.external_interface')
        for table in ('route','ipv6_route'):
            raw=obs.text(base+'/net/'+table,16384,'network.'+table)
            if table=='route':
                lines=raw.splitlines();require(lines and lines[0].split()[:3]==['Iface','Destination','Gateway'],'probe.route_shape')
                for line in lines[1:]:
                    if not line.strip():continue
                    cols=line.split();require(len(cols)==11 and cols[0]=='lo' and cols[2]=='00000000'
                        and re.fullmatch('[0-9A-Fa-f]{8}',cols[1]) and int(cols[1],16)&255==127
                        and re.fullmatch('[0-9A-Fa-f]{8}',cols[7]) and int(cols[7],16)!=0,'probe.external_route')
            else:
                for line in raw.splitlines():
                    cols=line.split();require(len(cols)==10 and cols[-1]=='lo'
                        and cols[0]=='00000000000000000000000000000001' and cols[1]=='80'
                        and cols[4]=='0'*32,'probe.external_ipv6_route')
        cg='/sys/fs/cgroup'+expected['cgroupPath'];limits={}
        for key,leaf in (('memoryMaxBytes','memory.max'),('memorySwapMaxBytes','memory.swap.max'),('pidsMax','pids.max')):
            raw=obs.text(cg+'/'+leaf,128,'cgroup.'+leaf).strip()
            require(re.fullmatch(r'0|[1-9]\d*',raw) is not None,'probe.cgroup_limit_shape');limits[key]=int(raw)
        cpu=obs.text(cg+'/cpu.max',128,'cgroup.cpu.max').split()
        require(len(cpu)==2 and all(re.fullmatch('[1-9]\d*',v) for v in cpu),'probe.cgroup_limit_shape')
        limits.update(cpuQuota=int(cpu[0]),cpuPeriod=int(cpu[1]))
        require(limits==expected['limits'],'probe.cgroup_limits')
        require(obs.text(cg+'/pids.current',128,'cgroup.pids.current').strip()=='1','probe.cgroup_peers')
        require(obs.text(base+'/task/'+str(expected['pid'])+'/children',4096,'children').strip()=='','probe.children')
        require(obs.names(base+'/task',64,'threads')==[str(expected['pid'])],'probe.thread_roster')
        fds=obs.names(base+'/fd',16,'fd.roster');require(set(fds)=={'0','1','2'},'probe.extra_descriptor')
        fd_facts={}
        for number,label in ((0,'stdin'),(1,'stdout'),(2,'stderr')):
            role='fd.'+label;info=obs.stat(base+'/fd/'+str(number),role+'.identity')
            record=fdinfo(obs.text(base+'/fdinfo/'+str(number),4096,role+'.flags'))
            obs.add(role,flags=record['flags'],pos=record['pos'],**identity(info))
            want=expected['stdio'][label]
            require(info.st_dev==want['dev'] and info.st_ino==want['ino'] and record['ino']==info.st_ino,'probe.stdio_inode')
            if number==0:
                require(stat.S_ISCHR(info.st_mode) and info.st_rdev==want['rdev']
                    and record['flags'] in (os.O_RDONLY,os.O_RDONLY|0o100000),'probe.stdin_authority')
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0
                    and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1 and 0<=info.st_size<=65536
                    and record['flags'] in (os.O_WRONLY|os.O_APPEND,os.O_WRONLY|os.O_APPEND|0o100000),
                    'probe.output_authority')
            fd_facts[label]={**identity(info),'rdev':info.st_rdev,'flags':record['flags'],'mountId':record['mountId'],
                             'nlink':info.st_nlink,'size':info.st_size}
        final_pids=obs.names('/proc',MAX_PIDS+64,'peer_roster.after')
        require(peers==sorted(int(x) for x in final_pids if re.fullmatch('[1-9]\d*',x)), 'probe.peer_roster_changed')
        # Recheck objects/FD flags/mount/env after the initial collection as well
        # as PID generation, so a same-PID exec/view transition cannot pass.
        require(obs.link(base+'/exe','stable.executable')==exe and obs.link(base+'/root','stable.root')==jail
                and obs.link(base+'/cwd','stable.cwd')==jail,'probe.unstable_object')
        require(obs.read(base+'/environ',8192,'stable.environment')==environment,'probe.unstable_environment')
        require(mount_table(obs.text(base+'/mountinfo',1048576,'stable.mounts'))==mounts,'probe.unstable_mounts')
        require(set(obs.names(base+'/fd',16,'stable.fd.roster'))=={'0','1','2'},'probe.unstable_descriptors')
        for number,label in ((0,'stdin'),(1,'stdout'),(2,'stderr')):
            info=obs.stat(base+'/fd/'+str(number),'stable.fd.'+label)
            record=fdinfo(obs.text(base+'/fdinfo/'+str(number),4096,'stable.fdinfo.'+label))
            require(identity(info)=={k:fd_facts[label][k] for k in IDENTITY_KEYS}
                    and info.st_rdev==fd_facts[label]['rdev'] and info.st_nlink==fd_facts[label]['nlink']
                    and record['flags']==fd_facts[label]['flags'] and record['mountId']==fd_facts[label]['mountId'],
                    'probe.unstable_descriptors')
        after=_snapshot(obs,expected,'after')
        require(first==after,'probe.unstable_tuple')
        facts={'schema':FACT_SCHEMA,'sessionId':expected['sessionId'],'bootId':boot,'pid':expected['pid'],
            'startTimeTicks':expected['startTimeTicks'],'uid':expected['uid'],'gid':expected['gid'],
            'invocationId':expected['invocationId'],'unitName':expected['unitName'],'identityName':expected['identityName'],
            'profileSha256':expected['profileSha256'],'cgroupPath':expected['cgroupPath'],'namespaces':first['namespaces'],
            'seccompMode':2,'seccompFilterCount':int(first['filters']),'capabilitySets':{k:0 for k in CAP_KEYS},
            'noNewPrivileges':1,'supplementaryGroups':[],'peerProcessesChecked':len(peers),
            'executable':{'dev':exei.st_dev,'ino':exei.st_ino},'jailRoot':{'dev':ji.st_dev,'ino':ji.st_ino},
            'mounts':positive,'environment':env_proof,'limits':limits,'stdio':fd_facts,'children':[],
            'stableTuple':True,'readCalls':obs.reads,'readBytes':obs.bytes}
        require(len(canonical(facts))<=10000,'probe.facts_cap')
        facts['factsSha256']=sha(canonical(facts));return facts
    except BaseException as error:
        raise obs.fail(error) from None


def main(_argv=None):
    require(ARMED is True,'probe.disarmed')
    # There is deliberately no standalone live CLI. The reviewed host
    # controller must supply exact expected anchors and its owned reader.
    raise Refusal('probe.controller_required')


if __name__=='__main__':main()

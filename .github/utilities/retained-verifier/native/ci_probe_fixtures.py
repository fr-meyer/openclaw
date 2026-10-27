"""Extracted unchanged public synthetic fact builders; no host reads."""
import os
import stat
import types
import ci_probe as p
from ci_protocol import canonical,sha

def metadata(kind,mode=0o755,*,dev=None,ino=1,uid=0,gid=0,rdev=0,nlink=1,size=0):
    return types.SimpleNamespace(st_mode=kind|mode,st_dev=os.makedev(8,1) if dev is None else dev,
        st_ino=ino,st_uid=uid,st_gid=gid,st_rdev=rdev,st_nlink=nlink,st_size=size)

def stat_line(pid,ticks=500,state='S',parent=1):
    # Linux proc_pid_stat fields3..52; comm deliberately includes parentheses.
    values=[state]+['0']*49;values[1]=str(parent);values[19]=str(ticks)
    return f'{pid} (python (worker)) '+ ' '.join(values)+'\n'

def status_line(pid,uid=61200,gid=61200):
    return (f'Name:\tpython3\nState:\tS (sleeping)\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t1\n'
        f'TracerPid:\t0\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{gid}\t{gid}\t{gid}\t{gid}\nGroups:\t{gid}\nThreads:\t1\n'
        'NoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n'+''.join(k+':\t0000000000000000\n' for k in p.CAP_KEYS))

def expected_fixture():
    session='a'*32;jail='/synthetic/verifier/nonroot/'+session+'/root';dev=os.makedev(8,1)
    rows=[];inherited=[]
    for index,target in enumerate(sorted(p.MOUNT_TARGETS)):
        role=p.FIXED_ROLES.get(target,target[1:].replace('/','_'))
        flags=['ro','nosuid','nodev']
        if target in ('/input','/control'):flags.append('noexec')
        root=jail+('' if target=='/' else target);device=dev;ino=100+index;mode=0o755
        if target=='/':ino=100
        if target in ('/tmp','/var/tmp'):root='/tmp/systemd-private-session-'+role+'/tmp';mode=0o1777
        if target=='/run/systemd/incoming':root='/systemd/unit-root/incoming';device=os.makedev(0,20);mode=0o700
        if target=='/input':mode=0
        rows.append({'role':role,'target':target,'fsroot':root,'majorMinor':str(os.major(device))+':'+str(os.minor(device)),
            'fsType':'tmpfs' if target=='/run/systemd/incoming' else 'ext4','source':'tmpfs' if target=='/run/systemd/incoming' else '/dev/sda1',
            'vfsOptions':flags,'fsOptions':['rw'],'optionalFields':[],
            'identity':{'dev':device,'ino':ino,'type':'directory','mode':mode,'uid':0,'gid':0}})
    for index,target in enumerate(sorted(p.INHERITED_TARGETS)):
        inherited.append({'target':target,'identity':{'dev':dev,'ino':200+index,
            'type':'directory','mode':0o755,'uid':0,'gid':0}})
    return {'schema':p.EXPECTED_SCHEMA,'sessionId':session,'bootId':'aaaabbbb-1234-5678-9abc-123456789abc',
        'pid':77,'startTimeTicks':500,'unitName':'ocv-'+session+'.service','identityName':'ocv-'+session[:24],
        'invocationId':'b'*32,'uid':61200,'gid':61200,'dynamicIdRange':[61184,65519],
        'cgroupPath':'/system.slice/ocv-'+session+'.service',
        'executable':{'path':jail+'/usr/bin/python3.11','dev':dev,'ino':999},'jailRoot':{'path':jail,'dev':dev,'ino':100},
        'hostNamespaces':dict(zip(p.NAMESPACE_NAMES,range(10,17))),'mounts':rows,
        'inheritedPaths':inherited,
        'stdio':{'stdin':{'dev':os.makedev(0,5),'ino':1,'rdev':os.makedev(1,3)},
                 'stdout':{'dev':dev,'ino':1000},'stderr':{'dev':dev,'ino':1001}},
        'limits':{'memoryMaxBytes':2147483648,'memorySwapMaxBytes':0,'cpuQuota':100000,'cpuPeriod':100000,'pidsMax':64},
        'environmentSha256':sha(canonical(p.ENVIRONMENT)),'profileSha256':'c'*64}

class FixtureReader:
    """A fixed in-memory file/metadata reader; every path must be fixture-bound."""
    def __init__(self,expected):
        self.expected=expected;self.data={};self.links={};self.stats={};self.directories={};self.calls=[]
        base='/proc/77';cg='/sys/fs/cgroup'+expected['cgroupPath'];jail=expected['jailRoot']['path']
        self.data.update({'/proc/sys/kernel/random/boot_id':(expected['bootId']+'\n').encode(),base+'/stat':stat_line(77).encode(),
            base+'/status':status_line(77).encode(),base+'/cgroup':('0::'+expected['cgroupPath']+'\n').encode(),
            '/proc/1/status':status_line(1,0,0).encode(),base+'/environ':b'PATH=/usr/bin\0LANG=C\0LC_ALL=C\0HOME=/\0',
            base+'/net/dev':b'Inter-| Receive\n face |bytes\n lo: 0 0 0 0\n',
            base+'/net/route':b'Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n',
            base+'/net/ipv6_route':b'',base+'/task/77/children':b'',
            cg+'/memory.max':b'2147483648\n',cg+'/memory.swap.max':b'0\n',cg+'/cpu.max':b'100000 100000\n',
            cg+'/pids.max':b'64\n',cg+'/pids.current':b'1\n'})
        self.directories.update({'/proc':['1','77','self','net'],base+'/fd':['0','1','2'],base+'/task':['77']})
        self.links.update({base+'/exe':'/usr/bin/python3.11',base+'/root':'/',base+'/cwd':'/'})
        self.stats.update({base+'/exe':metadata(stat.S_IFREG,0o755,dev=expected['executable']['dev'],ino=999),
                           base+'/root':metadata(stat.S_IFDIR,0o755,ino=100)})
        for name,host in expected['hostNamespaces'].items():self.links[base+'/ns/'+name]=name+':['+str(host+100 if name in ('mnt','net','ipc') else host)+']'
        lines=[]
        for index,row in enumerate(expected['mounts']):
            target=row['target'];ident=row['identity'];where=base+'/root'+('' if target=='/' else target)
            self.stats[where]=metadata(stat.S_IFDIR,ident['mode'],dev=ident['dev'],ino=ident['ino'])
            if row['role'] in ('private_tmp','private_var_tmp','systemd_incoming'):self.directories[base+'/root'+target]=[]
            lines.append(f'{index+100} 99 {row["majorMinor"]} {row["fsroot"]} {target} '+','.join(row['vfsOptions'])+' - '+row['fsType']+' '+row['source']+' '+','.join(row['fsOptions'])+'\n')
        for row in expected['inheritedPaths']:
            ident=row['identity'];where=base+'/root'+row['target']
            self.stats[where]=metadata(stat.S_IFDIR,ident['mode'],dev=ident['dev'],ino=ident['ino'])
        self.data[base+'/mountinfo']=''.join(lines).encode()
        for number,label in ((0,'stdin'),(1,'stdout'),(2,'stderr')):
            record=expected['stdio'][label];flags=0o100000 if number==0 else os.O_WRONLY|os.O_APPEND|0o100000
            self.stats[base+'/fd/'+str(number)]=metadata(stat.S_IFCHR if number==0 else stat.S_IFREG,
                0o666 if number==0 else 0o600,dev=record['dev'],ino=record['ino'],rdev=record.get('rdev',0),size=0)
            self.data[base+'/fdinfo/'+str(number)]=f'pos:\t0\nflags:\t{flags:o}\nmnt_id:\t900\nino:\t{record["ino"]}\n'.encode()
    def value(self,collection,path):
        value=collection[path]
        if isinstance(value,Exception):raise value
        if callable(value):return value()
        return value
    def read(self,path,cap):self.calls.append(('read',path,cap));return self.value(self.data,path)
    def readlink(self,path):self.calls.append(('readlink',path));return self.value(self.links,path)
    def stat(self,path):self.calls.append(('stat',path));return self.value(self.stats,path)
    def listdir(self,path,cap):self.calls.append(('listdir',path));return self.value(self.directories,path)

"""Independent manager-namespace mount anchors. Injected ops only; no CLI.

Source: systemd252.39 PrivateTmp/incoming paths and known RO/nosuid/noexec
transformations. Unknown SELinux/propagation/host visibility refuses. Child
mountinfo is never an input to this expected-roster collector.
"""
import re
import stat
from pathlib import PurePosixPath
import ci_probe as probe
from ci_protocol import Refusal,require

MS_PRIVATE=262144
MS_SHARED=1048576


def ident(info):return probe.identity(info)


class Sources:
    def __init__(self,ops,root,unit,boot_id,selinux_tool_sha256,*,propagation_policy):
        self.ops,self.root,self.unit,self.boot=ops,root,unit,boot_id
        self.selinux_tool_sha=selinux_tool_sha256
        require(propagation_policy=='private','ci.private_policy_required')
        self.propagation_policy=propagation_policy;self.host_propagation={}
        require(re.fullmatch('ocv-[0-9a-f]{32}\\.service',unit) and
          re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot_id),'ci.anchor_context')
        self.prefix='systemd-private-'+boot_id.replace('-','')+'-'+unit+'-'
        self.incoming='/run/systemd/propagate/'+unit;self.prepared=False;self.original={}
    def namespaces(self):
        rows={}
        for name in ('mnt','user'):
            own=self.ops.readlink('/proc/self/ns/'+name);manager=self.ops.readlink('/proc/1/ns/'+name)
            require(own==manager and re.fullmatch(name+r':\[[1-9][0-9]*\]',own),'ci.manager_namespace_changed')
            rows[name]=own
        return rows
    def trusted(self,path,*,mode=None):
        p=PurePosixPath(path);require(p.is_absolute() and str(p)==path and '..' not in p.parts,'ci.anchor_path')
        current='/'
        for part in ('',)+p.parts[1:]:
            if part:current=current.rstrip('/')+'/'+part
            info=self.ops.lstat(current)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0,'ci.anchor_owner_type')
            bits=stat.S_IMODE(info.st_mode)
            require(not bits&0o022 or (current in ('/tmp','/var/tmp') and bits==0o1777) or (current==path and mode==0o1777 and bits==0o1777),'ci.anchor_parent_writable')
        if mode is not None:require(stat.S_IMODE(info.st_mode)==mode,'ci.anchor_mode')
        return info
    def roster(self,parent):
        names=self.ops.listdir(parent,4096)
        require(type(names) is list and len(names)<=4096,'ci.anchor_roster_cap')
        prefix=self.prefix
        matches=[n for n in names if type(n) is str and n.startswith(prefix)]
        require(all(re.fullmatch(re.escape(prefix)+r'[A-Za-z0-9]{6}',n) for n in matches),'ci.anchor_roster_name')
        return matches
    def before(self):
        require(not self.prepared,'ci.anchor_before_once');self.prepared=True
        self.manager=self.namespaces()
        for p in ('/tmp','/var/tmp'):
            self.trusted(p,mode=0o1777);require(self.roster(p)==[],'ci.anchor_preexisting_private_tmp')
        self.trusted('/run/systemd')
        try:self.ops.lstat('/run/systemd/propagate')
        except FileNotFoundError:pass  # Manager may create this fixed parent on first use.
        else:self.trusted('/run/systemd/propagate')
        try:self.ops.lstat(self.incoming)
        except FileNotFoundError:pass
        else:raise Refusal('ci.anchor_preexisting_incoming')
        # Fixed read-only recognized query. Never disable SELinux or infer its
        # state from caller JSON/absence. Tool bytes are bound by the CI lock.
        from ci_protocol import sha
        require(type(self.selinux_tool_sha) is str and re.fullmatch('[0-9a-f]{64}',self.selinux_tool_sha),
                'ci.selinux_tool_pin_unbound')
        require(sha(self.ops.read('/usr/sbin/selinuxenabled',1048576))==self.selinux_tool_sha,'ci.selinux_tool_changed')
        from ci_native_port import command_boundary_refusal,command_capture_ok
        try:result=self.ops.command(('/usr/sbin/selinuxenabled',),5)
        except BaseException as error:result=command_boundary_refusal(error)
        self.selinux_evidence=result
        require(command_capture_ok(result),'ci.selinux_capture_refused')
        require(result.get('timedOut') is False and type(result.get('exitCode')) is int and result['exitCode'] in (0,1) and
          all(result.get(k,{}).get('truncated') is False for k in ('stdoutFacts','stderrFacts')),'ci.selinux_query_unknown')
        self.add_nosuid=result['exitCode']==1
        require(self.namespaces()==self.manager,'ci.manager_namespace_changed')
    def covering(self,path):
        rows=[r for r in self.host_mounts if path==r['target'] or path.startswith(r['target'].rstrip('/')+'/')]
        require(rows,'ci.anchor_mount_missing');row=max(rows,key=lambda r:len(r['target']))
        # Source-backed explicit MS_PRIVATE|MS_REC clears shared/master tags
        # in the child's new root; never copy child observations into anchors.
        tags=row['optionalFields'];seen=set()
        for tag in tags:
            if tag=='unbindable':raise Refusal('ci.anchor_unbindable_source')
            match=re.fullmatch(r'(shared|master|propagate_from):([1-9][0-9]*)',tag)
            require(match is not None and match[1] not in seen,'ci.anchor_source_propagation_unknown')
            seen.add(match[1])
        require('propagate_from' not in seen or 'master' in seen,'ci.anchor_source_propagation_unknown')
        self.host_propagation[path]=list(tags)
        relative=path[len(row['target'].rstrip('/')):].lstrip('/')
        root=row['fsroot'].rstrip('/')+('/'+relative if relative else '')
        return row,root or '/'
    def collect(self,context):
        require(self.prepared and self.namespaces()==self.manager,'ci.manager_namespace_changed')
        self.host_mounts=probe.mount_table(self.ops.read('/proc/self/mountinfo',1048576).decode())
        sources={}
        for target,parent in (('/tmp','/tmp'),('/var/tmp','/var/tmp')):
            matches=self.roster(parent);require(len(matches)==1,'ci.anchor_private_tmp_ambiguous')
            base=parent+'/'+matches[0];self.trusted(base,mode=0o700);self.trusted(base+'/tmp',mode=0o1777)
            sources[target]=base+'/tmp'
        self.trusted(self.incoming,mode=0o600)
        require(self.ops.listdir(self.incoming,128)==[],'ci.anchor_incoming_not_empty')
        sources['/run/systemd/incoming']=self.incoming
        rows=[]
        for target in sorted(probe.MOUNT_TARGETS):
            source=sources.get(target,self.root+'/root'+('' if target=='/' else target))
            mode=0o1777 if target in ('/tmp','/var/tmp') else 0o600 if target=='/run/systemd/incoming' else None
            info=self.trusted(source,mode=mode)
            role=probe.FIXED_ROLES.get(target,target[1:].replace('/','_'))
            mount,fsroot=self.covering(source)
            flags=set(mount['vfsOptions'])-{'rw'};flags.add('ro')
            if self.add_nosuid:flags.add('nosuid')
            if target in ('/input','/control'):flags.add('noexec')
            self.original[source]=ident(info)
            rows.append({'role':role,'target':target,'fsroot':fsroot,'majorMinor':mount['majorMinor'],
              'fsType':mount['fsType'],'source':mount['source'],'vfsOptions':sorted(flags),
              'fsOptions':mount['fsOptions'],'optionalFields':[],'identity':ident(info)})
        jail=self.trusted(self.root+'/root');exe=self.ops.lstat(self.root+'/root/usr/bin/python3.11')
        require(stat.S_ISREG(exe.st_mode) and exe.st_uid==exe.st_gid==0 and not stat.S_IMODE(exe.st_mode)&0o022,
                'ci.anchor_executable')
        stdio={}
        for label,path in (('stdin','/dev/null'),('stdout',self.root+'/evidence/worker.stdout'),('stderr',self.root+'/evidence/worker.stderr')):
            info=self.ops.lstat(path)
            require(info.st_nlink==1,'ci.anchor_stdio_link')
            if label=='stdin':require(stat.S_ISCHR(info.st_mode) and info.st_rdev==__import__('os').makedev(1,3),'ci.anchor_null')
            else:require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o600,'ci.anchor_stdio')
            stdio[label]={'dev':info.st_dev,'ino':info.st_ino}
            if label=='stdin':stdio[label]['rdev']=info.st_rdev
        return {'mounts':rows,'executable':{'path':self.root+'/root/usr/bin/python3.11','dev':exe.st_dev,'ino':exe.st_ino},
          'jailRoot':{'path':self.root+'/root','dev':jail.st_dev,'ino':jail.st_ino},'stdio':stdio}
    def recheck(self):
        require(self.original and self.namespaces()==self.manager,'ci.manager_namespace_changed')
        for path,before in self.original.items():require(ident(self.trusted(path,mode=before['mode'] if before['mode']==0o1777 else None))==before,'ci.anchor_source_changed')
        return True

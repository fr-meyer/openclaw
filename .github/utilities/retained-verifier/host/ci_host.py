"""One source-checked public CI build/proof. Import never issues native effects."""
from datetime import datetime,timezone
from pathlib import Path,PurePosixPath
import base64
import hashlib
import importlib
import json
import lzma
import os
import re
import stat
import sys
import tarfile
import time
import traceback
import uuid

ARTIFACT_CAP=64*1024**2
TOOLING_CAP=48*1024**2
JOB_SECONDS=2700
PRE_QEMU_RESERVE_SECONDS=2150
PRE_QEMU_PHASE_SECONDS={'source':60,'host':360,'metadata':270,'negative':30,'build':400}


class Refusal(RuntimeError):pass


def require(ok,code):
    if not ok:raise Refusal(code)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def decode(raw,cap=1048576):
    require(type(raw)is bytes and 0<len(raw)<=cap,'host.json_cap')
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,'host.json_duplicate');result[key]=value
        return result
    try:return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _v:(_ for _ in ()).throw(Refusal('host.json_constant')))
    except (UnicodeError,json.JSONDecodeError):raise Refusal('host.json_shape') from None


def read_regular(path,cap,*,owner=None):
    p=Path(path);require(p.is_absolute() and p.resolve()==p,'host.file_path')
    before=p.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid in (0,os.getuid()) and
            not before.st_mode&0o022 and 0<=before.st_size<=cap,'host.file_identity')
    if owner is not None:require(before.st_uid==owner,'host.file_owner')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        opened=os.fstat(fd);chunks=[];count=0
        while True:
            part=os.read(fd,min(65536,cap+1-count))
            if not part:break
            count+=len(part);require(count<=cap,'host.file_cap');chunks.append(part)
        after=os.fstat(fd)
    finally:os.close(fd)
    identity=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
    require(identity(before)==identity(opened)==identity(after)==identity(p.lstat()) and count==before.st_size,
            'host.file_changed')
    return b''.join(chunks)


def host_path_facts(path):
    """Read a fixed package path and every component of its resolved alias."""
    p=Path(path)
    require(p.is_absolute() and str(p)==path,'host.tool_path')
    try:resolved=p.resolve(strict=True)
    except (OSError,RuntimeError):raise Refusal('host.tool_missing') from None
    require(str(resolved).startswith(('/usr/bin/','/usr/sbin/')),'host.tool_escape')
    for leaf in (p,resolved):
        for part in (leaf,*tuple(parent for parent in leaf.parents if str(parent)!='/')):
            try:s=part.lstat()
            except OSError:raise Refusal('host.tool_missing') from None
            require(s.st_uid==s.st_gid==0 and
                    (stat.S_ISLNK(s.st_mode) or not s.st_mode&0o022) and
                    (stat.S_ISDIR(s.st_mode) or stat.S_ISLNK(s.st_mode) or part==leaf),
                    'host.tool_component')
    target=resolved.stat()
    require(stat.S_ISREG(target.st_mode) and target.st_uid==target.st_gid==0 and
            not target.st_mode&0o022 and target.st_mode&0o111 and
            0<target.st_size<=64*1024**2,'host.tool_identity')
    return {'canonical':str(resolved),'dev':target.st_dev,'ino':target.st_ino,
            'bytes':target.st_size,'mode':stat.S_IMODE(target.st_mode)}


def verify_host_package_binary(package,execution,registered,filelist,owner,*,probe=None):
    """Join a signed-APT installed package, its dpkg roster, and one inode."""
    require(type(filelist)is bytes and len(filelist)<=262144 and type(owner)is bytes and
            len(owner)<=4096,'host.package_roster_cap')
    paths=set(filelist.splitlines())
    require(registered.encode() in paths and
            owner.splitlines()==[(package+': '+registered).encode()], 'host.package_owner')
    if probe is None:probe=host_path_facts
    observed=probe(execution);recorded=probe(registered)
    require(type(observed)is dict and type(recorded)is dict and observed==recorded,
            'host.package_alias_identity')
    canonical=observed.get('canonical')
    require(type(canonical)is str and
            (canonical.encode() in paths or canonical.replace('/usr/','/',1).encode() in paths),
            'host.package_target_owner')
    return {'package':package,'executionPath':execution,'registeredPath':registered,
            'canonicalPath':canonical,'dev':observed['dev'],'ino':observed['ino'],
            'bytes':observed['bytes']}


def bootstrap_source(source,manifest_sha):
    require(type(manifest_sha)is str and re.fullmatch('[0-9a-f]{64}',manifest_sha),'host.source_pin')
    raw=read_regular(source/'PUBLIC-SOURCE-MANIFEST.json',1048576)
    require(sha(raw)==manifest_sha,'host.source_manifest_pin');value=decode(raw)
    require(type(value)is dict and set(value)=={'schema','files'} and value['schema']=='ocv-public-source-v1' and
            type(value['files'])is list and 1<=len(value['files'])<=256,'host.source_manifest')
    rows={}
    for row in value['files']:
        require(type(row)is dict and set(row)=={'path','bytes','sha256','mode'},'host.source_row')
        name=row['path'];p=PurePosixPath(name) if type(name)is str else None
        require(p is not None and not p.is_absolute() and str(p)==name and '..'not in p.parts and name not in rows and
                row['mode']==0o444 and type(row['bytes'])is int and 0<row['bytes']<=4*1024**2,'host.source_name')
        data=read_regular(source/name,row['bytes']+1)
        require(len(data)==row['bytes'] and sha(data)==row['sha256'],'host.source_changed');rows[name]=row
    require({'host/ci_host.py','host/host_context.py','host/command_factories.py','host/serial_receipt.py',
             'host/source_validator.py','host/outer_supervision.py','build/build_recipe.py'}<=set(rows),'host.source_incomplete')
    return raw,rows


def select_roots(records,required,kernel_name):
    require(type(records)is dict and type(kernel_name)is str,'host.root_records')
    result=[]
    for name in sorted(set(required)|{kernel_name}):
        matches=[row for key,row in records.items() if key[0]==name and key[2]in('amd64','all')]
        require(len(matches)==1,'host.package_root_ambiguous')
        row=matches[0];result.append({'name':name,'version':row['version'],'sha256':row['debSha256']})
    return result


def decompress_packages(raw):
    require(type(raw)is bytes and len(raw)<=16777216,'host.xz_cap')
    decompressor=lzma.LZMADecompressor();data=decompressor.decompress(raw,max_length=64*1024**2+1)
    require(len(data)<=64*1024**2 and decompressor.eof and not decompressor.unused_data,'host.xz_shape')
    return data


class Controller:
    """Pure injected orchestration; the port alone owns effects and custody."""
    def __init__(self,port):self.port=port;self.used=False
    def run(self):
        require(not self.used,'host.controller_once');self.used=True;phase='source'
        result={'schema':'ocv.host-mission-step.v1','status':'refused','phase':phase}
        try:
            self.port.admit_source()
            phase='source-tests';self.port.test_sources()
            phase='host-tools';self.port.install_host_tools()
            phase='signed-metadata';self.port.authenticate_metadata()
            phase='apt-negative';self.port.negative_bootstrap()
            phase='build';self.port.build_once()
            phase='image-binding';expected=self.port.bind_image()
            phase='guest';outer=self.port.boot_once()
            phase='custody';self.port.preserve_outer(outer)
            phase='independent-consumer';proof=self.port.verify_outer(outer,expected)
            require(type(proof)is dict and proof.get('status')=='passed','host.linux_proof_refused')
            phase='artifact';self.port.package_public_artifact(proof)
            result.update(status='passed',phase='complete',linuxIsolationProof=True,candidateQualified=False)
        except BaseException as error:
            reason=str(error) if isinstance(error,Refusal) and re.fullmatch('[A-Za-z0-9_.-]{1,160}',str(error)) else type(error).__name__
            result.update(phase=phase,reason=reason,linuxIsolationProof=False,candidateQualified=False)
            self.port.preserve_failure(phase,error)
        finally:
            self.port.save_final(result)
        return result


class NativePort:
    """Construct only with the source-owned native permit in the approved job."""
    def __init__(self,permit,modules,source,manifest_raw,rows):
        self.permit=permit;self.m=modules;self.source=Path(source);self.manifest_raw=manifest_raw;self.rows=rows
        self.project=Path(permit.project);self.project.mkdir(mode=0o755)
        self.artifacts=Path(os.environ['RUNNER_TEMP'])/'ocv-ci-artifacts';self.artifacts.mkdir(mode=0o755)
        clock_path=Path(os.environ['RUNNER_TEMP'])/'ocv-job-clock.json'
        anchor=decode(read_regular(clock_path,4096),4096)
        require(type(anchor)is dict and set(anchor)=={'schema','monotonicNs'} and
                anchor['schema']=='ocv-job-clock-v1' and type(anchor['monotonicNs'])is int and
                0<anchor['monotonicNs']<=time.monotonic_ns(),'host.job_clock')
        self.started=anchor['monotonicNs']/1000000000
        self.deadline=self.started+JOB_SECONDS;self.phase_deadline=self.started+60
        self.phases=set();self.commands=[];self.first_failure=None;self.bound=None
        self.run={'repository':'fr-meyer/openclaw','workflowRef':os.environ['GITHUB_WORKFLOW_REF'],
                  'sourceCommit':os.environ['GITHUB_SHA'],'runId':os.environ['GITHUB_RUN_ID'],'runAttempt':'1'}
    def _phase(self,name,seconds):
        require(name not in self.phases and type(seconds)is int and seconds>0,'host.phase_consumed')
        self.phases.add(name)
        self.phase_deadline=min(self.deadline,time.monotonic()+seconds)
        if name in PRE_QEMU_PHASE_SECONDS:
            require(seconds<=PRE_QEMU_PHASE_SECONDS[name],'host.phase_ceiling')
            self.phase_deadline=min(self.phase_deadline,self.deadline-PRE_QEMU_RESERVE_SECONDS)
        require(self.phase_deadline>time.monotonic(),'host.phase_deadline')
    def _pre_qemu_budget(self):
        now=time.monotonic()
        require(now<self.deadline-PRE_QEMU_RESERVE_SECONDS,'host.pre_qemu_pool')
        require(now<self.phase_deadline,'host.phase_deadline')
    def _run(self,role,arguments,timeout,*,allow_failure=False):
        remaining=self.deadline-time.monotonic();require(remaining>30,'host.whole_deadline')
        phase_remaining=self.phase_deadline-time.monotonic()
        require(phase_remaining>0,'host.phase_deadline')
        env=dict(self.m.context.ENV)
        if role.startswith('ubuntu_apt_'):env['DEBIAN_FRONTEND']='noninteractive'
        seal_options={'launch_deadline':self.deadline-PRE_QEMU_RESERVE_SECONDS} if role=='qemu_once' else {}
        scope=self.m.context.seal_command(self.permit,role,arguments,cwd=str(self.project),environment=env,**seal_options)
        now=time.monotonic()
        require(self.deadline-now>30,'host.whole_deadline')
        require(self.phase_deadline>now,'host.phase_deadline')
        if role=='qemu_once':require(now<self.deadline-PRE_QEMU_RESERVE_SECONDS,'host.pre_qemu_pool')
        value=self.m.context.run_owned(self.permit,scope,cwd=str(self.project),environment=env,
                                      deadline=min(self.deadline-30,self.phase_deadline,now+timeout))
        row={'role':role,'argv':list(scope.argv),'status':value.get('status'),'returncode':value.get('returncode'),
             'timedOut':value.get('timedOut'),'ownershipRetained':value.get('ownershipRetained'),
             'spawned':value.get('spawned'),'outerReason':value.get('reason'),
             'setupCause':value.get('setupCause'),
             'stdoutBytes':len(value['stdout']),'stdoutSha256':sha(value['stdout']),
             'stderrBytes':len(value['stderr']),'stderrSha256':sha(value['stderr'])}
        self.commands.append(row)
        if value.get('status')!='outer_exit_passed':
            if self.first_failure is None:
                self.first_failure=row
                cap=6*1024**2 if role=='qemu_once' else 1048576
                self._write(self.artifacts/'host-stdout.bin',value['stdout'][:cap])
                self._write(self.artifacts/'host-stderr.bin',value['stderr'][:1048576])
            if not allow_failure:raise Refusal('host.command_'+role)
        return value
    def _write(self,path,raw,mode=0o644):
        p=Path(path);require(p.is_relative_to(self.project) or p.is_relative_to(self.artifacts),'host.write_target')
        p.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
        require(p.parent.resolve()==p.parent,'host.write_parent')
        fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
        with os.fdopen(fd,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.chmod(p,mode)
    def admit_source(self):
        require(self.permit.expected['source_manifest_sha']==sha(self.manifest_raw),'host.permit_manifest')
        require(os.statvfs(self.project).f_bavail*os.statvfs(self.project).f_frsize>=10*1024**3,'host.build_disk_floor')
    def test_sources(self):
        require(self.started+60>time.monotonic(),'host.source_phase_exhausted')
        self._phase('source',max(1,int(self.started+60-time.monotonic())))
        for suite in self.m.commands.SUITES:self._run('python_tests',{'source_root':str(self.source),'suite':suite},60)
        self._pre_qemu_budget()
    def install_host_tools(self):
        self._phase('host',PRE_QEMU_PHASE_SECONDS['host'])
        for relative in ('ubuntu-lists/partial','ubuntu-archives/partial','metadata','out'):
            (self.project/relative).mkdir(mode=0o755,parents=True)
        self._write(self.project/'ubuntu.sources.list',self.m.commands.ubuntu_sources())
        self._run('ubuntu_apt_update',{'project':str(self.project)},120)
        self._run('ubuntu_apt_install',{'project':str(self.project)},240)
        versions=self._run('dpkg_query',{'kind':'versions'},20)['stdout']
        owners=self._run('dpkg_query',{'kind':'owners'},20)['stdout']
        installed={}
        for line in versions.splitlines():
            fields=line.split(b'\t')
            require(len(fields)==3 and fields[0] not in installed,'host.package_version_roster')
            installed[fields[0]]=fields
        require(b'mkosi' in installed and installed[b'mkosi'][1]==b'20.2-1',
                'host.mkosi_version')
        for name in (b'systemd-boot',b'kmod',b'e2fsprogs'):
            require(name in installed and re.fullmatch(rb'[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127}',installed[name][1])
                    and installed[name][2] in (b'amd64',b'all'),'host.package_version')
        require(b'systemd-boot: /usr/bin/bootctl' in owners.splitlines(),
                'host.bootctl_package')
        proof=[];package_filelists={}
        for package,executable,kind,allowed in (
            ('systemd-boot','/usr/bin/bootctl','systemd_boot_files',('/usr/bin/bootctl',)),
            ('kmod','/usr/sbin/depmod','kmod_files',('/usr/sbin/depmod','/sbin/depmod')),
            ('e2fsprogs','/usr/sbin/mkfs.ext4','e2fsprogs_files',
             ('/usr/sbin/mkfs.ext4','/sbin/mkfs.ext4')),
            ('e2fsprogs','/usr/sbin/mke2fs','e2fsprogs_files',
             ('/usr/sbin/mke2fs','/sbin/mke2fs'))):
            # One settled readonly package listing covers both e2fsprogs
            # binaries in this transaction. Reusing its immutable bytes avoids
            # resealing/reexecuting the identical command; per-binary owner,
            # alias/inode and target checks still run independently below.
            if kind not in package_filelists:
                package_filelists[kind]=self._run('dpkg_query',{'kind':kind},20)['stdout']
            files=package_filelists[kind]
            registered=[path for path in allowed if path.encode() in files.splitlines()]
            require(len(registered)==1,'host.package_filelist')
            path=registered[0]
            if package=='systemd-boot':
                owner=b'\n'.join(line for line in owners.splitlines() if b'/usr/bin/bootctl' in line)+b'\n'
            else:
                prefix='depmod' if package=='kmod' else 'mke2fs' if executable.endswith('/mke2fs') else 'mkfs'
                owner_kind=prefix+('_usr_owner' if path.startswith('/usr/') else '_sbin_owner')
                owner=self._run('dpkg_query',{'kind':owner_kind},20)['stdout']
            proof.append(verify_host_package_binary(package,executable,path,files,owner))
        self.host_tools={'versionsSha256':sha(versions),'ownersSha256':sha(owners),
                         'packagePathProofSha256':sha(canonical(proof))}
        self.keyring=read_regular('/usr/share/keyrings/debian-archive-keyring.gpg',1048576,owner=0)
        self.gpgv_sha=sha(read_regular('/usr/bin/gpgv',8*1024**2,owner=0))
        self.apt_helper_sha=sha(read_regular('/usr/lib/apt/apt-helper',8*1024**2,owner=0))
        self._write(self.project/'metadata/keyring.gpg',self.keyring,0o444)
        self._pre_qemu_budget()
    def authenticate_metadata(self):
        self._phase('metadata',PRE_QEMU_PHASE_SECONDS['metadata'])
        for kind in ('release','packages'):self._run('debian_metadata_curl',{'project':str(self.project),'kind':kind},130)
        release=read_regular(self.project/'metadata/InRelease',196608)
        compressed=read_regular(self.project/'metadata/Packages.xz',16777216)
        self.packages=decompress_packages(compressed)
        status=self._run('gpgv_metadata',{'project':str(self.project)},30,allow_failure=True)
        if status['returncode']==2:
            require(status.get('status')=='refused' and status.get('reason')=='command_exit_nonzero' and
                    status.get('spawned') is True and status.get('timedOut') is False and
                    status.get('outerExited') is True and status.get('ownedGroupGone') is True and
                    status.get('streamsEOF') is True and status.get('streamsClosed') is True and
                    status.get('ownershipRetained') is False and status.get('truncated') is False and
                    status.get('cleanupErrors')==[] and status.get('setupCause') is None,
                    'host.gpgv_process_boundary')
        else:
            require(status.get('status')=='outer_exit_passed','host.gpgv_process_boundary')
        self.metadata=self.m.policy.classify(release,self.packages,returncode=status['returncode'],
          timed_out=status['timedOut'],status=status['stdout'],checked_at=datetime.now(timezone.utc))
        if status['returncode']==2:
            # The classifier accepted only the exact extra unknown signature.
            # Clear provisional failure custody before the expected APT-negative
            # test so its diagnostic files retain their true origin.
            require(self.first_failure is self.commands[-1],'host.gpgv_failure_custody')
            for name in ('stdout','stderr'):
                diagnostic=self.artifacts/('host-'+name+'.bin')
                require(read_regular(diagnostic,1048576)==status[name][:1048576],
                        'host.gpgv_failure_custody')
                diagnostic.unlink()
            self.first_failure=None
        for kind in ('release','packages'):
            self._run('debian_metadata_curl',{'project':str(self.project),'kind':kind,'origin':'security'},130)
        security_release=read_regular(self.project/'metadata/SecurityInRelease',196608)
        security_compressed=read_regular(self.project/'metadata/SecurityPackages.xz',16777216)
        self.security_packages=decompress_packages(security_compressed)
        security_status=self._run('gpgv_metadata',{'project':str(self.project),'origin':'security'},30)
        require(security_status.get('status')=='outer_exit_passed' and
                security_status['returncode']==0,'host.security_gpgv_process_boundary')
        # Same returned status bytes as the classifier; no raw status/UID export.
        self.security_signature_facts=self.m.policy.security_signature_evidence(security_status['stdout'])
        self.security_metadata=self.m.policy.classify_security(security_release,self.security_packages,
          returncode=security_status['returncode'],timed_out=security_status['timedOut'],
          status=security_status['stdout'],checked_at=datetime.now(timezone.utc))
        self.records=self.m.apt.package_records(self.packages)
        security_records=self.m.apt.package_records(self.security_packages,origin='security')
        python=self.m.apt.security_python_roots(security_records)
        self.roots=select_roots(self.records,set(self.m.build.REQUIRED_PACKAGES)-set(self.m.policy.PYTHON_U9),
                                'linux-image-6.1.0-50-amd64')+python
        self.roots.sort(key=lambda row:row['name'])
        self.m.build.package_specs(self.roots)
        self._pre_qemu_budget()
    def _project_files(self,destination,negative=False):
        self._pre_qemu_budget()
        destination=Path(destination)
        if destination!=self.project:destination.mkdir(mode=0o755)
        build_id=sha((self.permit.mission+(':negative' if negative else ':positive')).encode())[:32]
        keyring_sha='0'*64 if negative else sha(self.keyring)
        guard=self.m.guard_project.make_context(source_manifest_sha256=sha(self.manifest_raw),build_id=build_id,
          keyring_sha256=keyring_sha,gpgv_sha256=self.gpgv_sha,apt_helper_sha256=self.apt_helper_sha,run_identity=self.run)
        kernel=next(row for row in self.roots if row['name'].startswith('linux-image-6.1.'))
        header={'schema':'ocv-host-build-context-v1','sourceManifestSha256':sha(self.manifest_raw),'buildId':build_id,
                'runIdentity':self.run,'keyringSha256':keyring_sha,'kernelPackage':{'name':kernel['name'],'version':kernel['version']},
                'packageRoots':self.roots}
        files=self.m.build.recipe_files(self.roots,source_manifest_sha256=sha(self.manifest_raw),
          build_entry_sha256=self.rows['host/build_entry.py']['sha256'],build_stage_context_sha256=sha(canonical(header)))
        for name,(raw,mode)in files.items():
            self._pre_qemu_budget();self._write(destination/name,raw,mode)
        for name,(raw,mode)in self.m.guard_project.project_files(guard,
          guard_source=read_regular(self.source/'apt/archive_guard.py',131072),
          policy_source=read_regular(self.source/'apt/archive_policy.py',131072),
          entry_source=read_regular(self.source/'apt/guard_entry.py',131072)).items():self._write(destination/'pkgmngr'/name,raw,mode)
        for name,mode in self.m.guard_project.project_directories().items():
            (destination/'pkgmngr'/name).mkdir(mode=mode,parents=True,exist_ok=True)
        self._write(destination/'mkosi.postinst',self.m.guard_project.outer_postinstall_script(),0o555)
        for name,row in self.rows.items():
            self._pre_qemu_budget()
            self._write(destination/'extra/opt/ocv/source'/name,read_regular(self.source/name,row['bytes']+1),0o444)
        self._write(destination/'extra/opt/ocv/source/PUBLIC-SOURCE-MANIFEST.json',self.manifest_raw,0o444)
        self._write(destination/'extra/opt/ocv/control/build-stage-context.json',canonical(header),0o444)
        for name,target in self.m.build.recipe_symlinks().items():
            link=destination/name;link.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
            os.symlink(target,link)
        self._run('own_project_chown',{'project':str(destination),'phase':'prepare','owner':'0:0'},30)
        self._pre_qemu_budget()
        return guard
    def negative_bootstrap(self):
        self._phase('negative',30)
        negative=self.project/'negative';context=self._project_files(negative,True)
        outcome=self._run('mkosi_build',{'project':str(negative)},240,allow_failure=True)
        require(type(outcome.get('returncode'))is int and outcome['returncode']!=0 and
                outcome.get('timedOut')is False and outcome.get('outerExited')is True and
                outcome.get('ownedGroupGone')is True and outcome.get('streamsEOF')is True and
                outcome.get('streamsClosed')is True and outcome.get('ownershipRetained')is False and outcome.get('truncated')is False,
                'host.negative_not_refused')
        records=[]
        for line in outcome['stderr'].splitlines():
            start=line.find(b'{')
            if start<0:continue
            try:value=decode(line[start:],32768)
            except (Refusal,ValueError):continue
            if type(value)is dict and value.get('schema')=='ocv-apt-refused-v1':records.append(value)
        require(len(records)==1,'host.negative_single_failure')
        receipt=records[0]
        require(receipt.get('buildId')==context['buildId'] and receipt.get('sourceManifestSha256')==sha(self.manifest_raw) and
                receipt.get('contextSha256')==sha(canonical(context)) and receipt.get('phase')=='update' and
                receipt.get('reason')=='apt.keyring_pin','host.negative_wrong_cause')
        cache=negative/'cache/cache/apt/archives'
        require(not cache.exists() or not list(cache.glob('*.deb')),'host.negative_downloaded_package')
        self.negative_proof={'status':'passed','reason':'apt.keyring_pin','receiptSha256':sha(canonical(receipt))}
        for name in ('stdout','stderr'):
            old=self.artifacts/('host-'+name+'.bin');new=self.artifacts/('negative-'+name+'.bin')
            require(not new.exists(),'host.negative_custody_exists')
            if old.exists():old.rename(new)
        self.first_failure=None
        self._pre_qemu_budget()
        # Expected negative is retained separately, not mislabeled a positive failure.
    def build_once(self):
        self._phase('build',400)
        self._project_files(self.project)
        self._run('mkosi_build',{'project':str(self.project)},400)
        self.m.context.normalize_mkosi_outputs(self.permit,str(self.project))
        fixture_files={name[len('integrated/fixture/'):]:read_regular(self.source/name,row['bytes']+1)
            for name,row in self.rows.items() if name.startswith('integrated/fixture/')}
        for name,(raw,mode) in self.m.integrated_fixture.fixture_layout(fixture_files).items():
            self._write(self.project/'integrated-seed'/name,raw,mode)
        self.m.context.initialize_integrated_test_image(self.permit,str(self.project))
        self._run('integrated_test_image',{'seed_root':str(self.project/'integrated-seed'),
            'output':str(self.project/'out/integrated-test.raw')},30)
        self._run('own_mkosi_outputs',{'project':str(self.project),
            'uid':self.permit.uid,'gid':self.permit.gid},30)
        self._run('freeze_public_outputs',{'project':str(self.project)},30)
        self.build=decode(read_regular(self.project/'out/build.json',32768))
        require(self.build['sourceManifestSha256']==sha(self.manifest_raw) and self.build['runIdentity']==self.run and
                self.build['fixtureOnly']is True and self.build['candidateImage']is False,'host.build_control')
        self._pre_qemu_budget()
    def bind_image(self):
        self._pre_qemu_budget()
        from types import SimpleNamespace
        out=self.project/'out';records={}
        for name,cap in (('ocv-test.raw',6*1024**3),('kernel.bin',128*1024**2),('initrd.img',512*1024**2)):
            p=out/name;s=p.lstat();require(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and p.resolve()==p and 0<s.st_size<=cap,'host.output_identity')
            h=hashlib.sha256();count=0
            with p.open('rb')as stream:
                while True:
                    self._pre_qemu_budget()
                    raw=stream.read(1048576)
                    if not raw:break
                    count+=len(raw);h.update(raw)
            after=p.lstat();require(count==s.st_size and (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'host.output_changed')
            records[name]={'bytes':s.st_size,'sha256':h.hexdigest(),'regular':True,
                           'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode)}
        table=self._run('partition_read',{'image':str(out/'ocv-test.raw')},30)['stdout']
        self.base_records=records
        self.bound=self.m.build.bind_qemu_inputs(str(out),records,table,source_sha256=sha(self.manifest_raw),
            build_sha256=sha(read_regular(out/'build.json',32768)),kernel_version=self.build['kernelVersion'],run_identity=self.run)
        self.expected=self.m.source_expectation.expected(self.source,out,self.bound,self.permit.mission)
        test=out/'integrated-test.raw';raw=read_regular(test,64*1024*1024,owner=0)
        require(len(raw)==64*1024*1024 and stat.S_IMODE(test.stat().st_mode)==0o444,'host.integrated_image_size')
        self.m.integrated_fixture.validate_test_image(raw)
        self.test_record={'name':'integrated-test.raw','bytes':len(raw),'sha256':sha(raw)}
        self.base_records['integrated-test.raw']={'bytes':len(raw),'sha256':sha(raw)}
        runtime_raw=read_regular(out/'runtime.json',4*1024**2)
        require(sha(runtime_raw)==self.build['runtimeManifestSha256'],'host.integrated_runtime_control')
        self.integrated_runtime_rows=self.m.integrated_capture.expected_runtime_rows(decode(runtime_raw,4*1024**2),self.build)
        self._pre_qemu_budget()
        return self.expected
    def boot_once(self):
        require(self.deadline-time.monotonic()>=PRE_QEMU_RESERVE_SECONDS,'host.guest_budget')
        self._phase('guest',2000)
        return self._run('qemu_once',{'bound':self.bound,'session':self.permit.mission,
            'test_record':self.test_record},2000,allow_failure=True)
    def preserve_outer(self,value):
        # Keep first expected-negative logs separate; these exact guest streams
        # are retained before any frame/consumer parsing, including parse failure.
        for name,key in (('host-stdout.bin','stdout'),('host-stderr.bin','stderr')):
            p=self.artifacts/name
            cap=6*1024**2 if key=='stdout' else 1048576
            require(len(value[key])<=cap,'host.outer_custody_cap')
            if p.exists():require(read_regular(p,cap)==value[key],'host.custody_changed')
            else:self._write(p,value[key])
    def verify_outer(self,value,expected):
        self.verify_base_unchanged()
        return self.m.serial.verify(value,expected,source_validator=lambda rows,binding:
            self.m.integrated_capture.validate_combined(rows,binding,generic_validator=self.m.validator.validate,
                runtime_rows=self.integrated_runtime_rows))
    def verify_base_unchanged(self):
        for name,expected in self.base_records.items():
            p=self.project/'out'/name
            before=p.lstat()
            require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==0 and
                    before.st_gid==0 and stat.S_IMODE(before.st_mode)==0o444 and
                    before.st_size==expected['bytes'] and p.resolve()==p,'host.base_identity_changed')
            h=hashlib.sha256();count=0
            with p.open('rb')as stream:
                while True:
                    data=stream.read(1048576)
                    if not data:break
                    count+=len(data);h.update(data)
            after=p.lstat()
            identity=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
            require(count==before.st_size and identity(before)==identity(after) and h.hexdigest()==expected['sha256'],'host.base_changed')
    def package_public_artifact(self,proof):
        self._phase('artifact',120)
        self.m.artifact.package(self.source,self.project/'out',self.artifacts/'public-tooling.tar.gz',
                                source_rows=self.rows,manifest_raw=self.manifest_raw,maximum=TOOLING_CAP)
        self._write(self.artifacts/'host-custody.json',canonical(proof))
        tools_raw=read_regular(self.project/'out/tools.json',1048576)
        require(sha(tools_raw)==self.build['toolManifestSha256'],'host.extra_tool_catalog_pin')
        catalog={'schema':'ocv.bound-build-tool-catalog.v1','fixtureOnly':True,'candidateImage':False,
            'nativeAuthority':False,'sourceManifestSha256':sha(self.manifest_raw),'runIdentity':self.run,
            'toolManifestSha256':sha(tools_raw),'aptMetadataManifestSha256':self.build['aptMetadataManifestSha256'],
            'tools':decode(tools_raw)['tools']}
        self._write(self.artifacts/'extra-tool-catalog.json',canonical(catalog))
    def preserve_failure(self,phase,error):
        frames=[]
        for frame in traceback.extract_tb(error.__traceback__)[-12:]:
            f=Path(frame.filename)
            if f.is_relative_to(self.source):name=str(f.relative_to(self.source))
            else:name=f.name
            frames.append({'source':name,'function':frame.name,'line':frame.lineno})
        path=getattr(error,'filename',None);relative=None
        if type(path)is str:
            p=Path(path)
            if p.is_relative_to(self.project):relative='project/'+str(p.relative_to(self.project))
            elif p.is_relative_to(self.source):relative='source/'+str(p.relative_to(self.source))
        self.failure={'phase':phase,'type':type(error).__name__,
                      'reason':str(error) if re.fullmatch('[A-Za-z0-9_.-]{1,160}',str(error))else'boundary_unknown',
                      'errno':getattr(error,'errno',None),'path':relative,'frames':frames,'firstCommand':self.first_failure}
        if phase=='signed-metadata' and hasattr(self,'security_signature_facts'):
            facts=self.security_signature_facts
            require(len(canonical(facts))<=1024,'host.security_signer_evidence_cap')
            self.failure['securitySignatures']=facts
    def save_final(self,value):
        record=dict(value,commands=self.commands,negativeAPT=getattr(self,'negative_proof',None),
                    failure=getattr(self,'failure',None),runIdentity=self.run,sourceManifestSha256=sha(self.manifest_raw))
        self._write(self.artifacts/'host-result.json',canonical(record))
        require(sum(p.stat().st_size for p in self.artifacts.iterdir()if p.is_file())<=ARTIFACT_CAP,'host.artifact_cap')


def main():
    source=Path(__file__).resolve().parents[1]
    try:
        manifest,rows=bootstrap_source(source,os.environ.get('OCV_SOURCE_MANIFEST_SHA'))
        for directory in ('host','build','apt','native','runtime','bootstrap','consumer','integrated'):
            sys.path.insert(0,str(source/directory))
        from types import SimpleNamespace
        import host_context,command_factories,build_recipe,guard_project,archive_guard,archive_policy,serial_receipt,source_validator
        import artifact,source_expectation,integrated_fixture,integrated_capture
        expected={'expected_source':os.environ['OCV_EXPECTED_SOURCE'],'expected_tree':os.environ['OCV_EXPECTED_TREE'],
                  'workflow_sha':os.environ['OCV_WORKFLOW_SHA'],'source_manifest_sha':os.environ['OCV_SOURCE_MANIFEST_SHA'],
                  'source_manifest_path':'PUBLIC-SOURCE-MANIFEST.json','run_id':os.environ['GITHUB_RUN_ID']}
        permit=host_context.make_native_permit(str(source),expected,os.environ['OCV_MISSION_ID'])
        modules=SimpleNamespace(context=host_context,commands=command_factories,build=build_recipe,guard_project=guard_project,
          apt=archive_guard,policy=archive_policy,serial=serial_receipt,validator=source_validator,
          artifact=artifact,source_expectation=source_expectation,
          integrated_fixture=integrated_fixture,integrated_capture=integrated_capture)
        result=Controller(NativePort(permit,modules,source,manifest,rows)).run()
        return 0 if result['status']=='passed' else 1
    except BaseException as error:
        reason=str(error) if re.fullmatch('[A-Za-z0-9_.-]{1,160}',str(error))else'boundary_unknown'
        sys.stderr.write(canonical({'schema':'ocv.host-early-refusal.v1','status':'refused','reason':reason,
                                    'type':type(error).__name__}).decode()+'\n')
        return 1


if __name__=='__main__':raise SystemExit(main())

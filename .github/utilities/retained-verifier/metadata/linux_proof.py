"""Synthetic-only Node SQLite proof, run inside the existing admitted namespace.

The existing host source/command owner verifies its complete public manifest
before this entry. Root privileges are required only in its isolated mount,
network and PID namespace; this is not a direct workflow sudo entry.
"""
import argparse, hashlib, json, os, pathlib, shutil, stat, subprocess, sys, tempfile

NODE_SHA='e32e2d16081cf644f88392934288086e7662529d0d43277c34f7aad2207cfafb'
NODE_BYTES=126879696
LEAVES=('metadata_reader.cjs','metadata_supervisor.cjs','test_metadata_reader.cjs',
        'test_metadata_supervisor.cjs','linux_fixture.cjs','test_supervisor_actual_child.cjs','linux_proof.py')

def need(value):
    if value is not True: raise RuntimeError('synthetic_metadata_proof_refused')

def run(argv, *, user=False, seconds=70):
    def demote(): os.setgroups([]); os.setgid(1000); os.setuid(1000)
    result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C','LC_ALL':'C','TZ':'UTC'},
        timeout=seconds,check=False,preexec_fn=demote if user else None)
    need(len(result.stdout)<=16384 and len(result.stderr)<=4096)
    return result

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--node',required=True)
    parser.add_argument('--source-manifest-sha256',required=True);args=parser.parse_args()
    need(sys.platform=='linux' and os.geteuid()==0 and os.getpid()==1)
    # proc net files describe this network namespace. An inherited sysfs mount
    # can describe the original namespace and is deliberately not authority.
    devices=pathlib.Path('/proc/net/dev').read_text();need(len(devices)<=65536)
    need({line.split(':',1)[0].strip()for line in devices.splitlines()if ':'in line}<={'lo'})
    routes=pathlib.Path('/proc/net/route').read_text();need(len(routes)<=65536)
    need(all(line.split()[0]=='lo'and line.split()[1]=='00000000'and
        line.split()[2]=='00000000'for line in routes.splitlines()[1:]if line.strip()))
    routes6=pathlib.Path('/proc/net/ipv6_route').read_text();need(len(routes6)<=65536)
    for line in routes6.splitlines():
        fields=line.split();need(len(fields)==10 and fields[-1]=='lo'and
            fields[0]in('0'*32,'0'*31+'1')and fields[4]=='0'*32)
    here=pathlib.Path(__file__).resolve().parent
    mf=here/'SOURCE-MANIFEST.json';raw=mf.read_bytes()
    need(hashlib.sha256(raw).hexdigest()==args.source_manifest_sha256)
    manifest=json.loads(raw);need(manifest['schema']=='ocv.generic-retained-metadata-proof-source.v1')
    need([r['path'] for r in manifest['files']]==sorted(LEAVES))
    for row in manifest['files']:
        p=here/row['path'];s=p.lstat();data=p.read_bytes()
        need(stat.S_ISREG(s.st_mode) and not p.is_symlink() and s.st_nlink==1 and
             s.st_size==row['bytes']==len(data) and hashlib.sha256(data).hexdigest()==row['sha256'])
    node=pathlib.Path(args.node);s=node.lstat();need(stat.S_ISREG(s.st_mode) and
        not node.is_symlink() and s.st_nlink==1 and s.st_size==NODE_BYTES and not s.st_mode&0o022)
    need(hashlib.sha256(node.read_bytes()).hexdigest()==NODE_SHA)
    owned=[];mounts=[];work=pathlib.Path(tempfile.mkdtemp(prefix='ocv-synthetic-metadata-'))
    metadata=pathlib.Path('/metadata');need(not metadata.exists())
    need(run(['/usr/bin/mount','--make-rprivate','/']).returncode==0)
    def bind(source,target):
        need(run(['/usr/bin/mount','--bind',str(source),str(target)]).returncode==0);mounts.append(target)
        need(run(['/usr/bin/mount','-o','remount,bind,ro,nosuid,nodev,noexec',str(target)]).returncode==0)
    def ident(p):
        v=p.lstat();return {k:str(getattr(v,'st_'+k) if k not in ('mtimeNs','ctimeNs') else
            getattr(v,'st_'+('mtime_ns' if k=='mtimeNs' else 'ctime_ns'))) for k in
            ('dev','ino','size','uid','gid','nlink','mode','mtimeNs','ctimeNs')}
    try:
        os.chmod(work,0o755);source=work/'sources'
        result=run([str(node),'--no-warnings',str(here/'linux_fixture.cjs'),'build',str(source)])
        need(result.returncode==0 and result.stdout==result.stderr==b'')
        metadata.mkdir(mode=0o755);owned.append(metadata)
        for name in ('metadata-reader.cjs','metadata-supervisor.cjs','metadata-profile.json'):
            target=pathlib.Path('/run')/name;need(not target.exists() and not target.is_symlink())
            target.touch(mode=0o444);owned.append(target)
        reader=work/'reader.cjs';reader.write_bytes((here/'metadata_reader.cjs').read_bytes());reader.chmod(0o444)
        supervisor=work/'supervisor.cjs';supervisor.write_bytes((here/'metadata_supervisor.cjs').read_bytes());supervisor.chmod(0o444)
        bind(reader,pathlib.Path('/run/metadata-reader.cjs'));bind(supervisor,pathlib.Path('/run/metadata-supervisor.cjs'))
        profile={'schema':'ocv.retained-clone-metadata-profile.v1','sourceSha':'a'*40,
            'indexDigest':'sha256:'+'1'*64,'platformDigest':'sha256:'+'2'*64,'configDigest':'sha256:'+'3'*64,
            'grantSha256':'b'*64,'dataset':{'testDiskId':'1','filesystemUuid':'synthetic','sourceSnapshotId':'2'},
            'admission':{'ownerSessionId':'c'*32,'vmId':'3','bootId':'00000000-0000-0000-0000-000000000001',
                'sourceOwnerProofSha256':'d'*64,'readOnlyMountsVerified':True,'noWritersVerified':True,
                'exactDatasetVerified':True,'controllerHardQuerySeconds':60,'controllerWholeActionSeconds':120,
                'noRetry':True,'established':True},'rows':[]}
        for n in range(11):
            directory=metadata/('db-'+str(n).zfill(2));directory.mkdir(mode=0o755);owned.append(directory)
            agent=None if n==0 else 'synthetic-'+str(n).zfill(2)
            relative='state/openclaw.sqlite' if n==0 else 'agents/'+agent+'/agent/openclaw-agent.sqlite'
            files={}
            for key,suffix in (('main',''),('wal','-wal'),('shm','-shm'),('journal','-journal')):
                origin=source/str(n).zfill(2)/('main.sqlite'+suffix)
                if origin.exists():
                    target=directory/('main.sqlite'+suffix);target.touch(mode=0o600);owned.append(target)
                    bind(origin,target);pin=ident(target)
                    files[key]=pin if key=='main' else {'state':'present','identity':pin}
                else: files[key]={'state':'absent','identity':None}
            profile['rows'].append({'ordinal':n,'relativePath':relative,'pathSha256':hashlib.sha256(relative.encode()).hexdigest(),
                'role':'global' if n==0 else 'agent','agentId':agent,'files':files})
        profile_source=work/'profile.json';profile_source.write_text(json.dumps(profile,separators=(',',':')))
        profile_source.chmod(0o444);bind(profile_source,pathlib.Path('/run/metadata-profile.json'))
        pin=hashlib.sha256(profile_source.read_bytes()).hexdigest()
        actual=run([str(node),'--no-warnings','/run/metadata-supervisor.cjs',pin],user=True)
        need(actual.returncode==0 and actual.stderr==b'');value=json.loads(actual.stdout)
        need(value['status']=='COMPLETED' and value['childCloseObserved'] is True and
            value['streamsEOF'] is True and value['streamsClosed'] is True and
            value['value']['status']=='METADATA_CONSISTENT' and len(value['value']['rows'])==11 and
            value['value']['integrityFreshnessMigrationProductionEstablished'] is False)
        need(b'synthetic-application-record' not in actual.stdout and b'synthetic-01' not in actual.stdout)
        for argv in ([str(node),'--no-warnings',str(here/'linux_fixture.cjs'),'deny'],
                     [str(node),'--no-warnings',str(here/'test_supervisor_actual_child.cjs')]):
            r=run(argv);need(r.returncode==0 and r.stderr==b'')
        # Existing-mounted WAL works; removing that required SHM from the
        # profile refuses before any SQLite database can be opened.
        partial=json.loads(json.dumps(profile));partial['rows'][0]['files']['shm']={'state':'absent','identity':None}
        profile_source.chmod(0o644);profile_source.write_text(json.dumps(partial,separators=(',',':')));profile_source.chmod(0o444)
        badpin=hashlib.sha256(profile_source.read_bytes()).hexdigest()
        refused=run([str(node),'--no-warnings','/run/metadata-supervisor.cjs',badpin],user=True)
        refusal=json.loads(refused.stdout)
        need(refused.returncode==1 and refusal['status']=='REFUSED'and refusal['failure']['code']==103 and refusal['failure']['ordinal']==-1)
        proof={'schema':'ocv.generic-retained-metadata-linux-proof.v1','status':'PASS',
            'nodeSha256':NODE_SHA,'sourceManifestSha256':args.source_manifest_sha256,
            'syntheticDatabases':11,'existingWalAndShmReadonlyPositive':True,'partialWalRefused':True,
            'actualAuthorizerRefusals':True,'actualChildKillAndReapVirtualDeadline':True,
            'retainedDataAccessed':False,'privateAdmissionEstablished':False}
    finally:
        cleanup=[]
        for target in reversed(mounts):
            try:need(run(['/usr/bin/umount','--',str(target)]).returncode==0)
            except BaseException:cleanup.append('unmount')
        for target in reversed(owned):
            try:
                if target.is_dir():target.rmdir()
                else:target.unlink()
            except BaseException:cleanup.append('path')
        try:shutil.rmtree(work)
        except BaseException:cleanup.append('work')
        need(not cleanup)
    proof['allOwnedMountsAndPathsRemoved']=True
    print(json.dumps(proof,separators=(',',':')))

if __name__=='__main__': main()

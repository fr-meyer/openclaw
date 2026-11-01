"""Synthetic-only Node SQLite proof, run inside the existing admitted namespace.

The existing host source/command owner verifies its complete public manifest
before this entry. Root privileges are required only in its isolated mount,
network and PID namespace; this is not a direct workflow sudo entry.
"""
import argparse, base64, hashlib, json, os, pathlib, shutil, stat, subprocess, sys, tempfile

NODE_SHA='e32e2d16081cf644f88392934288086e7662529d0d43277c34f7aad2207cfafb'
NODE_BYTES=126879696
LEAVES=('metadata_reader.cjs','metadata_supervisor.cjs','test_metadata_reader.cjs',
        'test_metadata_supervisor.cjs','linux_fixture.cjs','test_supervisor_actual_child.cjs','linux_proof.py',
        'schema_init_probe.cjs','source_table.sql')

def need(value):
    if value is not True: raise RuntimeError('synthetic_metadata_proof_refused')

SCHEMA_STAGES=('schema-build','schema-probe','schema-full-long','schema-full-public_table',
               'schema-full-generated_function','schema-full-expression_index','schema-full-above_limit')

def schema_failure(stage,code,stdout,stderr,*,timed_out=False):
    need(stage in SCHEMA_STAGES and type(code)is int)
    stdout=stdout if type(stdout)is bytes else b'';stderr=stderr if type(stderr)is bytes else b''
    def stream(raw):
        return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                'base64':base64.b64encode(raw[:4096]).decode('ascii'),'truncated':len(raw)>4096}
    value={'schema':'ocv.synthetic-schema-child-failure.v1','stage':stage,'exitCode':code,
           'timedOut':timed_out,'stdout':stream(stdout),'stderr':stream(stderr),
           'syntheticOnly':True,'retainedDataAccessed':False,'qualificationEstablished':False}
    raw=json.dumps(value,separators=(',',':'));need(len(raw.encode())<=16384)
    print(raw,flush=True)

def schema_require(result,stage,*,codes=(0,),empty_stdout=False):
    if result.returncode not in codes or result.stderr!=b'' or empty_stdout and result.stdout!=b'':
        schema_failure(stage,result.returncode,result.stdout,result.stderr)
        raise RuntimeError('synthetic_schema_child_refused')
    return result

def run(argv, *, user=False, seconds=70, diagnostic=None):
    def demote(): os.setgroups([]); os.setgid(1000); os.setuid(1000)
    try:
        result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C','LC_ALL':'C','TZ':'UTC'},
            timeout=seconds,check=False,preexec_fn=demote if user else None)
    except subprocess.TimeoutExpired as error:
        if diagnostic is not None:schema_failure(diagnostic,-1,error.stdout,error.stderr,timed_out=True)
        raise
    if diagnostic is not None and (len(result.stdout)>16384 or len(result.stderr)>4096):
        schema_failure(diagnostic,result.returncode,result.stdout,result.stderr)
    need(len(result.stdout)<=16384 and len(result.stderr)<=4096)
    return result

SCHEMA_SOURCE_LEAVES=('schema_init_probe.cjs','metadata_reader.cjs','linux_fixture.cjs','source_table.sql')

def copy_schema_sources(here,work,manifest):
    # Only the fixed four-leaf local require/read closure, never checkout parents.
    need(work.resolve()==work and work.is_dir() and not work.is_symlink())
    directory=work/'schema-programs';directory.mkdir(mode=0o755);directory.chmod(0o755)
    expected={r['path']:r for r in manifest['files']}
    for name in SCHEMA_SOURCE_LEAVES:
        source=here/name;before=source.lstat();row=expected[name]
        fields=lambda v:(v.st_dev,v.st_ino,v.st_uid,v.st_mode,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
        need(source.resolve()==source and stat.S_ISREG(before.st_mode) and before.st_nlink==1 and
             0<before.st_size==row['bytes']<=65536)
        fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb')as stream:
            need(fields(before)==fields(os.fstat(stream.fileno())))
            raw=stream.read(row['bytes']+1)
            need(fields(before)==fields(os.fstat(stream.fileno()))==fields(source.lstat()))
        need(len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'])
        target=directory/name;fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o444)
        with os.fdopen(fd,'wb')as stream:
            need(stream.write(raw)==len(raw));stream.flush();os.fchmod(stream.fileno(),0o444);os.fsync(stream.fileno())
        fact=target.lstat()
        need(target.resolve()==target and stat.S_ISREG(fact.st_mode) and fact.st_nlink==1 and
             fact.st_uid==os.geteuid() and stat.S_IMODE(fact.st_mode)==0o444 and
             fact.st_size==row['bytes'] and hashlib.sha256(target.read_bytes()).hexdigest()==row['sha256'])
    need({p.name for p in directory.iterdir()}==set(SCHEMA_SOURCE_LEAVES) and
         stat.S_IMODE(directory.stat().st_mode)==0o755)
    return directory


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
        need(int(profile['rows'][0]['files']['wal']['identity']['size'])>=32 and
             profile['rows'][1]['files']['wal']['identity']['size']=='0' and
             int(profile['rows'][1]['files']['shm']['identity']['size'])>0 and
             profile['rows'][2]['files']['wal']['state']=='absent')
        # Only tiny synthetic fixture files are hashed; no retained data route.
        synthetic_before={str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in source.rglob('*') if p.is_file()}
        pin=hashlib.sha256(profile_source.read_bytes()).hexdigest()
        actual=run([str(node),'--no-warnings','/run/metadata-supervisor.cjs',pin],user=True)
        need(actual.returncode==0 and actual.stderr==b'');value=json.loads(actual.stdout)
        need(value['status']=='COMPLETED' and value['childCloseObserved'] is True and
            value['streamsEOF'] is True and value['streamsClosed'] is True and
            value['value']['status']=='METADATA_CONSISTENT' and len(value['value']['rows'])==11 and
            value['value']['integrityFreshnessMigrationProductionEstablished'] is False)
        need(b'synthetic-application-record' not in actual.stdout and b'synthetic-01' not in actual.stdout)
        need(synthetic_before=={str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in source.rglob('*') if p.is_file()})
        for argv in ([str(node),'--no-warnings',str(here/'test_metadata_reader.cjs')],
                     [str(node),'--no-warnings',str(here/'test_metadata_supervisor.cjs')],
                     [str(node),'--no-warnings',str(here/'linux_fixture.cjs'),'deny'],
                     [str(node),'--no-warnings',str(here/'test_supervisor_actual_child.cjs')]):
            r=run(argv);need(r.returncode==0 and r.stderr==b'')
        # Reopen valid persisted synthetic/public-source schemas using the
        # full reader's exact constructor limits and authorizer, not CI78's
        # earlier tiny persisted-schema inputs. No retained database is accessed.
        init_root=work/'schema-init'
        schema_source=copy_schema_sources(here,work,manifest)
        r=run([str(node),'--no-warnings',str(schema_source/'schema_init_probe.cjs'),'build',str(init_root)],diagnostic='schema-build')
        schema_require(r,'schema-build',empty_stdout=True)
        init_before={p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in init_root.iterdir()}
        r=run([str(node),'--no-warnings',str(schema_source/'schema_init_probe.cjs'),'run',str(init_root)],user=True,diagnostic='schema-probe')
        try:
            schema_require(r,'schema-probe');initialization=json.loads(r.stdout)
            need(initialization['schema']=='ocv.synthetic-sqlite-schema-init-witness.v1' and
                 initialization['limits']=={'length':262144,'sqlLength':8192,'attach':0} and
                 initialization['readonly'] is True and initialization['extensionsDisabled'] is True and
                 initialization['authorizerUnchanged'] is True and initialization['sourceCopiesReadableByReader']is True and initialization['privateDataAccessed'] is False and
                 initialization['applicationRowsReturned'] is False and
                 all(x['initializationPassed']is True and x['versionValidated']is True for x in initialization['cases'])and
                 [x['name']for x in initialization['cases']]==['small','long','public_table','generated_function','expression_index'] and
                 all(x['statementCloseFailureCode']is None and x['databaseCloseFailureCode']is None and
                     (x['connectionReturned']is True and x['connectionClosed']is True or
                      x['connectionReturned']is False and x['connectionClosed']is False and
                      type(x['failure'])is dict and x['failure']['primitive']==1)for x in initialization['cases']) and
                 initialization['exactReadonlyAuthorizerNegativeCases']==7 and initialization['negativeCheckFailureCode']is None)
        except BaseException:
            if r.returncode==0 and r.stderr==b'':schema_failure('schema-probe',r.returncode,r.stdout,r.stderr)
            raise
        need(init_before=={p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in init_root.iterdir()})
        # Existing-mounted WAL works; removing that required SHM from the
        # profile refuses before any SQLite database can be opened.
        partial=json.loads(json.dumps(profile));partial['rows'][0]['files']['shm']={'state':'absent','identity':None}
        profile_source.chmod(0o644);profile_source.write_text(json.dumps(partial,separators=(',',':')));profile_source.chmod(0o444)
        badpin=hashlib.sha256(profile_source.read_bytes()).hexdigest()
        refused=run([str(node),'--no-warnings','/run/metadata-supervisor.cjs',badpin],user=True)
        refusal=json.loads(refused.stdout)
        need(refused.returncode==1 and refusal['status']=='REFUSED'and refusal['failure']['code']==103 and refusal['failure']['ordinal']==-1)
        # The original tiny-schema positive and partial-WAL negative above
        # remain intact. Now exercise the unchanged full reader on each new
        # persisted row0 schema, not just a port or an initialization imitation.
        for suffix in ('-shm','-wal',''):
            target=metadata/'db-00'/('main.sqlite'+suffix)
            need(run(['/usr/bin/umount','--',str(target)]).returncode==0);mounts.remove(target)
            if suffix:target.unlink();owned.remove(target)
        full_cases=[];main_target=metadata/'db-00/main.sqlite'
        for name in ('long','public_table','generated_function','expression_index','above_limit'):
            if main_target in mounts:
                need(run(['/usr/bin/umount','--',str(main_target)]).returncode==0);mounts.remove(main_target)
            bind(init_root/(name+'.sqlite'),main_target)
            current=json.loads(json.dumps(profile));current['rows'][0]['files']={
              'main':ident(main_target),**{k:{'state':'absent','identity':None}for k in('wal','shm','journal')}}
            profile_source.chmod(0o644);profile_source.write_text(json.dumps(current,separators=(',',':')));profile_source.chmod(0o444)
            current_pin=hashlib.sha256(profile_source.read_bytes()).hexdigest()
            r=run([str(node),'--no-warnings','/run/metadata-supervisor.cjs',current_pin],user=True,diagnostic='schema-full-'+name)
            try:
                schema_require(r,'schema-full-'+name,codes=(0,1));full=json.loads(r.stdout)
                need(r.stderr==b'' and full['childCloseObserved']is True and full['ownedChildUncertain']is False and
                     full['streamsEOF']is True and full['streamsClosed']is True and full['childSignal']is None and
                     full['deadlineReached']is False and full['killSubmitted']is False and full['errorClass']==0)
                failure=full['failure']
                if full['status']=='COMPLETED':
                    need(name!='above_limit' and r.returncode==full['childExitCode']==0 and failure is None and
                         full['value']['status']=='METADATA_CONSISTENT' and len(full['value']['rows'])==11)
                else:
                    need(name=='above_limit' and full['status']=='REFUSED' and
                         r.returncode==full['childExitCode']==1 and full['value']is None and
                         type(failure)is dict and failure['ordinal']==0 and failure['stage']==4 and failure['code']==11 and
                         set(failure)=={'ordinal','pathSha256','stage','code','sqliteVersion'})
            except BaseException:
                if r.returncode in(0,1)and r.stderr==b'':schema_failure('schema-full-'+name,r.returncode,r.stdout,r.stderr)
                raise
            full_cases.append({'name':name,'status':full['status'],'failure':failure,
              'childClosedAndReaped':True,'deadlineReached':False})
        need(init_before=={p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in init_root.iterdir()})
        proof={'schema':'ocv.generic-retained-metadata-linux-proof.v1','status':'PASS',
            'nodeSha256':NODE_SHA,'sourceManifestSha256':args.source_manifest_sha256,
            'syntheticDatabases':11,'existingWalAndShmReadonlyPositive':True,'zeroWalWithExistingShmReadonlyPositive':True,
            'syntheticDatabaseFilesUnchanged':True,'sourcePortSuitesExecuted':True,'partialWalRefused':True,
            'actualAuthorizerRefusals':True,'actualChildKillAndReapVirtualDeadline':True,
            'schemaInitFullReaderOptionsExercised':True,'schemaInitPublicSourceFixtureExercised':True,
            'schemaInitPrimitiveAndAuthorizerDiagnosticsComplete':True,'schemaInitSyntheticFilesUnchanged':True,
            'schemaInitBoundedSqlLength8192AuthorizerUnchanged':True,'schemaInitWithinBoundAllCompleted':True,'schemaInitAbove8192Refused':True,'schemaInitialization':initialization,
            'schemaInitFullReaderPersistedCasesExercised':True,'fullReaderSchemaInitialization':full_cases,
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

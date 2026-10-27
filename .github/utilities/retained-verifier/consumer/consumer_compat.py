"""Actual retained-consumer algorithms, public synthetic fixtures only.

This is compatibility testing, not scanning, attestation authentication,
private-report acceptance, image execution or Linux isolation proof.
"""
from contextlib import contextmanager, redirect_stdout
import base64
import copy
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import sys
import tarfile
import tempfile
import time
import types
import unittest
from unittest.mock import patch

SOURCE='8770609a78d68f6b53607ce3199baf0aa08687cf'
SCANNER='d658c890f5684b2dbe8468449a7fed17bb46055d'
PINS={
 'hosted_export.py':('hosted_export.py','4469f534a4c61678e951a1542e6e5caa69ac8fd7431729b6cfedeaef0f084e3c'),
 'hosted_privacy.py':('hosted_privacy.py','b6f9d4736b0051361aacc7c56f562de135a41c9662babae7e20cbdee436495b9'),
 'public-member-comparisons-v105-workboard.json':('public-member-comparisons-v105-workboard.json','b172ee3c6cdf34d983cdb4b1452924b5931762020b94596b4405e7a6fdeb03df')}
MAX_SECONDS=240


def digest(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


class CompatibilityRefusal(ValueError):pass
class CompatibilityTimeout(RuntimeError):pass


def need(ok,code):
    if not ok:raise CompatibilityRefusal(code)


def _identity(info):
    return tuple(getattr(info,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def _source_bytes(path,expected):
    need(path.resolve()==path,'source_path')
    info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and not(info.st_mode&0o022) and 0<info.st_size<=131072,'source_identity')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);chunks=[];size=0
        while True:
            data=os.read(fd,min(65536,131073-size))
            if not data:break
            chunks.append(data);size+=len(data);need(size<=131072,'source_bound')
        after=os.fstat(fd)
    finally:os.close(fd)
    raw=b''.join(chunks)
    need(_identity(info)==_identity(before)==_identity(after)==_identity(path.lstat()) and len(raw)==info.st_size,'source_changed')
    need(digest(raw)==expected,'source_pin')
    return raw


def _load(source_root):
    root=Path(source_root)
    need(root.is_absolute() and root.resolve()==root and root.is_dir(),'source_root')
    source={name:_source_bytes(root/name,pin) for name,(_relative,pin) in PINS.items()}
    saved={name:sys.modules.get(name) for name in ('hosted_privacy','hosted_export')}
    need(all(value is None for value in saved.values()),'ambient_consumer_module')
    modules={}
    try:
        for name in ('hosted_privacy','hosted_export'):
            module=types.ModuleType(name);module.__file__=str(root/(name+'.py'))
            sys.modules[name]=module
            exec(compile(source[name+'.py'],module.__file__,'exec'),module.__dict__)
            modules[name]=module
    finally:
        for name,value in saved.items():
            if value is None:sys.modules.pop(name,None)
            else:sys.modules[name]=value
    plan=json.loads(source['public-member-comparisons-v105-workboard.json'])
    return modules['hosted_privacy'],modules['hosted_export'],plan


@contextmanager
def _deadline():
    started=time.monotonic()
    old_handler=signal.getsignal(signal.SIGALRM)
    old_delay,old_interval=signal.getitimer(signal.ITIMER_REAL)
    need(old_interval==0,'outer_interval_timer')
    state={'cleanupErrors':[],'outerExpired':False};changed=False
    def expired(_sig,_frame):raise CompatibilityTimeout('compatibility_deadline')
    delay=min(MAX_SECONDS,old_delay) if old_delay>0 else MAX_SECONDS
    need(delay>0,'compatibility_deadline')
    try:
        signal.signal(signal.SIGALRM,expired);changed=True
        signal.setitimer(signal.ITIMER_REAL,delay)
        yield state
    finally:
        if changed:
            for operation in (lambda:signal.setitimer(signal.ITIMER_REAL,0),
                              lambda:signal.signal(signal.SIGALRM,old_handler)):
                try:operation()
                except BaseException as error:state['cleanupErrors'].append(type(error).__name__)
            remaining=old_delay-(time.monotonic()-started)
            if old_delay>0 and remaining>0:
                try:signal.setitimer(signal.ITIMER_REAL,remaining)
                except BaseException as error:state['cleanupErrors'].append(type(error).__name__)
            elif old_delay>0:state['outerExpired']=True


class TinyOCI:
    """Seven actual content-addressed blobs, one small valid public TAR layer."""
    def __init__(self,path,privacy,plan):
        self.path=path;self.p=privacy;self.blobs={};self.nodes={}
        (path/'blobs/sha256').mkdir(parents=True)
        buffer=io.BytesIO()
        with tarfile.open(fileobj=buffer,mode='w') as archive:
            data=b'Public synthetic retained-consumer test.\n'
            member=tarfile.TarInfo('usr/share/synthetic-fixture.txt');member.size=len(data);member.mode=0o444
            archive.addfile(member,io.BytesIO(data))
        self.layer=self.blob(buffer.getvalue(),privacy.TAR)
        config=self.blob(canonical({'architecture':'amd64','os':'linux','config':{
            'Labels':{'org.opencontainers.image.revision':SOURCE},'Env':[]}}),privacy.CONFIG)
        image=self.blob(canonical({'schemaVersion':2,'mediaType':privacy.MANIFEST,
                                  'config':config,'layers':[self.layer]}),privacy.MANIFEST)
        source={'uri':'https://github.com/'+privacy.REPOSITORY+'.git#'+SOURCE,'digest':{'sha1':SOURCE}}
        statement={'_type':'https://in-toto.io/Statement/v1','subject':[{'name':'synthetic-image',
            'digest':{'sha256':image['digest'][7:]}}],'predicateType':privacy.PROVENANCE,
            'predicate':{'buildDefinition':{'externalParameters':{'configSource':source},'resolvedDependencies':[source]}}}
        provenance=self.blob(canonical(statement),privacy.ATTESTATION)
        empty=self.blob(b'{}',privacy.EMPTY_CONFIG)
        attestation=self.blob(canonical({'schemaVersion':2,'mediaType':privacy.MANIFEST,
            'artifactType':privacy.ATTESTATION_ARTIFACT,'subject':image,'config':empty,'layers':[provenance]}),privacy.MANIFEST)
        image_entry={**image,'platform':{'os':'linux','architecture':'amd64'}}
        attestation_entry={**attestation,'platform':{'os':'unknown','architecture':'unknown'},
            'annotations':{'vnd.docker.reference.type':'attestation-manifest','vnd.docker.reference.digest':image['digest']}}
        index=self.blob(canonical({'schemaVersion':2,'mediaType':privacy.INDEX,
                                  'manifests':[image_entry,attestation_entry]}),privacy.INDEX)
        roots={'oci-layout':canonical({'imageLayoutVersion':'1.0.0'}),
               'index.json':canonical({'schemaVersion':2,'manifests':[index]})}
        for name,raw in roots.items():(path/name).write_bytes(raw)
        self.index=index['digest'];self.image=image['digest'];self.config=config['digest']
        self.expected_closure=digest(canonical({'schema':'openclaw.oci-closure.v1','sourceSha':SOURCE,
            'indexDigest':self.index,'roots':{n:digest(raw) for n,raw in roots.items()},
            'blobs':sorted(self.blobs.items())}))
        self.receipt=self.clean_receipt(plan)

    def blob(self,raw,media):
        name=digest(raw);(self.path/'blobs/sha256'/name).write_bytes(raw)
        self.blobs['sha256:'+name]=len(raw);self.nodes['sha256:'+name]=raw
        return {'mediaType':media,'digest':'sha256:'+name,'size':len(raw)}

    def clean_receipt(self,plan):
        plan_sha=PINS['public-member-comparisons-v105-workboard.json'][1]
        comparisons=[];qualifications=[]
        for entry in plan['entries']:
            common={'id':entry['id'],'locationSha256':digest(entry['path'].encode('utf-8','surrogatepass')),
                    'memberSha256':entry['memberSha256'],'memberBytes':entry['memberBytes']}
            comparisons.append({**common,'rules':entry['rules'],'status':'matched',
                                'observedMembers':1,'matchedMembers':1,'mismatchedMembers':0})
            for rule in entry['rules']:
                qualifications.append({**common,'sourceSha':SOURCE,'planSha256':plan_sha,'rule':rule,'memberOccurrences':1})
        return {'schema':'openclaw.hosted-privacy.v2','status':'passed','sourceSha':SOURCE,'toolingSha':SCANNER,
            'indexDigest':self.index,'imageDigest':self.image,'configDigest':self.config,
            'findingSummary':{'unit':self.p.COUNT_UNIT,'total':0,'byRule':dict.fromkeys(self.p.FINDING_RULES,0),
                              'byUnit':dict.fromkeys(self.p.FINDING_UNITS,0)},
            'inspectionComplete':True,'findings':[],'representativesTruncated':False,'representativeLimit':64,
            'locationIndex':[],'locationIndexTruncated':False,'locationIndexLimit':self.p.MAX_LOCATION_ROWS,
            'locationIndexByteLimit':self.p.MAX_LOCATION_BYTES,
            'publicMemberComparisons':{'schema':'openclaw.public-member-comparison-results.v1','sourceSha':SOURCE,
                'planSha256':plan_sha,'diagnosticOnly':True,'records':comparisons,'inspectionComplete':True},
            'publicMemberQualification':{'schema':'openclaw.public-member-qualification.v1','sourceSha':SOURCE,
                'planSha256':plan_sha,'records':qualifications,'inspectionComplete':True,'status':'satisfied'}}



def _suite(privacy,export,plan,scratch):
    class ConsumerCases(unittest.TestCase):
        def setUp(self):
            self.privacy=privacy;self.export=export;self.plan=plan
            self.tmp=tempfile.TemporaryDirectory(prefix='case-',dir=scratch);self.addCleanup(self.tmp.cleanup)
            self.base=Path(self.tmp.name);self.fixture=TinyOCI(self.base/'oci',self.privacy,self.plan)
            self.report=self.base/'synthetic-privacy.json';self.write_report()

        def write_report(self):
            raw=canonical(self.fixture.receipt);self.report.write_bytes(raw);self.report_hash=digest(raw)

        def check(self,*,expected_report_hash=None):
            stdout=io.StringIO()
            args=['--privacy',str(self.report),'--sha256',expected_report_hash or self.report_hash,
                  '--source-sha',SOURCE,'--tooling-sha',SCANNER,'--index-digest',self.fixture.index,
                  '--oci',str(self.fixture.path)]
            # RetainedClosure must never use the full scanner's TAR extraction path.
            with patch.object(self.privacy.tarfile,'open',side_effect=AssertionError('unexpected layer expansion')),redirect_stdout(stdout):
                code=self.export.check_privacy(args)
            return code,json.loads(stdout.getvalue())

        def test_actual_check_and_retained_closure_pass_tiny_typed_graph(self):
            code,proof=self.check()
            self.assertEqual(code,0)
            self.assertEqual(proof,{'status':'passed','privacyReceiptSha256':self.report_hash,
                                   'ociClosureSha256':self.fixture.expected_closure})
            self.assertEqual(len(self.fixture.blobs),7)
            closure=self.export.RetainedClosure(self.fixture.path,self.fixture.index,SOURCE,SCANNER)
            with patch.object(self.privacy.tarfile,'open',side_effect=AssertionError('unexpected layer expansion')):
                self.assertEqual(closure.closure_digest(),self.fixture.expected_closure)
            self.assertEqual(closure.counts['expandedBytes'],0)
            self.assertEqual(closure.counts['members'],0)

        def test_changed_blob_is_rejected_by_actual_graph_rehash(self):
            path=self.fixture.path/'blobs/sha256'/self.fixture.layer['digest'][7:]
            raw=path.read_bytes();path.write_bytes(b'X'+raw[1:])
            code,result=self.check();self.assertEqual(code,1)
            self.assertEqual(result['diagnostic']['phase'],'closure')
            self.assertEqual(result['diagnostic']['subcheck'],'digest')

        def test_changed_report_bytes_do_not_match_old_expected_hash(self):
            expected=self.report_hash;self.report.write_bytes(self.report.read_bytes()+b'\n')
            code,result=self.check(expected_report_hash=expected);self.assertEqual(code,1)
            self.assertEqual(result['diagnostic']['code'],'privacy_binding_changed')

        def test_rehashed_report_with_semantic_findings_is_still_refused(self):
            finding=self.fixture.receipt['findingSummary'];finding['total']=1
            finding['byRule']['private_runtime_path']=1;finding['byUnit']['byte_input']=1
            self.write_report();code,result=self.check();self.assertEqual(code,1)
            self.assertEqual(result['diagnostic']['code'],'aggregate_findings_or_disagreement')

        def test_rehashed_report_with_changed_qualification_is_refused(self):
            self.fixture.receipt['publicMemberQualification']['records'][0]['memberOccurrences']=2
            self.write_report();code,result=self.check();self.assertEqual(code,1)
            self.assertEqual(result['diagnostic']['phase'],'qualification')
            self.assertEqual(result['diagnostic']['code'],'public_member_qualification_invalid')

        def test_extra_blob_or_nonempty_ingest_is_refused(self):
            extra=self.fixture.path/'blobs/sha256'/('f'*64);extra.write_bytes(b'synthetic extra')
            code,_=self.check();self.assertEqual(code,1)
            extra.unlink();(self.fixture.path/'ingest').mkdir();(self.fixture.path/'ingest'/'extra').write_bytes(b'extra')
            code,_=self.check();self.assertEqual(code,1)

        def test_rehashed_report_selected_image_mismatch_is_refused(self):
            self.fixture.receipt['imageDigest']='sha256:'+'e'*64
            self.write_report();code,result=self.check();self.assertEqual(code,1)
            self.assertEqual(result['diagnostic']['code'],'closure_selected_image_changed')

    return unittest.defaultTestLoader.loadTestsFromTestCase(ConsumerCases)


class _Result(unittest.TestResult):
    def __init__(self):super().__init__();self.fixed=[]
    def _fixed(self,test,err):
        self.fixed.append({'case':test._testMethodName,'type':err[0].__name__[:80]})
        self.stop()
    def addError(self,test,err):super().addError(test,err);self._fixed(test,err)
    def addFailure(self,test,err):super().addFailure(test,err);self._fixed(test,err)


def run_suite(source_root,scratchroot):
    """Run exactly seven source-pinned synthetic cases once, with a hard timer.

    Scratch must be a new child of an already-owned caller directory. This
    function does not issue any native/execution authority or accept a saved
    verdict. The caller owns outer lifecycle and separately verifies Linux.
    """
    began=time.monotonic();scratch=Path(scratchroot)
    need(scratch.is_absolute() and scratch.parent.resolve()==scratch.parent and not os.path.lexists(scratch),'scratch_fresh')
    privacy,export,plan=_load(source_root)
    scratch.mkdir(mode=0o700)
    result=_Result();timed=False;timer_state={'cleanupErrors':[],'outerExpired':False}
    try:
        with _deadline() as timer_state:_suite(privacy,export,plan,scratch).run(result)
    except CompatibilityTimeout:
        timed=True
    elapsed=time.monotonic()-began
    need(math.isfinite(elapsed) and elapsed>=0,'clock')
    failures=result.fixed[:16]
    if timed:failures.append({'case':'suite','type':'CompatibilityTimeout'})
    if timer_state['cleanupErrors']:failures.append({'case':'timer','type':'TimerRestoreError'})
    if timer_state['outerExpired']:failures.append({'case':'timer','type':'OuterDeadline'})
    passed=result.testsRun==7 and not failures and not result.errors and not result.failures and elapsed<=MAX_SECONDS
    return {'schema':'ocv.consumer-compat.v1','status':'passed' if passed else 'failed','testsRun':result.testsRun,
            'failures':failures,'sourceHashes':{name:pin for name,(_path,pin) in PINS.items()},
            'elapsedMilliseconds':int(elapsed*1000),'fixtureOnly':True,'nativeProof':False}


if __name__=='__main__':raise SystemExit('ci_import_only')

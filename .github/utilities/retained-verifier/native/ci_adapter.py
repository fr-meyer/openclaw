"""One CI-only injected unit sequence. No live command/kernel port is supplied."""
import datetime as dt
import re
import ci_probe as probe
import ci_profile as profile
from ci_custody import Custody
from ci_protocol import Budget,Refusal,canonical,closed,decode,require,sha,stamp,utc
import ci_fixture as fixture
import ci_worker as worker
ARMED=False
CI_CONTEXT_MANIFEST_SHA256=None


class Reader:
    """Actual probe boundary; all syscalls come only from the injected owner.

    No NativeReader ARM bypass. This type has no os/proc/subprocess operations.
    Future native implementation must be separately source-bound to its unit.
    """
    def __init__(self,kernel,expected):
        self.kernel=kernel;self.pid=expected['pid'];self.cgroup='/sys/fs/cgroup'+expected['cgroupPath']
    def allowed(self,path):
        return (path in ('/proc','/proc/sys/kernel/random/boot_id') or
          re.fullmatch('/proc/[1-9][0-9]*/status',path) is not None or path.startswith('/proc/'+str(self.pid)+'/') or
          path.startswith(self.cgroup+'/'))
    def call(self,name,path,*args):
        require(self.allowed(path) and '..' not in path.split('/'),'ci.reader_path')
        return getattr(self.kernel,name)(path,*args)
    def read(self,path,cap):return self.call('read',path,cap)
    def readlink(self,path):return self.call('readlink',path)
    def stat(self,path):return self.call('stat',path)
    def listdir(self,path,cap):return self.call('listdir',path,cap)
def unit_binding(actual, expected, context, properties_sha):
    closed(actual, {"unitName", "DynamicUser", "User", "Group", "MainPID", "UID", "GID",
                    "InvocationID", "ControlGroup", "propertiesSha256", "staticNameAbsent", "MountFlags"}, "unit_schema")
    require(actual["unitName"] == context["unitName"] and actual["DynamicUser"] is True and
            actual["User"] == actual["Group"] == context["identityName"] and
            actual["staticNameAbsent"] is True and actual["propertiesSha256"] == properties_sha and
            type(actual["MountFlags"]) is int and actual["MountFlags"] == 262144 and context["mountPropagation"] == "private",
            "unit_properties_binding")
    require(actual["MainPID"] == expected["pid"] and actual["UID"] == expected["uid"] and
            actual["GID"] == expected["gid"] and actual["InvocationID"] == expected["invocationId"] and
            actual["ControlGroup"] == expected["cgroupPath"] and expected["sessionId"] == context["sessionId"] and
            expected["bootId"] == context["bootId"] and expected["unitName"] == context["unitName"] and
            expected["identityName"] == context["identityName"] and
            expected["profileSha256"] == context["profileSha256"], "unit_process_join")

def gate(context, context_raw, proof, now):
    require(proof["sessionId"] == context["sessionId"] and proof["bootId"] == context["bootId"] and
            proof["unitName"] == context["unitName"] and proof["profileSha256"] == context["profileSha256"],
            "gate_proof_join")
    clean = {k: v for k, v in proof.items() if k != "factsSha256"}
    require(proof["factsSha256"] == sha(canonical(clean)), "gate_proof_hash")
    expires = min(now + dt.timedelta(seconds=30), utc(context["workerDeadlineUtc"]))
    require(expires > now, "gate_deadline")
    joined = ("sessionId", "unitName", "bootId", "vmId", "identityName", "workerDeadlineUtc", "profileSha256",
              "entrySha256", "workerSha256", "runtimeManifestSha256", "inputManifestSha256", "sourceSha",
              "scannerSha", "indexDigest", "privacySha256", "privacyBytes", "consumerCode", "mountPropagation")
    value = {k: context[k] for k in joined}
    value.update(schema="openclaw.retained-verifier-admission.v1", contextSha256=sha(context_raw),
                 pid=proof["pid"], startTimeTicks=proof["startTimeTicks"], uid=proof["uid"], gid=proof["gid"],
                 invocationId=proof["invocationId"], checkedAt=stamp(now), expiresAt=stamp(expires),
                 proofSha256=proof["factsSha256"], status="passed", inputReleased=True)
    require(len(canonical(value)) <= 16384, "gate_size")
    return value

def ready_binding(raw, context, context_raw, expected):
    value = closed(decode(raw, 4096), {"schema", "status", "pid", "uid", "gid", "contextSha256", "workerSha256"},
                   "controller_ready_schema")
    require(value == {"schema": "openclaw.retained-verifier-ready.v1", "status": "ready",
                      "pid": expected["pid"], "uid": expected["uid"], "gid": expected["gid"],
                      "contextSha256": sha(context_raw), "workerSha256": context["workerSha256"]},
            "controller_ready_binding")

class Adapter:
    """Logic is executable only through explicit injected dependencies.

    The default CLI cannot issue effects. A future CI binding/manifest is not
    caller JSON authority; no cloud or live Mac boundary exists in this source.
    """
    def __init__(self,port,directory,*,clock):
        self.port,self.clock=port,clock;self.custody=Custody(directory);self.used=False
        self.intents=set();self.closed=False;self.result=None;self.budget=Budget(300,clock.monotonic)
    def once(self,name,*args):
        require(name not in self.intents,'ci.effect_once')
        if name not in {'stop_owned_unit_normally','owned_cgroup_empty','collect_owned_outputs','copied_report_once',
                        'retire_only_copied_inputs','normal_guest_shutdown'}:self.budget.remaining()
        self.intents.add(name)
        return getattr(self.port,name)(*args)
    def run(self,context_raw):
        require(not self.used,'ci.attempt_once');self.used=True
        submitted=False;staged=False;outcome=None;context=None;phase='context';proof=None
        result={'status':'refused','phase':phase,'reason':'ci.not_started','nativeProof':False}
        try:
            context=decode(context_raw,16384)
            worker.validate_context(context,self.clock.utc(),self.port.code)
            phase='metadata'
            metadata=self.once('admit_metadata_before_unit')
            require(type(metadata) is dict and metadata.get('status')=='classified' and
              metadata.get('fixtureOnly') is True and metadata.get('nativeAuthenticationIssued') is False,
              'ci.metadata_binding')
            phase='preparation'
            staged=self.once('stage_public_inputs',context)
            require(type(staged) is dict and set(staged)=={'manifest','propertiesSha256'} and
              sha(canonical(staged['manifest']))==context['inputManifestSha256'],'ci.stage_binding')
            self.custody.preserve('staging-manifest',canonical(staged['manifest']))
            phase='unit_submit';submitted=True
            self.once('start_unit_once',context)
            phase='admission'
            expected,unit=self.once('owned_observation',context)
            unit_binding(unit,expected,context,staged['propertiesSha256'])
            ready_binding(self.once('ready_once'),context,context_raw,expected)
            proof=probe.collect_and_validate(Reader(self.port.kernel,expected),expected)
            self.custody.preserve('host-result',canonical(proof))
            require(self.once('source_anchor_recheck') is True,'ci.anchor_recheck_required')
            record=gate(context,context_raw,proof,self.clock.utc())
            phase='input_gate';self.once('release_inputs_and_gate',canonical(record))
            phase='consumer';outcome=self.once('wait_once',min(240,self.budget.remaining()-30))
            self.budget.remaining()
            self.preserve_outputs(outcome)
            report=self.once('copied_report_once')
            self.custody.preserve('report',report)
            require(sha(report)==fixture.REPORT_SHA and len(report)==context['privacyBytes'],'ci.report_changed')
            proof=self.custody.accept_consumer(outcome['stdout'],outcome['stderr'],returncode=outcome['returncode'],
              timed_out=outcome['timedOut'],context_sha=sha(context_raw),report_sha=fixture.REPORT_SHA,
              expected_closure_sha=fixture.CLOSURE_SHA,pid=expected['pid'],uid=expected['uid'],gid=expected['gid'],
              expected_worker_sha=context['workerSha256'])
            result={'status':'passed','phase':phase,'reason':None,'nativeProof':False,'proof':proof}
        except BaseException as error:
            reason=error.code if isinstance(error,Refusal) else 'ci.boundary_unknown'
            result={'status':'refused','phase':phase,'reason':reason,'nativeProof':False}
            try:self.custody.preserve('host-diagnostics',canonical({'phase':phase,'reason':reason,
              'exceptionType':type(error).__name__,'facts':error.facts if isinstance(error,Refusal) else {},
              'boundary':self.port.failure_evidence() if callable(getattr(self.port,'failure_evidence',None)) else {}}))
            except BaseException:result['custodyFailure']=True
        finally:
            # Only the submitted owned unit is stopped. Evidence recovery and
            # outer guest shutdown remain independent of worker/custody result.
            empty=False;custody_complete=False
            if submitted:
                try:self.once('stop_owned_unit_normally',context['unitName']);empty=self.once('owned_cgroup_empty') is True
                except BaseException:result['unitStopUncertain']=True
                if not {'worker-stdout','worker-stderr'}<=set(self.custody.rows):
                    try:self.preserve_outputs(self.once('collect_owned_outputs'))
                    except BaseException:result['custodyFailure']=True
            if staged and 'report' not in self.custody.rows:
                try:self.custody.preserve('report',self.once('copied_report_once'))
                except BaseException:result['custodyFailure']=True
            required={'staging-manifest','report','worker-stdout','worker-stderr'}
            custody_complete=(required<=set(self.custody.rows) and all(not r['truncated'] for r in self.custody.rows.values())
              and not result.get('custodyFailure'))
            result['ownedUnitEmpty']=empty;result['custodyComplete']=custody_complete
            if empty and custody_complete:
                try:self.once('retire_only_copied_inputs')
                except BaseException:result['copiesRetained']=True
            try:
                close=self.once('normal_guest_shutdown')
                require(type(close) is dict and set(close)=={'shutdownRequested','outerExitPending'} and
                  close['shutdownRequested'] is True and close['outerExitPending'] is True,'ci.shutdown_request_uncertain')
                result['closeout']=close
            except BaseException:result['closeout']={'status':'uncertain'}
            if result['status']=='passed' and (not empty or not custody_complete or result['closeout'].get('status')=='uncertain'):
                result.update(status='refused',reason='ci.closeout_or_custody_incomplete')
            result['unitStatus']=result['status']
            if result['status']=='passed':result['status']='unit_passed_pending_outer_exit'
            self.closed=True;self.result=result
        return result
    def preserve_outputs(self,value):
        require(type(value) is dict and set(value)=={'stdout','stderr','returncode','timedOut'},'ci.outcome_schema')
        for role,key in (('worker-stdout','stdout'),('worker-stderr','stderr')):
            if role not in self.custody.rows:self.custody.preserve(role,value[key])


def main():
    require(ARMED is True and CI_CONTEXT_MANIFEST_SHA256 is not None,'ci.adapter_disarmed')
    raise Refusal('ci.native_capability_unissued')


if __name__=='__main__':main()

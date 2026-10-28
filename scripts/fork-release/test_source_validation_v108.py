"""Closed successor campaign boundaries; synthetic APIs/runtimes and temporary Git only."""
import base64
import copy
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import itertools
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.error
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("v108_successor_driver", Path(__file__).with_name("source_validation_v108.py"))
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)
SOURCE_LITERAL = driver.SOURCE
PIPELINE_ROOT = Path(__file__).resolve().parents[2]
SOURCE, TREE, HEAD, OLD_HEAD, MERGE = (c * 40 for c in "defab")
NOW = datetime(2026, 10, 28, 5, tzinfo=timezone.utc)


def historical_v3_request():
    """Immutable published historical input, never the operational v4 request."""
    raw = Path(__file__).with_name("fixtures").joinpath("v108-source-request-v3-0dd.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != "f4328240f75c6a97471843fb4af8e3ee4ceeb93c2fcef98f3e0f9c59ee4fcd3c":
        raise AssertionError("historical v3 fixture digest changed")
    return driver.read_json(raw)


def operational_v4_request():
    """Actual tracked closed request; legacy fixtures never stand in for it."""
    value = driver.read_json((PIPELINE_ROOT / driver.REQUEST).read_bytes())
    return copy.deepcopy(driver.validate_request_v4(value, driver.STAGE_PINS))


def request(round_number=2, profiles=None, prior=None):
    return {"schema": "openclaw.fork-source-validation-request.v3", "campaignId": driver.CAMPAIGN,
            "round": round_number, "profiles": [] if profiles is None else profiles,
            "sourceSha": SOURCE, "sourceTree": TREE, "firstSourceSha": SOURCE,
            "firstSourceTree": TREE, "sourceAuthorization": driver.SOURCE_AUTHORIZATION,
            "manifestSha256": "d" * 64, "inventorySha256": "e" * 64,
            "settledUsageSha256": "f" * 64, "sourceWitness": None, "initialResume": None,
            "priorRunIds": list(driver.RETAINED_SOURCE_RUN_IDS) if prior is None else prior}


def event_env():
    repository = {"full_name": driver.REPOSITORY, "private": False}
    event = {"action": "synchronize", "number": 28, "repository": repository,
        "pull_request": {"number": 28, "state": "open", "draft": True,
            "head": {"ref": driver.BRANCH, "sha": HEAD, "repo": repository},
            "base": {"ref": driver.BASE_BRANCH, "sha": driver.BASE, "repo": repository}}}
    env = {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux", "RUNNER_ENVIRONMENT": "github-hosted",
           "GITHUB_EVENT_NAME": "pull_request", "GITHUB_RUN_ATTEMPT": "1",
           "GITHUB_REPOSITORY": driver.REPOSITORY, "GITHUB_REF": "refs/pull/28/merge",
           "GITHUB_WORKFLOW_REF": driver.REPOSITORY + "/" + driver.WORKFLOW + "@refs/pull/28/merge",
           "GITHUB_WORKFLOW_SHA": MERGE, "GITHUB_RUN_ID": "999", "GITHUB_JOB": "admission"}
    return copy.deepcopy(event), env


_JOB_IDS = itertools.count(10000)


def job(name, minutes=1, conclusion="success", acquired=True, legacy_label=False):
    start = NOW - timedelta(hours=3)
    return {"id": next(_JOB_IDS), "name": name, "status": "completed", "conclusion": conclusion, "run_attempt": 1,
            "runner_id": 42 if acquired else 0, "runner_name": "hosted" if acquired else "",
            "runner_group_name": "GitHub Actions" if acquired else None,
            "labels": ["ubuntu-latest" if legacy_label else "ubuntu-24.04"] if acquired else [],
            "steps": [] if not acquired else [{"name": "synthetic"}],
            "started_at": start.isoformat().replace("+00:00", "Z"),
            "completed_at": (start + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")}


def source_jobs(minutes=300, legacy=True):
    caps = driver.LEGACY_PROFILE_MINUTES if legacy else driver.PROFILE_MINUTES
    if minutes == 0:
        return {"total_count": 3, "jobs": [job(n, 0, "skipped", False) for n in
                    ("admission", "source (${{ matrix.profile }})", "final")]}
    if legacy and minutes == 300:
        amounts = [16,17,14,15,16,16,26,24,26,61,40,13]
        # Profile ordering is fixed independently of actual source execution.
        amounts = dict(zip(caps, amounts))
        amounts["dependency"] = 13
        amounts["types-production"] = 17
        amounts["types-tests"] = 14
        amounts["types-scripts"] = 15
        amounts["workboard-1"] = amounts["workboard-2"] = 16
        amounts["models-1"], amounts["models-2"] = 26,24
        amounts["sqlite"], amounts["doctor"], amounts["memory"] = 26,61,40
        amounts["pipeline-contracts"] = 13
        jobs = [job("admission",13),job("final",6,"cancelled")]
        jobs += [job("source ("+p+")",m,"cancelled" if p=="doctor" else "failure" if p in
                     ("dependency","types-tests") else "success") for p,m in amounts.items()]
    elif legacy and minutes == 92:
        jobs = [job("admission",14),job("final",6,"cancelled")]
        jobs += [job("source ("+p+")",6,"failure") for p in caps]
    else:
        jobs = [job("admission"),job("final")]+[job("source ("+p+")") for p in caps]
    return {"total_count":len(jobs),"jobs":jobs}


def run_record(run_id, head, path, conclusion="success", status="completed"):
    repo={"full_name":driver.REPOSITORY,"private":False}
    return {"id":int(run_id),"head_sha":head,"path":path,"event":"pull_request",
            "status":status,"conclusion":conclusion,"run_attempt":1,
            "repository":repo,"head_repository":repo,"head_branch":driver.BRANCH,
            "display_title":driver.CAMPAIGN,"created_at":"2026-10-28T05:00:00Z","pull_requests":[{"number":28}]}


def history_fixture(root, req):
    event, env = event_env()
    (root/driver.WORKFLOW).parent.mkdir(parents=True,exist_ok=True)
    (root/driver.WORKFLOW).write_bytes(b"frozen workflow")
    usage_rows=[]; runs=[]; tables={}
    for i,rid in enumerate(driver.RETAINED_SOURCE_RUN_IDS):
        head=format(i+1,"040x");conclusion=("skipped","cancelled","failure")[i]
        run=run_record(rid,head,driver.WORKFLOW,conclusion)
        table=source_jobs((0,92,300)[i]);tables[rid]=table;runs.append(run)
        usage_rows.append({"id":rid,"headSha":head,"path":driver.WORKFLOW,"event":"pull_request",
                          "conclusion":conclusion,"roundedMinutes":(0,92,300)[i]})
    for i in range(54):
        rid=str(2000+i);head=format(100+i,"040x");minutes=1 if i<33 else 0
        conclusion="success" if minutes else "skipped"
        path=".github/workflows/synthetic-metadata.yml";runs.append(run_record(rid,head,path,conclusion))
        tables[rid]={"total_count":1,"jobs":[job("metadata",minutes,conclusion,bool(minutes),legacy_label=i==0)]}
        usage_rows.append({"id":rid,"headSha":head,"path":path,"event":"pull_request",
                          "conclusion":conclusion,"roundedMinutes":minutes})
    usage={"schema":"openclaw.v108.settled-usage.v1","observedAt":"2026-10-28T04:15:41Z",
           "spentRunnerMinutes":425,"runs":usage_rows}
    raw=json.dumps(usage,sort_keys=True).encode();path=root/driver.SETTLED_USAGE;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
    req["settledUsageSha256"]=hashlib.sha256(raw).hexdigest()
    runs.append(run_record("999",HEAD,driver.WORKFLOW,None,"in_progress"))
    own_job=job("admission");own_job.update(run_id=999,status="in_progress",conclusion=None,
        started_at=(NOW-timedelta(minutes=1)).isoformat().replace("+00:00","Z"),completed_at=None)
    tables["999"]={"total_count":1,"jobs":[own_job]}
    responses={"/pulls/28":event["pull_request"],"/git/ref/heads/"+driver.BASE_BRANCH:
               {"ref":"refs/heads/"+driver.BASE_BRANCH,"object":{"type":"commit","sha":driver.TARGET_BRANCH_TIP}}}
    def api(path):
        prefix="/repos/"+driver.REPOSITORY;assert path.startswith(prefix);path=path[len(prefix):]
        if path.startswith("/actions/runs?branch="):
            return {"total_count":len(runs),"workflow_runs":runs}
        if path.startswith("/actions/runs/") and "/jobs?" in path:
            return tables[path.split("/")[3]]
        return responses[path]
    return req,event,env,responses,api,runs,tables


class SourceValidationTests(unittest.TestCase):
    def setUp(self):
        self.pins=patch.multiple(driver,SOURCE=SOURCE,TREE=TREE,FIRST_SOURCE=SOURCE,FIRST_TREE=TREE)
        self.pins.start();self.addCleanup(self.pins.stop)
    def refused(self,fn,*args):
        with self.assertRaises(driver.release.Refusal):fn(*args)
    def test_full_and_targeted_booking_use_original_lifetime_allowance(self):
        self.assertEqual(driver.round_minutes(driver.validate_request(request())),940)
        req=request(3,["types-tests","doctor-1","doctor-2","doctor-3"],[*driver.RETAINED_SOURCE_RUN_IDS,"998"])
        self.assertEqual(driver.round_minutes(driver.validate_request(req)),250)
        self.assertEqual(425+940+300+135,1800)
        self.assertEqual(len(driver.profiles_for(request())),15)
        broad_types=request(3,["types-tests","types-production","types-scripts"],[*driver.RETAINED_SOURCE_RUN_IDS,"998"])
        self.assertEqual(driver.round_minutes(driver.validate_request(broad_types)),295)
    def test_closed_source_authorization_placeholders_rounds_and_extra_inputs_refuse(self):
        for field,value in (("sourceAuthorization","different"),("schema","old"),("round",4),("round",True),
                            ("sourceSha","PENDING_REVIEWED_SOURCE_SHA"),("sourceTree",HEAD),
                            ("settledUsageSha256","x"*64),("profiles",["doctor"])):
            req=request();req[field]=value;self.refused(driver.validate_request,req)
        for extra in ("command","url","secret","ref"):
            req=request();req[extra]="arbitrary";self.refused(driver.validate_request,req)
        self.refused(driver.read_json,'{"round":2,"round":3}')
        with patch.object(driver,"SOURCE","PENDING_REVIEWED_SOURCE_SHA"):
            self.refused(driver.validate_request,request())
    def test_prior_runs_are_complete_ordered_and_targeted_profiles_bounded(self):
        for prior in ([],list(reversed(driver.RETAINED_SOURCE_RUN_IDS)),[*driver.RETAINED_SOURCE_RUN_IDS,"x"]):
            self.refused(driver.validate_request,request(prior=prior))
        for profiles in ([],["dependency","dependency"],["types-tests","types-production","types-scripts","dependency"],
                         ["doctor"],["$(curl bad)"]):
            self.refused(driver.validate_request,request(3,profiles,[*driver.RETAINED_SOURCE_RUN_IDS,"998"]))
    def test_exact_pr_snapshot_is_not_replaced_by_canonical_target_tip(self):
        event,env=event_env();self.assertEqual(driver.validate_event(event,env),HEAD)
        event["pull_request"]["base"]["sha"]=driver.TARGET_BRANCH_TIP
        self.refused(driver.validate_event,event,env)
    def test_no_local_dispatch_rerun_private_repo_or_other_pr(self):
        event,env=event_env()
        for key,value in (("GITHUB_ACTIONS","false"),("RUNNER_OS","macOS"),("RUNNER_ENVIRONMENT","self-hosted"),
                          ("GITHUB_EVENT_NAME","workflow_dispatch"),("GITHUB_RUN_ATTEMPT","2"),
                          ("GITHUB_WORKFLOW_SHA","main"),("GITHUB_REF","refs/heads/main")):
            self.refused(driver.validate_event,event,dict(env,**{key:value}))
        for field,value in (("draft",False),("state","closed"),("number",29)):
            changed=copy.deepcopy(event);changed["pull_request"][field]=value
            self.refused(driver.validate_event,changed,env)
        changed=copy.deepcopy(event);changed["repository"]["private"]=True
        self.refused(driver.validate_event,changed,env)
    def test_complete_actual425_is_rechecked_before_full940_and_targeted300_reserve(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);args=history_fixture(root,request());req,event,env,responses,api,runs,tables=args
            with patch.object(driver.subprocess,"run"),patch.object(driver,"datetime",wraps=datetime) as clock:
                clock.now.return_value=NOW;budget=driver.history_checks(req,event,env,root,api)
            self.assertEqual(budget["actualSettledRunnerMinutes"],425)
            self.assertEqual(budget["bookedRunnerMinutes"],1800)
            self.assertEqual(budget["futureTargetedReserveMinutes"],300)
            self.assertTrue(budget["historicalConclusionsRetained"])
    def test_settled_state_head_job_usage_and_zero_evidence_cannot_be_discounted(self):
        for mutation in ("running","head","rerun","duration","missing-zero","private","missing-run"):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);req,event,env,responses,api,runs,tables=history_fixture(root,request())
                if mutation=="running":runs[0]["status"]="in_progress"
                elif mutation=="head":runs[0]["head_sha"]=HEAD
                elif mutation=="rerun":runs[0]["run_attempt"]=2
                elif mutation=="duration":tables[driver.RETAINED_SOURCE_RUN_IDS[2]]["jobs"][0]["completed_at"]="2026-10-28T02:14:00Z"
                elif mutation=="missing-zero":tables[driver.RETAINED_SOURCE_RUN_IDS[0]]["jobs"][0].pop("runner_id")
                elif mutation=="private":runs[0]["head_repository"]["private"]=True
                else:runs.pop(0)
                with patch.object(driver.subprocess,"run"),patch.object(driver,"datetime",wraps=datetime) as clock:
                    clock.now.return_value=NOW;self.refused(driver.history_checks,req,event,env,root,api)
    def test_unlisted_source_run_target_drift_expiry_or_preapproval_refuse(self):
        for mutation in ("extra","target","expired","preapproval"):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);req,event,env,responses,api,runs,tables=history_fixture(root,request())
                if mutation=="extra":runs.append(run_record("998",OLD_HEAD,driver.WORKFLOW))
                elif mutation=="target":responses["/git/ref/heads/"+driver.BASE_BRANCH]["object"]["sha"]=HEAD
                elif mutation=="preapproval":runs[-1]["created_at"]="2026-10-28T04:00:00Z"
                with patch.object(driver.subprocess,"run"),patch.object(driver,"datetime",wraps=datetime) as clock:
                    clock.now.return_value=datetime(2026,10,29,1,tzinfo=timezone.utc) if mutation=="expired" else NOW
                    self.refused(driver.history_checks,req,event,env,root,api)
    def test_doctor_three_shards_are_disjoint_complete_and_spread_expensive_files(self):
        paths=["src/commands/doctor-fixture-%03d.test.ts"%i for i in range(421)]
        expensive=["src/commands/doctor-config-preflight.process.test.ts","src/commands/doctor-session.test.ts","src/flows/doctor/other-process.test.ts"]
        paths+=expensive
        full=driver.selected_tests(paths,"doctor");shards=[driver.selected_tests(paths,"doctor-"+str(i)) for i in (1,2,3)]
        self.assertEqual(len(full),424);self.assertEqual(sorted(sum(shards,[])),full)
        self.assertEqual(len(set(sum(shards,[]))),424)
        self.assertTrue(all(len(set(s)&set(expensive))==1 for s in shards))
    def test_compatibility_requires_node_browser_workers_imap_mcp_and_lock_mirror(self):
        paths=[*driver.COMPATIBILITY_TESTS,"test/v108-remediation-security.test.mjs"]
        argv=driver.commands(Path("pipeline"),Path("source"),"compatibility",paths)
        self.assertIn("test/v108-remediation-security.test.mjs",argv[0])
        self.assertEqual(argv[1][1:4],["--import","./scripts/tsx.mjs","scripts/test-projects.mts"])
        self.assertEqual(set(argv[1][4:]),set(driver.COMPATIBILITY_TESTS))
        self.assertEqual(argv[2],["pnpm","deps:npm-lock:check:changed","--base",driver.ORIGINAL_SOURCE,"--head",SOURCE])
        for missing in paths:
            self.refused(driver.commands,Path("pipeline"),Path("source"),"compatibility",[p for p in paths if p!=missing])
    def test_audit_failures_do_not_erase_later_command_outcomes(self):
        with patch.object(driver.subprocess,"run",side_effect=[SimpleNamespace(returncode=n) for n in (1,2,0)]):
            self.assertEqual(driver.run_commands([["audit"],["production"],["regression"]],Path("source"),{}),[1,2,0])
    def test_clean_child_environment_has_no_credentials_or_prebuilt_override(self):
        with tempfile.TemporaryDirectory() as directory:
            env=driver.clean_env(Path(directory),{"PATH":"/usr/bin","GITHUB_TOKEN":"secret","HOME":"private", "GOOGLE_APPLICATION_CREDENTIALS":"private","OPENCLAW_SKIP_BUILD":"1"})
            for key in ("GITHUB_TOKEN","GOOGLE_APPLICATION_CREDENTIALS","OPENCLAW_SKIP_BUILD"):
                self.assertNotIn(key,env)
            self.assertEqual(env["HOME"],directory)
    def test_final_only_sparse_history_and_source_budget_bindings(self):
        workflow=Path(__file__).resolve().parents[2]/driver.WORKFLOW;text=workflow.read_text();before,final=text.split("  final:\n",1)
        self.assertEqual(before.count("path: pipeline\n          fetch-depth: 0"),2)
        self.assertEqual(before.count("path: source\n          fetch-depth: 1"),2)
        self.assertIn("fetch-depth: 1",final)
        self.assertIn("sparse-checkout:",final);self.assertIn("timeout-minutes: 10",final)
        self.assertIn("SOURCE_JOB_STARTED_EPOCH: ${{ steps.source-clock.outputs.started_epoch }}",text)
        self.assertEqual(SOURCE_LITERAL, driver.V4_PARENT_SOURCE)
        self.assertEqual(text.count("ref: "+driver.STAGE_PINS["sourceSha"]),2)
        self.assertNotIn("ref: "+SOURCE_LITERAL,text)
        self.assertNotIn("workflow_dispatch:",text);self.assertNotIn("actions/upload-artifact",text)
        self.assertNotIn("id-token:",text);self.assertNotIn("secrets.",text)
    def test_minimal_merge_acquisition_fetches_two_levels_and_preserves_head(self):
        event,env=event_env();env["PATH"]="/usr/bin";calls=[]
        def git(root,*args):
            if args==("cat-file","-t",MERGE):return b"commit"
            if args==("cat-file","-e",MERGE+"^1^{commit}"):raise subprocess.CalledProcessError(1,args)
            if args==("rev-parse","FETCH_HEAD^{commit}"):return MERGE.encode()
            if args==("rev-parse","HEAD"):return HEAD.encode()
            raise AssertionError(args)
        with patch.object(driver,"git",side_effect=git),patch.object(driver.subprocess,"run",side_effect=lambda a,**kw:calls.append((a,kw))):
            driver.acquire_workflow_commit(Path("pipeline"),HEAD,env,minimal=True)
        self.assertIn("--depth=2",calls[0][0]);self.assertNotIn("GITHUB_TOKEN",calls[0][1]["env"])
    def test_all_five_owner_bytes_and_first_parent_remain_checked(self):
        event,env=event_env();files=(driver.WORKFLOW,"scripts/fork-release/source_validation_v108.py","scripts/fork-release/preflight.py","scripts/fork-release/release.py","scripts/fork-release/native_tests.mjs")
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in files:(root/name).parent.mkdir(parents=True,exist_ok=True);(root/name).write_bytes(b"reviewed")
            def git(where,*args):
                if args==("rev-parse","HEAD"):return HEAD.encode()
                if args==("rev-parse",MERGE+"^1"):return driver.TARGET_BRANCH_TIP.encode()
                return b"reviewed"
            with patch.object(driver,"git",side_effect=git),patch.object(driver,"acquire_workflow_commit"):
                driver.code_binding(root,None,event,env,minimal=True)
            def drift(where,*args):
                return b"wrong" if args==("show",MERGE+":"+files[-1]) else git(where,*args)
            with patch.object(driver,"git",side_effect=drift),patch.object(driver,"acquire_workflow_commit"):
                self.refused(driver.code_binding,root,None,event,env,True)
    def test_profile_clock_budget_reserves_cleanup_and_original_absolute_deadline(self):
        epoch=int(NOW.timestamp());env={"SOURCE_JOB_STARTED_EPOCH":str(epoch-60)}
        with patch.object(driver.time,"time",return_value=epoch):
            self.assertEqual(driver.profile_deadline(env,"doctor-1"),epoch-60+45*60-60)
            self.refused(driver.profile_deadline,{},"doctor-1")
    def test_command_timeout_records_result_and_settles_only_owned_group(self):
        group=FakeOwnedGroup(leader_zero=False)
        result,receipt=exercise_owned_timeout(group)
        self.assertTrue(result.timed_out);self.assertEqual(result.returncode,124)
        self.assertEqual(result.actual_returncode,-9);self.assertTrue(result.cleanup_settled)
        self.assertTrue(group.start_new_session)
        self.assertEqual(group.signals,[driver.signal.SIGTERM,driver.signal.SIGKILL])
        self.assertEqual(receipt["status"],"timeout")
    def test_timeout_with_zero_child_exit_is_still_failure_and_owned_escalation_is_bounded(self):
        for zero in (True,False):
            group=FakeOwnedGroup(leader_zero=zero)
            result,receipt=exercise_owned_timeout(group)
            self.assertEqual(result.returncode,124);self.assertTrue(result.timed_out)
            self.assertEqual(group.signals,[driver.signal.SIGTERM,driver.signal.SIGKILL])
            self.assertEqual(receipt["exitCode"],0 if zero else None)
            self.assertLessEqual(group.now,15.1)
    def test_no_remaining_budget_records_refusal_before_child_creation(self):
        with patch.object(driver.subprocess,"Popen") as child,patch.object(driver.time,"time",return_value=20),patch.object(driver,"summarize") as report:
            self.refused(driver.phase_process,["fixed"],Path("source"),{}, {"profile":"doctor-1","deadlineEpoch":12},"command",0)
        child.assert_not_called();self.assertEqual(report.call_args.args[0]["status"],"budget_refused")

class FakeOwnedGroup:
    """A TERM-handling leader and inherited-stdio descendant, with fake time."""
    def __init__(self, leader_zero=True, foreign=False, never_settles=False):
        self.pid=777;self.returncode=None;self.reaped=False;self.descendant_alive=True
        self.leader_zero=leader_zero;self.foreign=foreign;self.never_settles=never_settles
        self.now=0.0;self.signals=[];self.communications=0;self.term_seen=False
    def communicate(self, timeout):
        self.communications+=1
        if self.communications==1:raise subprocess.TimeoutExpired(["fixed"],timeout)
        if self.leader_zero and self.term_seen:self.returncode=0
        elif not self.descendant_alive:self.returncode=-9
        else:raise subprocess.TimeoutExpired(["fixed"],timeout)
        self.reaped=True
        return None,None
    def group(self,pid):
        if self.reaped:raise AssertionError("destructive ownership check after leader reap")
        assert pid==self.pid
        return self.pid+1 if self.foreign else self.pid
    def killpg(self,pid,sig):
        assert pid==self.pid
        if sig==0:
            if self.never_settles or self.descendant_alive or not self.reaped:return
            raise ProcessLookupError()
        if self.reaped:raise AssertionError("signal after leader reap risks reused process identity")
        self.signals.append(sig)
        if sig==driver.signal.SIGTERM:self.term_seen=True
        elif sig==driver.signal.SIGKILL:self.descendant_alive=False
        else:raise AssertionError(sig)
    def monotonic(self):return self.now
    def sleep(self,seconds):self.now+=seconds


def exercise_owned_timeout(group):
    with patch.object(driver.subprocess,"Popen",return_value=group) as launch, \
         patch.object(driver.os,"getpgid",side_effect=group.group), \
         patch.object(driver.os,"getsid",side_effect=group.group), \
         patch.object(driver.os,"killpg",side_effect=group.killpg), \
         patch.object(driver.time,"time",return_value=10), \
         patch.object(driver.time,"monotonic",side_effect=group.monotonic), \
         patch.object(driver.time,"sleep",side_effect=group.sleep), \
         patch.object(driver,"summarize") as report:
        result=driver.phase_process(["fixed"],Path("source"),{},
            {"profile":"doctor-1","deadlineEpoch":12},"command",0)
    group.start_new_session=launch.call_args.kwargs["start_new_session"]
    return result,report.call_args.args[0]


class P2CounterexampleTests(unittest.TestCase):
    def setUp(self):
        self.pins=patch.multiple(driver,SOURCE=SOURCE,TREE=TREE,FIRST_SOURCE=SOURCE,FIRST_TREE=TREE)
        self.pins.start();self.addCleanup(self.pins.stop)
    def add_ancillary(self,runs,tables,minutes=1,status="completed"):
        run=run_record("8888",HEAD,".github/workflows/synthetic-metadata.yml",
                       "success" if status=="completed" else None,status)
        table={"total_count":1,"jobs":[job("metadata",minutes)]}
        tables["8888"]=table;runs.append(run)
        return run,table
    def test_new_ancillary136_must_refuse_without_refunding_fixed425(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);req,event,env,responses,api,runs,tables=history_fixture(root,request())
            self.add_ancillary(runs,tables,136)
            with patch.object(driver.subprocess,"run"),patch.object(driver,"datetime",wraps=datetime) as clock:
                clock.now.return_value=NOW
                with self.assertRaises(driver.release.Refusal):driver.history_checks(req,event,env,root,api)
    def test_leader_zero_exit_cannot_leave_term_ignoring_owned_descendant(self):
        group=FakeOwnedGroup(leader_zero=True)
        result,receipt=exercise_owned_timeout(group)
        self.assertFalse(group.descendant_alive,"TERM-ignoring descendant survived leader communicate exit0")
        self.assertEqual(group.signals,[driver.signal.SIGTERM,driver.signal.SIGKILL])
        self.assertEqual(result.actual_returncode,0);self.assertEqual(result.returncode,124)
        self.assertTrue(result.cleanup_settled);self.assertTrue(receipt["cleanupSettled"])
    def test_new_ancillary_usage_is_inclusive_in135_not_added_twice(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);req,event,env,responses,api,runs,tables=history_fixture(root,request())
            self.add_ancillary(runs,tables,40)
            with patch.object(driver.subprocess,"run"),patch.object(driver,"datetime",wraps=datetime) as clock:
                clock.now.return_value=NOW;result=driver.history_checks(req,event,env,root,api)
            self.assertEqual(result["actualSettledRunnerMinutes"],425)
            self.assertEqual(result["observedNewAncillaryRunnerMinutes"],40)
            self.assertEqual(result["newAncillaryRemainingReserveMinutes"],95)
            self.assertEqual(result["bookedRunnerMinutes"],1800)
    def test_new_ancillary_unknown_usage_or_identity_refuses(self):
        for mutation in ("runner_id","started_at","private","foreign-head"):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);req,event,env,responses,api,runs,tables=history_fixture(root,request())
                run,table=self.add_ancillary(runs,tables)
                if mutation=="private":run["head_repository"]["private"]=True
                elif mutation=="foreign-head":run["head_sha"]="c"*40
                else:table["jobs"][0].pop(mutation)
                with patch.object(driver.subprocess,"run"),patch.object(driver,"datetime",wraps=datetime) as clock:
                    clock.now.return_value=NOW
                    with self.assertRaises(driver.release.Refusal):driver.history_checks(req,event,env,root,api)
    def test_new_inprogress_ancillary_reports_elapsed_then_refuses_unbounded_remaining(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);req,event,env,responses,api,runs,tables=history_fixture(root,request())
            run,table=self.add_ancillary(runs,tables,status="in_progress")
            active=table["jobs"][0];active.update(status="in_progress",conclusion=None,
                started_at=(NOW-timedelta(minutes=2)).isoformat().replace("+00:00","Z"),completed_at=None)
            elapsed=[0]
            def sleep(seconds):elapsed[0]+=seconds
            with patch.object(driver.subprocess,"run"),patch.object(driver,"datetime",wraps=datetime) as clock,patch.object(driver,"summarize") as report,patch.object(driver.time,"monotonic",side_effect=lambda:elapsed[0]),patch.object(driver.time,"sleep",side_effect=sleep):
                clock.now.side_effect=lambda zone:NOW+timedelta(seconds=elapsed[0])
                with self.assertRaises(driver.release.Refusal):driver.history_checks(req,event,env,root,api)
            record=next(call.args[0] for call in report.call_args_list if call.args[0].get("phase")=="new_ancillary")
            self.assertEqual(record["observedAcquiredRunnerMinutes"],2)
            self.assertFalse(record["usageComplete"]);self.assertIsNone(record["remainingReservationMinutes"])
            self.assertEqual(elapsed[0],60)
    def test_cleanup_refuses_foreign_session_and_never_signals_after_reap(self):
        group=FakeOwnedGroup(foreign=True)
        result,receipt=exercise_owned_timeout(group)
        self.assertFalse(result.cleanup_settled);self.assertFalse(receipt["cleanupSettled"])
        self.assertEqual(group.signals,[]);self.assertEqual(result.returncode,124)
    def test_owned_group_surviving_after_kill_is_reported_unsettled_without_extra_signals(self):
        group=FakeOwnedGroup(never_settles=True)
        result,receipt=exercise_owned_timeout(group)
        self.assertFalse(result.cleanup_settled);self.assertFalse(receipt["cleanupSettled"])
        self.assertEqual(group.signals,[driver.signal.SIGTERM,driver.signal.SIGKILL])
        self.assertLessEqual(group.now,15.1)


class AncillaryObservationTests(unittest.TestCase):
    def setUp(self):
        self.pins=patch.multiple(driver,SOURCE=SOURCE,TREE=TREE,FIRST_SOURCE=SOURCE,FIRST_TREE=TREE)
        self.pins.start();self.addCleanup(self.pins.stop)
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        args=history_fixture(self.root,request())
        self.req,self.event,self.env,self.responses,self.base_api,self.runs,self.tables=args
        self.run,self.table=P2CounterexampleTests.add_ancillary(self,self.runs,self.tables,status="in_progress")
        self.active=self.table["jobs"][0]
        self.active.update(status="in_progress",conclusion=None,
            started_at=(NOW-timedelta(minutes=2)).isoformat().replace("+00:00","Z"),completed_at=None)
        self.elapsed=0;self.sleeps=[];self.calls=[];self.poll=None;self.list_count=0
        self.clock=patch.object(driver,"datetime",wraps=datetime).start();self.addCleanup(patch.stopall)
        self.clock.now.side_effect=lambda zone:NOW+timedelta(seconds=self.elapsed)
        patch.object(driver.time,"monotonic",side_effect=lambda:self.elapsed).start()
        patch.object(driver.time,"sleep",side_effect=self.sleep).start()
        patch.object(driver.subprocess,"run").start()
        self.report=patch.object(driver,"summarize").start()
    def sleep(self,seconds):
        self.sleeps.append(seconds);self.elapsed+=seconds
    def api(self,path):
        self.calls.append(path)
        if "/actions/runs?branch=" in path:
            self.list_count+=1
            if self.list_count>1 and self.poll:self.poll()
        return self.base_api(path)
    def run_history(self):
        return driver.history_checks(self.req,self.event,self.env,self.root,self.api)
    def finish(self):
        self.run.update(status="completed",conclusion="success")
        self.active.update(status="completed",conclusion="success",
            completed_at=(NOW+timedelta(seconds=self.elapsed)).isoformat().replace("+00:00","Z"))
    def test_same_event_active_to_terminal_is_measured_without_refetching_old57(self):
        self.poll=self.finish
        result=self.run_history()
        self.assertEqual(result["observedNewAncillaryRunnerMinutes"],3)
        self.assertEqual(result["newAncillaryRemainingReserveMinutes"],132)
        self.assertEqual(result["bookedRunnerMinutes"],1800)
        self.assertEqual(self.elapsed,5);self.assertEqual(self.sleeps,[5])
        for row in driver.read_json((self.root/driver.SETTLED_USAGE).read_bytes())["runs"]:
            self.assertEqual(sum("/actions/runs/"+row["id"]+"/jobs?" in p for p in self.calls),1)
        self.assertEqual(sum("/actions/runs/8888/jobs?" in p for p in self.calls),2)
        self.assertTrue(result["newAncillaryRecords"][0]["usageComplete"])
    def test_queued_owned_standard_job_can_settle_to_explicit_unacquired_terminal(self):
        self.run["status"]="queued"
        self.active.update(status="queued",runner_id=0,runner_name="",steps=[],started_at=None)
        def finish():
            self.run.update(status="completed",conclusion="skipped")
            self.active.update(status="completed",conclusion="skipped")
        self.poll=finish
        result=self.run_history()
        self.assertEqual(result["observedNewAncillaryRunnerMinutes"],0)
        self.assertEqual(result["newAncillaryRemainingReserveMinutes"],135)
        self.assertEqual(self.elapsed,5)
    def test_pending_timeout_is_exactly60_and_never_a_zero_future_usage_pass(self):
        with self.assertRaisesRegex(driver.release.Refusal,"bounded60"):
            self.run_history()
        self.assertEqual(self.elapsed,60);self.assertEqual(self.list_count,12)
        last=self.report.call_args_list[-1].args[0]
        self.assertEqual(last["pendingRunIds"],["8888"])
        self.assertFalse(last["usageComplete"]);self.assertIsNone(last["remainingReservationMinutes"])
        self.assertEqual(last["observedAcquiredRunnerMinutes"],3)
    def test_invalid_provider_or_identity_or_no_headroom_refuses_before_wait(self):
        original_run,original_table=copy.deepcopy(self.run),copy.deepcopy(self.table)
        for mutation in ("runner","labels","queued-labels","start","empty","unknown-path","excess","headroom"):
            with self.subTest(mutation=mutation):
                self.run.clear();self.run.update(copy.deepcopy(original_run))
                self.table.clear();self.table.update(copy.deepcopy(original_table));self.active=self.table["jobs"][0]
                if mutation=="runner":self.active.pop("runner_id")
                elif mutation=="labels":self.active["labels"]=["self-hosted"]
                elif mutation=="queued-labels":self.active.update(status="queued",runner_id=0,runner_name="",steps=[],labels=[])
                elif mutation=="start":self.active.pop("started_at")
                elif mutation=="empty":self.table.update(total_count=0,jobs=[])
                elif mutation=="unknown-path":self.run["path"]=".github/workflows/unknown.yml"
                else:self.active["started_at"]=(NOW-timedelta(minutes=136 if mutation=="excess" else 135)).isoformat().replace("+00:00","Z")
                with self.assertRaises(driver.release.Refusal):self.run_history()
                self.assertEqual(self.sleeps,[])
    def test_own_admission_or_original_deadline_insufficient_refuses_before_wait(self):
        own=self.tables["999"]["jobs"][0];original=copy.deepcopy(own)
        for mutation in ("old-admission","missing-run","wrong-job","unknown-runner","approval-expired"):
            with self.subTest(mutation=mutation):
                own.clear();own.update(copy.deepcopy(original));self.env["GITHUB_JOB"]="admission"
                if mutation=="old-admission":own["started_at"]=(NOW-timedelta(minutes=14,seconds=1)).isoformat().replace("+00:00","Z")
                elif mutation=="missing-run":own.pop("run_id")
                elif mutation=="wrong-job":self.env["GITHUB_JOB"]="source"
                elif mutation=="unknown-runner":own["labels"]=["self-hosted"]
                with patch.object(driver,"APPROVAL_DEADLINE","2026-10-28T05:00:59Z" if mutation=="approval-expired" else driver.APPROVAL_DEADLINE):
                    with self.assertRaises(driver.release.Refusal):self.run_history()
                self.assertEqual(self.sleeps,[])
    def test_newly_indexed_owned_run_is_measured_and_terminal_cache_not_refetched(self):
        extra=run_record("8889",HEAD,".github/workflows/synthetic-metadata.yml",None,"queued")
        extra_job=job("metadata",0,"skipped",False);extra_job.update(status="queued",conclusion=None,labels=["ubuntu-24.04"])
        count=[0]
        def poll():
            count[0]+=1
            if count[0]==1:
                self.finish();self.runs.append(extra);self.tables["8889"]={"total_count":1,"jobs":[extra_job]}
            else:
                extra.update(status="completed",conclusion="skipped");extra_job.update(status="completed",conclusion="skipped")
        self.poll=poll
        result=self.run_history()
        self.assertEqual(self.elapsed,10)
        self.assertEqual(result["observedNewAncillaryRunnerMinutes"],3)
        self.assertEqual(len(result["newAncillaryRecords"]),2)
        self.assertEqual(sum("/actions/runs/8888/jobs?" in p for p in self.calls),2)
    def test_identity_drift_on_poll_refuses_at_first_observation(self):
        self.poll=lambda:self.run.update(head_sha="c"*40)
        with self.assertRaises(driver.release.Refusal):self.run_history()
        self.assertEqual(self.elapsed,5)
    def test_duplicate_source_on_poll_refuses_without_rechecking_old_jobs(self):
        self.poll=lambda:self.runs.append(run_record("1000",HEAD,driver.WORKFLOW,None,"queued"))
        with self.assertRaises(driver.release.Refusal):self.run_history()
        self.assertEqual(self.elapsed,5)
        self.assertEqual(sum("/actions/runs/40616416909/jobs?" in p for p in self.calls),1)
    def test_new_usage_exceeding135_on_poll_refuses_without_more_wait(self):
        def poll():
            self.finish()
            extra=run_record("8889",HEAD,".github/workflows/synthetic-metadata.yml")
            self.runs.append(extra);self.tables["8889"]={"total_count":1,"jobs":[job("metadata",133)]}
        self.poll=poll
        with self.assertRaisesRegex(driver.release.Refusal,"135-minute"):
            self.run_history()
        self.assertEqual(self.elapsed,5)
    def test_blocked_provider_call_has_hard_alarm_bound_and_restores_handler(self):
        old=driver.signal.getsignal(driver.signal.SIGALRM)
        with self.assertRaises(driver.AncillaryObservationExpired):
            with driver.ancillary_observation_window():
                handler=driver.signal.getsignal(driver.signal.SIGALRM)
                self.assertGreater(driver.signal.getitimer(driver.signal.ITIMER_REAL)[0],0)
                handler(driver.signal.SIGALRM,None)
        self.assertEqual(driver.signal.getitimer(driver.signal.ITIMER_REAL),(0.0,0.0))
        self.assertEqual(driver.signal.getsignal(driver.signal.SIGALRM),old)

class AdmissionDiagnosticTests(unittest.TestCase):
    CANARY = "PRIVATE_CANARY_URL_TOKEN_API_BODY_CHILD_STDERR_88199"
    def setUp(self):
        self.pins=patch.multiple(driver,SOURCE=SOURCE,TREE=TREE,FIRST_SOURCE=SOURCE,FIRST_TREE=TREE)
        self.pins.start();self.addCleanup(self.pins.stop)
    def admission(self, *, failed_owner="history_checks_v4", effect=None, mutate_env=None, mutate_event=None):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);event,env=event_env()
            if mutate_event:mutate_event(event)
            event_path=root/"event.json";event_path.write_text(json.dumps(event))
            output=root/"matrix";env.update(GITHUB_EVENT_PATH=str(event_path),GITHUB_OUTPUT=str(output),
                GH_SOURCE_READ_TOKEN=self.CANARY,GITHUB_STEP_SUMMARY=str(root/"summary"))
            if mutate_env:mutate_env(env)
            stdout,stderr=io.StringIO(),io.StringIO()
            owners={name:patch.object(driver,name) for name in
                ("metadata","code_binding","history_checks_v4","fetch_closure",
                 "verify_source_equivalence_v4","admission_deadline")}
            mocks={name:owner.start() for name,owner in owners.items()}
            current=operational_v4_request()
            mocks["metadata"].return_value=(current,{},"d"*64)
            mocks["admission_deadline"].return_value=int(NOW.timestamp())+3600
            mocks["history_checks_v4"].return_value={"deadlineEpoch":int(NOW.timestamp())+3600,
                "profileMatrix":[{"profile":profile,"minutes":driver.profile_minutes_for(current)[profile]}
                                 for profile in current["profiles"]],
                "reusedProfileEvidence":{"profiles":list(driver.V4_REUSED_PROFILES)}}
            mocks["verify_source_equivalence_v4"].return_value={"status":"synthetic_verified_equivalence"}
            if effect is not None:mocks[failed_owner].side_effect=effect
            try:
                with patch.dict(driver.os.environ,env,clear=True),patch.object(sys,"argv",[
                    "source_validation_v108.py","admit","--pipeline-dir",str(root/"pipeline"),
                    "--source-dir",str(root/"source")]),redirect_stdout(stdout),redirect_stderr(stderr):
                    code=driver.entrypoint()
            finally:
                for owner in reversed(list(owners.values())):owner.stop()
            raw=stdout.getvalue()+stderr.getvalue();self.assertNotIn(self.CANARY,raw)
            facts=[json.loads(line) for line in stdout.getvalue().splitlines()]
            failure=[row for row in facts if row.get("schema")=="openclaw.v108.admission-failure.v1"]
            if code==2:
                self.assertFalse(output.exists(),"refusal emitted a source matrix")
                self.assertEqual(len(failure),1)
                self.assertEqual(stderr.getvalue(),"source-validation: refused; inspect bounded structured admission/step diagnostics\n")
                self.assertLess(len(json.dumps(failure[0]).encode()),4096)
                self.assertIsNone(driver._ADMISSION_DIAGNOSTIC)
            return code,failure,facts,mocks,output.exists()
    def test_known_owner_need_keeps_fixed_phase_reason_run_and_exit2(self):
        def fail(*args, **kwargs):
            driver.admission_stage("history","settled-prefix","40607329259")
            driver.need(False,"settled provider usage changed")
        code,failures,_,mocks,_=self.admission(effect=fail)
        self.assertEqual(code,2);f=failures[0]
        self.assertEqual((f["phase"],f["subcheck"]),("history","settled-prefix"))
        self.assertEqual(f["failedNeedCode"],"need.settled_provider_usage_changed")
        self.assertEqual(f["exceptionClass"],"Refusal")
        self.assertEqual((f["runId"],f["relatedRunId"]),(999,40607329259))
        self.assertIsNone(f["httpStatus"]);self.assertIsNone(f["childExitCode"])
        self.assertFalse(f["productionAuthorized"]);self.assertFalse(f["imageBuilt"])
        mocks["fetch_closure"].assert_not_called()
    def test_unknown_need_label_canary_is_explicitly_unprojected_not_exported(self):
        def fail(*args, **kwargs):driver.need(False,self.CANARY)
        _,failures,_,_,_=self.admission(effect=fail)
        self.assertEqual(failures[0]["failedNeedCode"],"v4.unprojected")
    def test_http_error_preserves_only_valid_status_and_fixed_api_location(self):
        def fail(*args, **kwargs):
            with driver.admission_api_read("/repos/fr-meyer/openclaw/actions/runs/40607329259/jobs?filter=all&per_page=100"):
                raise urllib.error.HTTPError("https://"+self.CANARY,403,self.CANARY,{"x-secret":self.CANARY},io.BytesIO(self.CANARY.encode()))
        _,failures,_,_,_=self.admission(effect=fail)
        f=failures[0];self.assertEqual((f["phase"],f["subcheck"]),("history","api.read"))
        self.assertEqual(f["relatedRunId"],40607329259);self.assertEqual(f["httpStatus"],403)
        self.assertEqual(f["exceptionClass"],"HTTPError");self.assertEqual(f["failedNeedCode"],"v4.unprojected")
    def test_child_error_never_exports_argv_output_stderr_or_exception_text(self):
        error=subprocess.CalledProcessError(7,[self.CANARY],output=self.CANARY,stderr=self.CANARY)
        _,failures,_,_,_=self.admission(failed_owner="code_binding",effect=error)
        f=failures[0];self.assertEqual((f["phase"],f["subcheck"]),("binding","code.bind"))
        self.assertEqual(f["childExitCode"],7);self.assertEqual(f["exceptionClass"],"CalledProcessError")
    def test_invalid_http_and_child_numeric_fields_never_project_bool_string_or_excess(self):
        for value in (True,self.CANARY,600):
            with self.subTest(http=value):
                error=urllib.error.HTTPError(self.CANARY,value,self.CANARY,{},None)
                _,failures,_,_,_=self.admission(effect=error);self.assertIsNone(failures[0]["httpStatus"])
        for value in (True,self.CANARY,256):
            with self.subTest(child=value):
                error=subprocess.CalledProcessError(value,[self.CANARY])
                _,failures,_,_,_=self.admission(effect=error);self.assertIsNone(failures[0]["childExitCode"])
        _,failures,_,_,_=self.admission(effect=subprocess.CalledProcessError(-15,[self.CANARY]))
        self.assertEqual(failures[0]["childExitCode"],-15)
    def test_event_and_metadata_failures_have_distinct_fixed_stages(self):
        _,failures,_,mocks,_=self.admission(mutate_event=lambda e:e["pull_request"]["base"].update(sha=HEAD))
        self.assertEqual((failures[0]["phase"],failures[0]["subcheck"]),("input","event.validate"))
        self.assertEqual(failures[0]["failedNeedCode"],"need.fixed_base");mocks["metadata"].assert_not_called()
        def fail(*args, **kwargs):driver.need(False,"request metadata hashes")
        _,failures,_,mocks,_=self.admission(failed_owner="metadata",effect=fail)
        self.assertEqual((failures[0]["phase"],failures[0]["subcheck"]),("metadata","manifest.request"))
        mocks["code_binding"].assert_not_called()
    def test_raw_subclass_name_and_untrusted_context_are_not_exposed(self):
        private_error=type(self.CANARY,(ValueError,),{})
        def fail(*args, **kwargs):
            driver.admission_stage(self.CANARY,self.CANARY,self.CANARY);raise private_error(self.CANARY)
        _,failures,_,_,_=self.admission(effect=fail)
        self.assertEqual(failures[0]["exceptionClass"],"ValueError")
        self.assertEqual((failures[0]["phase"],failures[0]["subcheck"]),("unprojected","unprojected"))
        self.assertIsNone(failures[0]["relatedRunId"])
    def test_success_has_no_failure_projection_and_admits_matrix_once(self):
        code,failures,facts,mocks,exists=self.admission()
        self.assertEqual(code,0);self.assertEqual(failures,[]);self.assertTrue(exists)
        mocks["fetch_closure"].assert_called_once();mocks["verify_source_equivalence_v4"].assert_called_once()
        current=mocks["metadata"].return_value[0]
        self.assertEqual(mocks["fetch_closure"].call_args.kwargs["request"],current)
        self.assertEqual(mocks["verify_source_equivalence_v4"].call_args.args[:2],(current,driver.STAGE_PINS))
        self.assertEqual(facts[-1]["authorization"],"source-validation-only")
    def test_nonadmission_failure_uses_original_exception_without_admission_output(self):
        stdout=io.StringIO()
        with redirect_stdout(stdout),self.assertRaises(driver.release.Refusal),driver.admission_diagnostics({},False):
            driver.need(False,"fixed base")
        self.assertEqual(stdout.getvalue(),"")
    def test_diagnostic_allowlist_is_static_complete_for_existing_need_literals(self):
        import ast
        tree=ast.parse(Path(driver.__file__).read_text())
        calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and
            isinstance(n.func,ast.Name) and n.func.id=="need" and len(n.args)>1]
        literals={n.args[1].value for n in calls if
            isinstance(n.args[1],ast.Constant) and isinstance(n.args[1].value,str)}
        dynamic=[n for n in calls if not (isinstance(n.args[1],ast.Constant) and
                                         isinstance(n.args[1].value,str))]
        history_owner=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=="_h4_need")
        self.assertEqual(len(dynamic),1)
        self.assertIn(dynamic[0],list(ast.walk(history_owner)))
        expected=ast.parse('need(value, "v4.history." + code)',mode="eval").body
        self.assertEqual(ast.dump(dynamic[0],include_attributes=False),ast.dump(expected,include_attributes=False))
        history_calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and
            isinstance(n.func,ast.Name) and n.func.id=="_h4_need"]
        self.assertTrue(history_calls)
        for call in history_calls:
            self.assertEqual(len(call.args),2)
            self.assertIsInstance(call.args[1],ast.Constant)
            self.assertIsInstance(call.args[1].value,str)
            self.assertRegex(call.args[1].value,r"\A[a-z][a-z0-9_]*\Z")
            literals.add("v4.history."+call.args[1].value)
        # Replaced v3 metadata no longer calls these labels operationally. Keep
        # their exact historical projection without allowing arbitrary extras.
        historical={"source-only manifest":"need.source_only_manifest",
                    "request metadata hashes":"need.request_metadata_hashes"}
        for label,code in historical.items():
            self.assertEqual(driver.ADMISSION_NEED_CODES[label],code)
        literals.update(historical)
        self.assertEqual(literals,set(driver.ADMISSION_NEED_CODES))
        self.assertEqual(len(set(driver.ADMISSION_NEED_CODES.values())),len(literals))
        self.assertTrue(all(__import__('re').fullmatch(r"need\.[a-z0-9_]+",c) for c in driver.ADMISSION_NEED_CODES.values()))


class ProviderJobIdentityTests(unittest.TestCase):
    def table(self,acquired=False):
        # Actual display/acquisition shape of the provider collision; only IDs
        # identify rows, and equal labels cannot discount acquired usage.
        rows=[job("${{ matrix.checkName }}",minutes,"success" if acquired else "skipped",acquired)
              for minutes in ((1,2) if acquired else (0,0))]
        rows[0]["id"],rows[1]["id"]=122550039414,122550039415
        return {"total_count":2,"jobs":rows}
    def test_distinct_ids_same_skipped_display_are_allowed_and_charge_zero(self):
        table=self.table();self.assertEqual(driver.observed_minutes(table,legacy=True),0)
        facts=driver.ancillary_job_snapshot(table,NOW,True)
        self.assertTrue(facts["usageComplete"]);self.assertEqual(facts["explicitlyUnacquiredJobs"],2)
        self.assertEqual(facts["observedAcquiredRunnerMinutes"],0)
    def test_distinct_acquired_ids_same_display_charge_every_job(self):
        table=self.table(True);self.assertEqual(driver.observed_minutes(table,legacy=True),3)
        facts=driver.ancillary_job_snapshot(table,NOW,True)
        self.assertEqual(facts["observedAcquiredRunnerMinutes"],3);self.assertEqual(facts["acquiredJobs"],2)
    def test_repeated_or_noncanonical_job_id_refuses_even_if_name_differs(self):
        for bad in (None,True,0,"122550039414",122550039414):
            with self.subTest(id=bad):
                table=self.table();table["jobs"][1].update(id=bad,name="different")
                with self.assertRaises(driver.release.Refusal):driver.observed_minutes(table,legacy=True)
                with self.assertRaises(driver.release.Refusal):driver.ancillary_job_snapshot(table,NOW,True)
    def test_expected_source_semantic_names_stay_unique_even_with_distinct_ids(self):
        table=source_jobs(legacy=False);first=next(j for j in table["jobs"] if j["name"]=="source (dependency)")
        table["jobs"].append(dict(first,id=999999));table["total_count"]+=1
        with self.assertRaises(driver.release.Refusal):driver.observed_minutes(table,list(driver.PROFILE_MINUTES))


class InitialResumeTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.request=historical_v3_request()
    def prior_raw(self):
        value=copy.deepcopy(self.request)
        value.update(schema="openclaw.fork-source-validation-request.v2",round=2,profiles=[],
                     priorRunIds=list(driver.RETAINED_SOURCE_RUN_IDS))
        value.pop("initialResume")
        return (json.dumps(value,indent=2)+"\n").encode()
    def prior_table(self):
        rows=[job("admission",14,"failure"),job("final",0,"skipped",False),
              job("source (${{ matrix.profile }})",0,"skipped",False)]
        for row,identity in zip(rows,(122653671093,122657664876,122657665262)):
            row.update(id=identity,run_id=int(driver.INITIAL_RESUME_RUN_ID),head_sha=driver.INITIAL_RESUME_PIPELINE)
        rows[0].update(started_at="2026-10-28T05:40:39Z",completed_at="2026-10-28T05:53:48Z")
        return {"total_count":3,"jobs":rows}
    def fixture(self):
        req=copy.deepcopy(self.request);original_digest=req["settledUsageSha256"]
        req,event,env,responses,api,runs,tables=history_fixture(self.root,req)
        usage=driver.read_json((self.root/driver.SETTLED_USAGE).read_bytes())
        # This unit fixture replaces only the independently tested settled-file
        # hash owner; history still measures every synthetic prefix job table.
        req["settledUsageSha256"]=original_digest
        previous=run_record(driver.INITIAL_RESUME_RUN_ID,driver.INITIAL_RESUME_PIPELINE,driver.WORKFLOW,"failure")
        previous["created_at"]="2026-10-28T05:40:35Z";runs.append(previous)
        current=next(run for run in runs if str(run["id"])==env["GITHUB_RUN_ID"])
        current["created_at"]="2026-10-28T06:00:00Z"
        tables[driver.INITIAL_RESUME_RUN_ID]=self.prior_table()
        raw=self.prior_raw();self.assertEqual(hashlib.sha256(raw).hexdigest(),driver.INITIAL_RESUME_REQUEST_SHA256)
        for path,content in ((driver.REQUEST,raw),(driver.WORKFLOW,b"frozen workflow")):
            responses["/contents/"+path+"?ref="+driver.INITIAL_RESUME_PIPELINE]={
                "type":"file","encoding":"base64","size":len(content),
                "content":base64.b64encode(content).decode()}
        return req,event,env,responses,api,runs,tables,usage
    def check_history(self,args):
        req,event,env,responses,api,runs,tables,usage=args
        with patch.object(driver,"settled_usage",return_value=usage),patch.object(driver.subprocess,"run"),patch.object(driver,"datetime",wraps=datetime) as clock:
            clock.now.return_value=datetime(2026,10,28,6,tzinfo=timezone.utc)
            return driver.history_checks(req,event,env,self.root,api)
    def test_closed_resume_rebooks_failed14_and286_without_a_new_round_or_relabel(self):
        args=self.fixture();req=args[0]
        self.assertEqual(driver.validate_request(req),req)
        self.assertEqual(driver.profiles_for(req),list(driver.PROFILE_MINUTES))
        self.assertEqual(driver.round_minutes(req),940)
        result=self.check_history(args)
        self.assertEqual(result["actualSettledRunnerMinutes"],425)
        self.assertEqual(result["observedNewPriorRunnerMinutes"],14)
        self.assertEqual(result["reservedCorrectionBalanceMinutes"],286)
        self.assertEqual(result["futureTargetedReserveMinutes"],0)
        self.assertEqual(result["operatorRoundsRemaining"],0)
        self.assertEqual(result["bookedRunnerMinutes"],425+14+940+286+135)
        prior=result["firstSourceReceipt"]
        self.assertEqual(prior["runId"],driver.INITIAL_RESUME_RUN_ID)
        self.assertEqual(prior["conclusion"],"failure");self.assertEqual(prior["profileResults"],{})
        self.assertTrue(prior["initialValidationNeverStarted"]);self.assertFalse(prior["relabeledAsCurrentSourcePass"])
    def test_v2_is_prior_evidence_only_bound_to_exact95df_blob(self):
        raw=self.prior_raw();value=driver.read_json(raw)
        with self.assertRaises(driver.release.Refusal):driver.validate_request(value)
        self.assertEqual(driver.prior_request(raw,driver.INITIAL_RESUME_PIPELINE),value)
        for content,head in ((raw+b" ",driver.INITIAL_RESUME_PIPELINE),(raw,HEAD)):
            with self.assertRaises(driver.release.Refusal):driver.prior_request(content,head)
    def test_normal_v3_nullable_resume_retains_targeted300_cap(self):
        value=request(3,["types-tests","doctor-1","doctor-2","doctor-3"],
                      [*driver.RETAINED_SOURCE_RUN_IDS,driver.INITIAL_RESUME_RUN_ID])
        self.assertEqual(driver.round_minutes(driver.validate_request(value,bind_source=False)),250)
        value["profiles"]=list(driver.PROFILE_MINUTES)
        with self.assertRaises(driver.release.Refusal):driver.validate_request(value,bind_source=False)
    def test_resume_witness_has_no_extra_fields_repin_partial_profiles_or_second_round(self):
        for mutation in ("extra","head","source","tree","manifest","inventory","prior","profiles","round","source-witness"):
            with self.subTest(mutation=mutation):
                value=copy.deepcopy(self.request)
                if mutation=="extra":value["initialResume"]["extra"]=True
                elif mutation=="head":value["initialResume"]["priorPipelineHead"]=HEAD
                elif mutation=="source":value["sourceSha"]=HEAD
                elif mutation=="tree":value["sourceTree"]=HEAD
                elif mutation=="manifest":value["manifestSha256"]="0"*64
                elif mutation=="inventory":value["inventorySha256"]="0"*64
                elif mutation=="prior":value["priorRunIds"][-1]="8888"
                elif mutation=="profiles":value["profiles"]=["dependency"]
                elif mutation=="round":value["round"]=2
                else:value["sourceWitness"]={"schema":"other"}
                with self.assertRaises(driver.release.Refusal):driver.validate_request(value)
    def test_provider_positive_unstarted_evidence_cannot_be_forged_from_missing_or_acquired_jobs(self):
        for mutation in ("acquired-source","source-steps","missing-runner","final-cancelled","admission-pass",
                         "admission-over15","rerun","missing-job","extra-job","head","run","duplicate-id"):
            with self.subTest(mutation=mutation):
                table=self.prior_table();admission,final,source=table["jobs"]
                if mutation=="acquired-source":source.update(runner_id=12,runner_name="hosted",runner_group_name="GitHub Actions",labels=["ubuntu-24.04"])
                elif mutation=="source-steps":source["steps"]=[{"name":"unexpected"}]
                elif mutation=="missing-runner":source.pop("runner_id")
                elif mutation=="final-cancelled":final["conclusion"]="cancelled"
                elif mutation=="admission-pass":admission["conclusion"]="success"
                elif mutation=="admission-over15":admission["completed_at"]="2026-10-28T05:56:00Z"
                elif mutation=="rerun":source["run_attempt"]=2
                elif mutation=="missing-job":table["jobs"].pop();table["total_count"]-=1
                elif mutation=="extra-job":table["jobs"].append(dict(source,id=998,name="source (dependency)"));table["total_count"]+=1
                elif mutation=="head":source["head_sha"]=HEAD
                elif mutation=="run":source["run_id"]=999
                else:source["id"]=admission["id"]
                with self.assertRaises(driver.release.Refusal):driver.initial_resume_jobs(table)
    def test_changed_workflow_or_prior_conclusion_refuses_without_any_matrix(self):
        for mutation in ("workflow","conclusion"):
            with self.subTest(mutation=mutation):
                # Each fixture owns only its synthetic temporary source controls.
                with tempfile.TemporaryDirectory() as directory:
                    old=self.root;self.root=Path(directory)
                    try:
                        args=self.fixture()
                        if mutation=="workflow":(self.root/driver.WORKFLOW).write_bytes(b"different")
                        else:next(r for r in args[5] if str(r["id"])==driver.INITIAL_RESUME_RUN_ID)["conclusion"]="success"
                        with self.assertRaises(driver.release.Refusal):self.check_history(args)
                    finally:self.root=old


class FinalizeCoverageTests(unittest.TestCase):
    def finalize(self,value,pins=None):
        with tempfile.TemporaryDirectory() as directory:
            event,env=event_env();path=Path(directory)/"event.json";path.write_text(json.dumps(event))
            env.update(GITHUB_EVENT_PATH=str(path),SOURCE_MATRIX_RESULT="success",SOURCE_ADMISSION_RESULT="success")
            output=io.StringIO()
            with patch.dict(driver.os.environ,env,clear=True),patch.object(sys,"argv",[
                    "source_validation_v108.py","finalize","--pipeline-dir",directory]),\
                    patch.object(driver,"metadata",return_value=(value,{},"d"*64)),\
                    patch.object(driver,"STAGE_PINS",driver.STAGE_PINS if pins is None else pins),\
                    patch.object(driver,"code_binding") as binding,redirect_stdout(output):
                code=driver.entrypoint()
            binding.assert_called_once()
            self.assertEqual(binding.call_args.args[:3],(Path(directory),None,event))
            self.assertTrue(binding.call_args.kwargs["minimal"])
            self.assertEqual(binding.call_args.kwargs["request"],value)
            self.assertEqual(code,0)
            facts=json.loads(output.getvalue());self.assertEqual(facts["status"],"passed")
            self.assertFalse(facts["productionAuthorized"]);self.assertFalse(facts["imageBuilt"])
            return facts
    def test_initial_v4_reports_affected_profiles_and_original_historical_reuse(self):
        value=operational_v4_request()
        facts=self.finalize(value)
        self.assertEqual(facts["coverage"],"affected_profiles_with_admission_verified_historical_reuse")
        self.assertEqual(facts["affectedProfiles"],value["profiles"])
        reuse=facts["historicalReuse"]
        self.assertTrue(reuse["verified"])
        self.assertEqual(reuse["profiles"],list(driver.V4_REUSED_PROFILES))
        self.assertEqual((reuse["sourceSha"],reuse["runId"]),(driver.V4_PARENT_SOURCE,driver.V4_PARENT_RUN))
        self.assertFalse(reuse["relabeledAsCurrentSourcePass"])
    def test_v4_same_source_correction_keeps_targeted_profiles_and_original_witness(self):
        value=operational_v4_request()
        pins=copy.deepcopy(driver.STAGE_PINS)
        # Unit-only synthetic first-run ID; do not append to live corrective controls.
        pins["priorRunIds"]=[*pins["priorRunIds"][:5], "99998"]
        value.update(round=5,lifetimeOperatorRound=6,profiles=["dependency"],priorRunIds=pins["priorRunIds"])
        self.assertIsNone(value["sourceWitness"]["corrective"])
        facts=self.finalize(value,pins)
        self.assertEqual(facts["coverage"],"affected_profiles_with_admission_verified_historical_reuse")
        self.assertEqual(facts["affectedProfiles"],["dependency"])
        self.assertEqual(facts["sourceWitness"],value["sourceWitness"])




class CheckoutClosurePolicyTests(unittest.TestCase):
    F5 = "f5c198efedd78625e5a1b4a133d58ebfb3dae1c5"
    COMMITS = sorted(("157d8c2bc3ea2fa183afdc11088e69690bf8e64e",
        "1cf0627b9df7d81f101c39d94e87c0a68ba90884",
        "2691ebb4610d5ff9f836c1587be3d6a9703a23e1",
        "61f924bdb7ed4f837096c87120087919ff0a6bdf",
        "85a9bdc1285c338f10f5ca818abc259f6d483b5b",
        "dc2523e5a5c7a309517fd7fa834add938231d526", F5))
    TAG = "e07a2f67d11717ed39aa2fa07bbe9342376ebfbf"
    UPSTREAM = "dc2523e5a5c7a309517fd7fa834add938231d526"

    def test_real_layout_uses_only_root_candidate_request(self):
        self.assertFalse(Path(__file__).with_name("source-request.json").exists())
        actual = driver.read_json((PIPELINE_ROOT / driver.REQUEST).read_bytes())
        self.assertEqual(actual["schema"], driver.V4_SCHEMA)
        self.assertEqual(actual["sourceSha"], driver.STAGE_PINS["sourceSha"])
        self.assertEqual(driver.validate_request_v4(actual, driver.STAGE_PINS), actual)

    def test_policy_version_preserves_historical45_and_repairs_only_doctor1(self):
        old = {"schema": "openclaw.fork-source-validation-request.v3"}
        new = {"schema": "openclaw.fork-source-validation-request.v4",
               "profilePolicy": "five-gate-repair-v1"}
        self.assertEqual(driver.profile_minutes_for()["doctor-1"], 45)
        self.assertEqual(driver.profile_minutes_for(old)["doctor-1"], 45)
        self.assertEqual(driver.profile_minutes_for(new)["doctor-1"], 60)
        historical=driver.profile_minutes_for(old)
        current=driver.profile_minutes_for(new)
        self.assertEqual(historical,driver.PROFILE_MINUTES)
        self.assertEqual(current,{"dependency":60,"types-tests":90,"types-scripts":90,
            "models-1":60,"doctor-1":60,"compatibility":60,"pipeline-contracts":30})
        changed = [key for key in historical.keys() & current.keys()
                   if historical[key] != current[key]]
        self.assertEqual(changed, ["doctor-1"])
        for bad in ({"schema": "unknown"}, dict(new, profilePolicy="other"),
                    dict(old, profilePolicy="five-gate-repair-v1")):
            with self.assertRaises(driver.release.Refusal):driver.profile_minutes_for(bad)
        table = {"total_count": 3, "jobs": [job("admission",1),job("final",1),job("source (doctor-1)",47)]}
        with self.assertRaises(driver.release.Refusal):driver.observed_minutes(table,["doctor-1"],profile_request=old)
        self.assertEqual(driver.observed_minutes(table,["doctor-1"],profile_request=new),49)

    def test_one_early_admission_clock_bounds_checkout_to_remaining_not_new10(self):
        epoch = int(NOW.timestamp())
        for age,expected in ((0,10),(5*60,9),(10*60,4)):
            env = {"GITHUB_JOB":"admission","SOURCE_ADMISSION_STARTED_EPOCH":str(epoch-age)}
            with patch.object(driver.time,"time",return_value=epoch):
                self.assertEqual(driver.product_checkout_minutes(env),expected)
        for start in (None,"not-time",str(epoch+1),str(epoch-15*60),str(epoch-14*60)):
            env = {"GITHUB_JOB":"admission"}
            if start is not None:env["SOURCE_ADMISSION_STARTED_EPOCH"]=start
            with patch.object(driver.time,"time",return_value=epoch),self.assertRaises(driver.release.Refusal):
                driver.product_checkout_minutes(env)

    def test_product_only_shallow_checkout_and_clock_precede_both_checkouts(self):
        text = (PIPELINE_ROOT / driver.WORKFLOW).read_text()
        admission = text.split("  admission:\n",1)[1].split("\n  source:",1)[0]
        self.assertLess(admission.index("id: admission-clock"),admission.index("Checkout reviewed pipeline"))
        self.assertLess(admission.index("id: checkout-budget"),admission.index("Checkout frozen product"))
        self.assertIn("timeout-minutes: ${{ fromJSON(steps.checkout-budget.outputs.checkout_minutes) }}",admission)
        self.assertEqual(text.count("path: source\n          fetch-depth: 1"),2)
        self.assertEqual(text.count("path: pipeline\n          fetch-depth: 0"),2)
        self.assertEqual(text.count("SOURCE_ADMISSION_STARTED_EPOCH: ${{ steps.admission-clock.outputs.started_epoch }}"),2)

    def closure(self, *, shallow=True, remains_shallow=False, fetch_failure=None,
                tag_mismatch=False, expire_after_fetch=False, request_policy=None, source_profile=False):
        epoch = int(NOW.timestamp()); clock=[epoch]; reads=[]; acquisitions=[]
        env={"PATH":os.environ["PATH"],"GITHUB_JOB":"admission",
             "SOURCE_ADMISSION_STARTED_EPOCH":str(epoch)}
        req={"schema":"openclaw.fork-source-validation-request.v3"}
        if request_policy:req=request_policy
        if source_profile:
            env.update(GITHUB_JOB="source",SOURCE_PROFILE="doctor-1",SOURCE_JOB_STARTED_EPOCH=str(epoch))
        inventory={"upstream":{"tag":"v2026.10.8","tagObject":self.TAG,"commit":self.UPSTREAM}}
        def inspect(argv,**kwargs):
            args=argv[3:];reads.append(args)
            self.assertGreater(kwargs["timeout"],0)
            self.assertEqual(kwargs["env"]["GIT_NO_LAZY_FETCH"],"1")
            if args==["rev-parse","--is-shallow-repository"]:
                return b"true" if (not acquisitions and shallow) or (acquisitions and remains_shallow) else b"false"
            if args[:2]==["cat-file","-t"]:return b"tag" if args[-1]==self.TAG else b"commit"
            if args==["rev-parse","FETCH_HEAD"]:return ("0"*40 if tag_mismatch else self.TAG).encode()
            if args==["rev-parse",self.TAG+"^{commit}"]:return self.UPSTREAM.encode()
            raise AssertionError("unexpected local Git verification")
        def acquire(argv,cwd,child_env,context,phase,ordinal):
            acquisitions.append((argv,dict(context)))
            self.assertEqual(phase,"source-closure");self.assertEqual(ordinal,len(acquisitions)-1)
            self.assertNotIn("GH_SOURCE_READ_TOKEN",child_env)
            if expire_after_fetch:clock[0]=context["deadlineEpoch"]+1
            return SimpleNamespace(returncode=1 if fetch_failure==ordinal else 0,timed_out=False)
        with patch.dict(driver.os.environ,env,clear=True),patch.object(driver,"SOURCE",self.F5), \
                patch.object(driver,"metadata",return_value=(req,{},"d"*64)), \
                patch.object(driver.preflight,"inventory_at",return_value=(inventory,None)), \
                patch.object(driver.preflight,"history_commits",return_value=sorted(set(self.COMMITS) |
                    ({req["sourceSha"]} if req["schema"]==driver.V4_SCHEMA else set()))), \
                patch.object(driver.subprocess,"check_output",side_effect=inspect), \
                patch.object(driver,"phase_process",side_effect=acquire), \
                patch.object(driver,"source_preflight") as preflight, \
                patch.object(driver.time,"time",side_effect=lambda:clock[0]):
            error=None
            try:driver.fetch_closure(Path("pipeline"),Path("source"))
            except driver.release.Refusal as caught:error=caught
        return error,reads,acquisitions,preflight

    def test_present_but_shallow_f5_acquires_all7_plus_exact_annotated_tag_once(self):
        error,reads,fetches,preflight=self.closure()
        self.assertIsNone(error);self.assertEqual(len(fetches),2);preflight.assert_called_once()
        first=fetches[0][0];second=fetches[1][0]
        self.assertIn("--unshallow",first)
        self.assertEqual(first[-8:], ["https://github.com/fr-meyer/openclaw.git",*self.COMMITS])
        self.assertEqual(second[-2:],["https://github.com/openclaw/openclaw.git","refs/tags/v2026.10.8"])
        self.assertNotIn("--all",first+second);self.assertFalse(any("*" in arg for arg in first+second))
        self.assertFalse(any("cat-file" in args and "-e" in args for args in reads))

    def test_complete_product_repo_still_acquires_all_named_roots_without_unshallow(self):
        error,_,fetches,_=self.closure(shallow=False)
        self.assertIsNone(error);self.assertEqual(len(fetches),2);self.assertNotIn("--unshallow",fetches[0][0])

    def test_failed_fetch_shallow_result_or_tag_mismatch_has_no_retry_or_preflight(self):
        for kwargs,expected_calls in (({"fetch_failure":0},1),({"remains_shallow":True},1),
                                      ({"tag_mismatch":True},2),({"fetch_failure":1},2)):
            with self.subTest(kwargs=kwargs):
                error,_,fetches,preflight=self.closure(**kwargs)
                self.assertIsInstance(error,driver.release.Refusal);self.assertEqual(len(fetches),expected_calls)
                preflight.assert_not_called()

    def test_shared_deadline_expiry_after_fetch_refuses_before_more_verification(self):
        error,reads,fetches,preflight=self.closure(expire_after_fetch=True)
        self.assertIsInstance(error,driver.release.Refusal);self.assertEqual(len(fetches),1)
        self.assertEqual(reads,[["rev-parse","--is-shallow-repository"]]);preflight.assert_not_called()

    def test_source_closure_uses_record_policy_and_original_early_source_clock(self):
        old={"schema":"openclaw.fork-source-validation-request.v3"}
        new=operational_v4_request()
        for req,minutes in ((old,45),(new,60)):
            error,_,fetches,_=self.closure(request_policy=req,source_profile=True)
            self.assertIsNone(error)
            self.assertEqual(fetches[0][1]["deadlineEpoch"],int(NOW.timestamp())+minutes*60-60)


if __name__=="__main__":unittest.main()

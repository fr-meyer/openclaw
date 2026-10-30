"""Synthetic diagnostic route/admission/accounting controls; no clients/apps run."""
import ast
import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

import model_diagnostic_v109 as model
import source_validation_contract_v109 as policy
import source_validation_v109 as runtime
import bounded_run_contract_v109 as grants

HERE = Path(__file__).parent
SOURCE_RAW = (HERE / "fixtures/v109-h-diagnostic-source-request.json").read_bytes()
SOURCE = policy.parse(SOURCE_RAW)
NOW = policy.utc("2026-10-31T00:00:00Z").timestamp()


def selected():
    value = model.template()
    value.update(status="REVIEWED", routingMode="DIAGNOSTIC", reviewSha256="7" * 64)
    return value


def run(path=None, rid="123456", head="b" * 40, status="completed", conclusion="failure"):
    return {"id": int(rid), "run_attempt": 1, "head_sha": head, "status": status, "conclusion": conclusion,
        "repository": {"full_name": policy.REPOSITORY, "private": False}, "actor": {"login": "fr-meyer"},
        "triggering_actor": {"login": "fr-meyer"}, "event": "pull_request", "head_branch": policy.PIPELINE_BRANCH,
        "path": path or model.WORKFLOW, "name": model.CAMPAIGN, "display_title": model.CAMPAIGN}


def skipped(name, jid=1):
    return {"id": jid, "name": name, "run_attempt": 1, "status": "completed", "conclusion": "skipped",
        "runner_id": 0, "runner_name": None, "runner_group_name": None, "steps": []}


def actual_held_names():
    return ("admission", "source (${{ matrix.profile }})", "final")


class ModelDiagnostic(unittest.TestCase):
    def test_disarmed_template_exact_and_no_source_execution_or_approval_created(self):
        path = HERE / model.REQUEST_PATH.removeprefix("scripts/fork-release/")
        self.assertEqual(policy.parse(path.read_bytes()), model.template())
        self.assertEqual(model.validate(model.template(), SOURCE_RAW), model.template())
        self.assertNotIn("executionSequence", model.template())
        self.assertIsNone(model.template()["reviewSha256"])
        with self.assertRaises(policy.Refusal):
            model.validate(model.template(), SOURCE_RAW, active=True, now=NOW)

    def test_synthetic_reviewed_request_is_only_fixed_H_and_current_clock(self):
        model.validate(selected(), SOURCE_RAW, active=True, now=NOW)
        for key, bad in (("sourceSha", "a" * 40), ("sourceTree", "a" * 40), ("sourceRequestSha256", "a" * 64),
            ("generationSha256", "a" * 64), ("runAllowanceSha256", "a" * 64), ("profiles", ["models-1"]),
            ("publicManifestCapture", {"path": "private"}), ("expiresAt", "2027-01-01T00:00:00Z")):
            value = selected(); value[key] = bad
            with self.subTest(key=key), self.assertRaises(policy.Refusal):
                model.validate(value, SOURCE_RAW, active=True, now=NOW)
        for clock in (policy.utc(model.START).timestamp() - 1, policy.utc(model.END).timestamp()):
            with self.assertRaises(policy.Refusal):
                model.validate(selected(), SOURCE_RAW, active=True, now=clock)

    def test_missing_unknown_fields_wrong_review_and_counter_types_refuse(self):
        for kind in ("missing", "unknown", "review", "bool", "extra-profile", "mode"):
            value = selected()
            if kind == "missing":del value["priorValidation"]
            elif kind == "unknown":value["command"] = "arbitrary"
            elif kind == "review":value["reviewSha256"] = None
            elif kind == "bool":value["reservations"]["current"] = True
            elif kind == "extra-profile":value["profiles"].append("memory")
            else:value["routingMode"] = "SOURCE"
            with self.subTest(kind=kind), self.assertRaises(policy.Refusal):model.validate(value, SOURCE_RAW)

    def test_changed_source_raw_H2_or_lock_is_not_admissible_diagnostic(self):
        for key in ("sourceSha", "sourceTree"):
            source = deepcopy(SOURCE); source["source"][key] = "f" * 40
            with self.assertRaises(policy.Refusal):model.validate(selected(), policy.encode(source))
        with self.assertRaises(policy.Refusal):model.validate(selected(), SOURCE_RAW + b" ")

    def test_mutual_PR_body_route_never_relies_on_paths(self):
        for diagnostic in (True, False):
            body = "public instructions\n" + model.HOLD_MARKER if diagnostic else "public instructions"
            event = {"pull_request": {"body": body}}
            model.route_event(event, diagnostic)
            with self.assertRaises(policy.Refusal):model.route_event(event, not diagnostic)

    def test_exact_workflow_hold_and_restore_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            def put(relative, raw):
                path=root/relative;path.parent.mkdir(parents=True, exist_ok=True);path.write_bytes(raw)
            diag = (HERE / "fixtures/v109-model-diagnostic.yml").read_bytes()
            put(model.WORKFLOW, diag)
            for diagnostic, name in ((True, "held"), (False, "restored")):
                value = selected() if diagnostic else model.template()
                put(model.REQUEST_PATH, policy.encode(value))
                raw = (HERE / ("fixtures/v109-source-validation-" + name + ".yml")).read_bytes()
                put(policy.WORKFLOW, raw)
                model.workflow_routing(runtime, root, diagnostic)
                put(policy.WORKFLOW, raw + b"# unreviewed\n")
                with self.assertRaises(policy.Refusal):model.workflow_routing(runtime, root, diagnostic)

    def test_actual_event_context_is_not_forged_as_source_workflow(self):
        repo={"full_name":policy.REPOSITORY,"private":False}
        event={"number":28,"action":"synchronize","repository":repo,"pull_request":{
            "number":28,"state":"open","draft":True,"body":model.HOLD_MARKER,
            "head":{"repo":repo,"ref":policy.PIPELINE_BRANCH,"sha":"b"*40},
            "base":{"repo":repo,"ref":policy.BASE_BRANCH,"sha":policy.BASE}}}
        env={"GITHUB_ACTIONS":"true","RUNNER_OS":"Linux","RUNNER_ENVIRONMENT":"github-hosted",
            "GITHUB_EVENT_NAME":"pull_request","GITHUB_RUN_ATTEMPT":"1","GITHUB_REPOSITORY":policy.REPOSITORY,
            "GITHUB_ACTOR":"fr-meyer","GITHUB_REF":"refs/pull/28/merge","GITHUB_RUN_ID":"123456",
            "GITHUB_WORKFLOW_REF":policy.REPOSITORY+"/"+model.WORKFLOW+"@refs/pull/28/merge",
            "GITHUB_WORKFLOW_SHA":"c"*40}
        self.assertEqual(runtime.event_binding(event,env,diagnostic=True),"b"*40)
        with self.assertRaises(policy.Refusal):runtime.event_binding(event,env)
        for key,bad in (("GITHUB_ACTOR","other"),("GITHUB_RUN_ATTEMPT","2"),("GITHUB_EVENT_NAME","workflow_dispatch")):
            with self.subTest(key=key),self.assertRaises(policy.Refusal):runtime.event_binding(event,{**env,key:bad},diagnostic=True)

    def test_only_known_diagnostic_family_has_standard_role(self):
        self.assertEqual(model.native_role(runtime,run(),selected()),model.NATIVE_LIMITS)
        for key,bad in (("path",".github/workflows/unknown.yml"),("name","other"),("run_attempt",2),
            ("event","workflow_dispatch"),("head_branch","main")):
            value=run();value[key]=bad
            with self.subTest(key=key),self.assertRaises(policy.Refusal):model.native_role(runtime,value,selected())

    def test_explicit_zero_runner_main_hold_and_diagnostic_reverse_hold(self):
        jobs=[skipped(n,i+1)for i,n in enumerate(actual_held_names())]
        source=run(policy.WORKFLOW);source.update(name=policy.CAMPAIGN,display_title=policy.CAMPAIGN)
        model.validate_record(runtime,source,selected(),jobs,[],"123456")
        reverse=[skipped(n,i+11)for i,n in enumerate(("admission",model.UNEXPANDED,"final"))]
        model.validate_record(runtime,run(),model.template(),reverse,[],"123456")
        self.assertEqual(runtime.observed_jobs(jobs,NOW,True,runtime.SOURCE_JOBS)[0],0)
        self.assertEqual(runtime.observed_jobs(reverse,NOW,True,model.NATIVE_LIMITS)[0],0)

    def test_hold_never_defaults_missing_runner_acquisition_or_steps(self):
        for field,bad in (("runner_id",5),("runner_id",False),("runner_name","hosted"),
            ("runner_group_name","GitHub Actions"),("steps",[{"name":"executed"}]),("conclusion","cancelled")):
            rows=[skipped(n,i+1)for i,n in enumerate(actual_held_names())];rows[0][field]=bad
            with self.subTest(field=field,bad=bad),self.assertRaises(policy.Refusal):model.zero_runner_jobs(rows,actual_held_names())
        rows=[skipped(n,i+1)for i,n in enumerate(actual_held_names())];del rows[0]["runner_group_name"]
        with self.assertRaises(policy.Refusal):model.zero_runner_jobs(rows,actual_held_names())

    def test_held_artifact_or_overlapping_diagnostic_refuses(self):
        rows=[skipped(n,i+1)for i,n in enumerate(("admission",model.UNEXPANDED,"final"))]
        with self.assertRaises(policy.Refusal):model.validate_record(runtime,run(),model.template(),rows,[{"id":1}],"123456")
        value=run(status="in_progress",conclusion=None)
        with self.assertRaises(policy.Refusal):model.validate_record(runtime,value,selected(),[],[],"999999")

    def test_diagnostic_job_matrix_expansion_and_failed_admission_are_explicit(self):
        jobs=[skipped(n,i+1)for i,n in enumerate(model.LIMITS)]
        jobs[0]["conclusion"]="success"
        model.validate_record(runtime,run(),selected(),jobs,[],"123456")
        jobs=[skipped(n,i+1)for i,n in enumerate(("admission",model.UNEXPANDED,"final"))]
        jobs[0]["conclusion"]="failure"
        model.validate_record(runtime,run(),selected(),jobs,[],"123456")
        jobs.append(skipped("unknown",99))
        with self.assertRaises(policy.Refusal):model.validate_record(runtime,run(),selected(),jobs,[],"123456")

    def test_original_predecessor_must_be_actual_failed_H_not_prep_or_pass(self):
        prior=run(policy.WORKFLOW,rid=model.PRIOR["runId"],head=model.PRIOR["pipelineHead"])
        row=(model.PRIOR["runId"],prior,SOURCE,SOURCE_RAW)
        self.assertEqual(model.predecessor([row],selected()),model.PRIOR["runId"])
        for field,bad in (("status","in_progress"),("conclusion","success"),("head_sha","f"*40)):
            changed=deepcopy(prior);changed[field]=bad
            with self.assertRaises(policy.Refusal):model.predecessor([(row[0],changed,SOURCE,SOURCE_RAW)],selected())
        with self.assertRaises(policy.Refusal):model.predecessor([],selected())
        with self.assertRaises(policy.Refusal):model.predecessor([(row[0],prior,{**SOURCE,"phase":"lock-preparation"},SOURCE_RAW)],selected())

    def test_no_automatic_second_diagnostic_but_reverse_held_records_are_countable(self):
        rows=[("123456",run(),selected()),("333333",run(rid="333333"),model.template())]
        model.once_current(rows,"123456")
        with self.assertRaises(policy.Refusal):model.once_current(rows+[("444444",run(rid="444444"),selected())],"123456")

    def test_at_head_source_mode_does_not_bind_later_H2_to_old_H(self):
        calls=[]
        def content(api,path,head,*args):
            calls.append(path)
            if path==model.REQUEST_PATH:return policy.encode(model.template())
            raise AssertionError("inactive diagnostic must not compare H2 source to H")
        fake=types.SimpleNamespace(content=content,REQUEST=runtime.REQUEST)
        self.assertEqual(model.at_head(fake,None,"b"*40)[0],model.template())
        self.assertEqual(calls,[model.REQUEST_PATH])

    def test_budget_preserves_actual_and_booked_floors_without_old2944_or_current_double_booking(self):
        minutes={(rid,1):1 if i<38 else 0 for i,rid in enumerate(grants.PREFIX_RUN_IDS)}
        minutes[("555555",1)]=200;minutes[("123456",1)]=2
        grant={"bookedAdditionalAttempts":[{"runId":"555555","nativeAttempt":1,"runnerMinutes":250}]}
        charged,facts=model.budget(runtime,grant,minutes,"123456",2,selected())
        self.assertEqual(charged,290)
        self.assertEqual(facts["otherMinutesCharged"],288)
        self.assertEqual(facts["maximumNewMinutesBooked"],288+160+1075+180+50)
        self.assertFalse(facts["sourceExecutionAdvanced"])
        self.assertNotIn(2944,facts.values())
        bad=deepcopy(grant);bad["bookedAdditionalAttempts"].append({"runId":"123456","nativeAttempt":1,"runnerMinutes":2})
        with self.assertRaises(policy.Refusal):model.budget(runtime,bad,minutes,"123456",2,selected())
        minutes[("555555",1)]=2400
        with self.assertRaises(grants.Refusal):model.budget(runtime,grant,minutes,"123456",2,selected())

    def test_every_diagnostic_and_zero_runner_hold_attempt_still_counts(self):
        rows={rid:{"id":int(rid),"run_attempt":1}for rid in grants.PREFIX_RUN_IDS}
        rows.update({"123456":{"id":123456,"run_attempt":1},"234567":{"id":234567,"run_attempt":1}})
        facts=grants.count_attempts(rows,set(),{"bookedAdditionalAttempts":[]})
        self.assertEqual(facts["additionalAttemptCount"],2)
        self.assertEqual(facts["stageAttemptCount"],44)
        rows["123456"]["run_attempt"]=2
        facts=grants.count_attempts(rows,set(),{"bookedAdditionalAttempts":[]})
        self.assertEqual(facts["additionalAttemptCount"],3)
        self.assertEqual(facts["unsupportedNativeReruns"],["123456"])

    def test_manifest_seam_is_fixed_reviewed_R2_and_no_raw_upload_selected(self):
        self.assertEqual(model.manifest_capture(Path("/not-read"),selected())["status"],"fixed_public_validator_bound")
        value=selected();value["publicManifestCapture"]={"path":"arbitrary"}
        with self.assertRaises(policy.Refusal):model.manifest_capture(Path("/not-read"),value)

    def test_workflow_is_fixed_secretless_bounded_and_mutual(self):
        workflow=(HERE/"fixtures/v109-model-diagnostic.yml").read_text()
        held=(HERE/"fixtures/v109-source-validation-held.yml").read_text()
        restored=(HERE/"fixtures/v109-source-validation-restored.yml").read_text()
        self.assertEqual(hashlib.sha256(workflow.encode()).hexdigest(),model.DIAGNOSTIC_WORKFLOW_SHA256)
        self.assertEqual(hashlib.sha256(restored.encode()).hexdigest(),model.SOURCE_WORKFLOW_RESTORED)
        self.assertEqual(hashlib.sha256(held.encode()).hexdigest(),model.SOURCE_WORKFLOW_HELD)
        self.assertEqual(workflow.count("contains(github.event.pull_request.body, '"+model.HOLD_MARKER+"')"),4)
        self.assertEqual(held.count("!contains(github.event.pull_request.body, '"+model.HOLD_MARKER+"')"),3)
        self.assertNotIn(model.HOLD_MARKER,restored)
        for forbidden in ("workflow_dispatch", "pull_request_target:", "secrets.", "docker ", "gcloud ", "persist-credentials: true"):
            self.assertNotIn(forbidden,workflow)
        for required in ("max-parallel: 2", "profile: [models-1, models-2]", "timeout-minutes: 30", "timeout-minutes: 60",
            "timeout-minutes: 10", "actions: read", "contents: read", "pull-requests: read", "retention-days: 3",
            "'future-v109-model-diagnostic-hold-pr28'"):
            self.assertIn(required,workflow)
        self.assertNotIn("source-validation.json",workflow)

    def test_cli_has_no_arbitrary_ref_command_build_or_dispatch(self):
        # Only the argparse shape is inspected; main() is never entered here.
        tree=ast.parse((HERE/"model_diagnostic_v109.py").read_text())
        choices=[kw.value for node in ast.walk(tree)if isinstance(node,ast.Call)for kw in node.keywords if kw.arg=="choices"]
        self.assertIn(("admit","fetch-closure","run","finalize"),[ast.literal_eval(v)for v in choices if isinstance(v,ast.Tuple)])
        self.assertNotIn("derive",(HERE/"model_diagnostic_v109.py").read_text().split('choices=')[1].split(')')[0])

    def test_selected_and_held_workflows_cannot_deadlock_the_executable_group(self):
        held=(HERE/"fixtures/v109-source-validation-held.yml").read_text()
        diagnostic=(HERE/"fixtures/v109-model-diagnostic.yml").read_text()
        expected_source="group: ${{ contains(github.event.pull_request.body, '"+model.HOLD_MARKER+"') && 'future-v109-source-hold-pr28' || 'future-v109-source-validation-pr28' }}"
        expected_diagnostic="group: ${{ contains(github.event.pull_request.body, '"+model.HOLD_MARKER+"') && 'future-v109-source-validation-pr28' || 'future-v109-model-diagnostic-hold-pr28' }}"
        self.assertIn(expected_source,held)
        self.assertIn(expected_diagnostic,diagnostic)
        executable="future-v109-source-validation-pr28"
        for selected in (False,True):
            groups=("future-v109-source-hold-pr28"if selected else executable,
                executable if selected else"future-v109-model-diagnostic-hold-pr28")
            self.assertEqual(groups.count(executable),1)
            self.assertNotEqual(*groups)

    def test_actual_history_function_routes_diagnostic_and_reverse_hold_without_advancing_source(self):
        """Only the NEW routing composition is real here. Unchanged baseline,
        provider retrieval, legacy request validation and sequence replay are
        explicitly mocked at their reviewed boundaries, not claimed observed.
        No HTTP, Git or application is run; rows below are synthetic envelopes.
        """
        def acquired(name,jid,done=True,conclusion="success"):
            return {"id":jid,"name":name,"run_attempt":1,"status":"completed"if done else"in_progress",
                "conclusion":conclusion if done else None,"runner_id":jid,"runner_name":"synthetic hosted",
                "runner_group_name":"GitHub Actions","labels":["ubuntu-24.04"],"steps":[],
                "started_at":runtime.now_utc(NOW-120),"completed_at":runtime.now_utc(NOW-60)if done else None}
        def queued(name,jid):
            v=skipped(name,jid);v.update(status="queued",conclusion=None,started_at=None);return v
        for reverse in (False,True):
            with self.subTest(reverse=reverse):
                history,jobs,contents={}, {}, {}
                serial=1000
                def record(rid,path,head,native,conclusion="failure",current=False):
                    nonlocal serial
                    value=run(path,rid,head,"in_progress"if current else"completed",None if current else conclusion)
                    value["created_at"]=runtime.now_utc(NOW-3600)
                    if path==policy.WORKFLOW:value.update(name=policy.CAMPAIGN,display_title=policy.CAMPAIGN)
                    elif path==".github/workflows/synthetic-incidental.yml":value.update(name="synthetic incidental",display_title="synthetic incidental")
                    history[rid]=value;jobs[rid]=native
                    serial+=100
                for i,rid in enumerate(grants.PREFIX_RUN_IDS):
                    native=[acquired("synthetic incidental",serial)]if i<38 else[skipped("synthetic incidental",serial)]
                    record(rid,".github/workflows/synthetic-incidental.yml","a"*40,native)
                generation=SOURCE["generation"]
                lock={**SOURCE,"phase":"lock-preparation","generation":None}
                record(generation["runId"],policy.WORKFLOW,generation["pipelineHead"],
                    [acquired("lock-preparation",serial)],"success")
                prior_jobs=[skipped(name,serial+i)for i,name in enumerate(runtime.SOURCE_JOBS)if name!="source (${{ matrix.profile }})"]
                prior_jobs[0]=acquired("admission",serial)
                record(model.PRIOR["runId"],policy.WORKFLOW,model.PRIOR["pipelineHead"],prior_jobs)
                diag_id,hold_id,diag_head="123456","234567","d"*40
                if reverse:
                    diag_jobs=[acquired(name,serial+i,conclusion="failure"if name.startswith("diagnostic (")else"success")for i,name in enumerate(model.LIMITS)]
                    record(diag_id,model.WORKFLOW,diag_head,diag_jobs)
                else:
                    record(diag_id,model.WORKFLOW,diag_head,[acquired("admission",serial,False),
                        queued(model.UNEXPANDED,serial+1),queued("final",serial+2)],current=True)
                record(hold_id,policy.WORKFLOW,diag_head,[skipped(n,serial+i)for i,n in enumerate(actual_held_names())],"skipped")
                current_id,current_request=(diag_id,SOURCE)
                if reverse:
                    current_id="777777";current_head="e"*40
                    current_request=deepcopy(SOURCE);current_request.update(phase="correction",executionSequence=6)
                    current_request["source"]["sourceSha"]="f"*40
                    record(current_id,policy.WORKFLOW,current_head,[acquired("admission",serial,False),
                        queued("source (${{ matrix.profile }})",serial+1),queued("final",serial+2)],current=True)
                    record("888888",model.WORKFLOW,current_head,[skipped(n,serial+i)for i,n in enumerate(
                        ("admission",model.UNEXPANDED,"final"))],"skipped")
                    contents[current_head,model.REQUEST_PATH]=policy.encode(model.template())
                    contents[current_head,runtime.REQUEST]=policy.encode(current_request)
                source_body=policy.encode(SOURCE)
                contents[diag_head,model.REQUEST_PATH]=policy.encode(selected())
                contents[diag_head,runtime.REQUEST]=SOURCE_RAW
                contents[model.PRIOR["pipelineHead"],runtime.REQUEST]=SOURCE_RAW
                contents[generation["pipelineHead"],runtime.REQUEST]=policy.encode(lock)
                grant={"authoritySha256":model.AUTHORITY,"bookedAdditionalAttempts":[],
                    "nextExecution":{"reservations":{"current":1075,"pendingValidation":0,"conditionalImage":180,"incidental":50},
                        "requestSha256":model.H_REQUEST}}
                binding={"authorization":{"approvedAt":model.START},"ciRunGrant":grant,
                    "preparationCorrection":None,"validation":{"source":SOURCE["source"],"generation":generation}}
                def content(api,path,head,*args):
                    if path==runtime.BINDINGS:
                        historical=deepcopy(binding)
                        historical["ciRunGrant"]["nextExecution"]["requestSha256"]=policy.digest(contents[head,runtime.REQUEST])
                        return policy.encode(historical)
                    return contents[head,path]
                captured=[]
                def sequence(b,q,rows,current):
                    captured.append({"ids":{r[0]for r in rows},"current":current,"request":q})
                    return {"sourceExecutionSequence":q["executionSequence"]}
                tree=ast.parse((HERE/"source_validation_v109.py").read_text())
                node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=="history_checks")
                module=types.ModuleType("synthetic_model_history_composition")
                module.__dict__.update(runtime.__dict__)
                module.__name__="synthetic_model_history_composition"
                module.history_rows=lambda api,clock:history
                module.closed_baseline=lambda *a:(set(),set(),set())
                module.content=content
                module.regular=lambda *a:b"synthetic already-reviewed baseline boundary"
                module.jobs_for=lambda api,r:jobs[str(r["id"])]
                module.artifacts_for=lambda *a:[]
                module.pipeline_recovery_history=lambda *a:{"syntheticBoundary":True}
                module.bounded_source_history=sequence
                module.emit=lambda value:None
                resolver=types.SimpleNamespace(WORKFLOW=policy.WORKFLOW,resolve_baseline_258=lambda *a:{"runs":[
                    {"id":987654,"path":".github/workflows/synthetic-incidental.yml"}]})
                exec(compile(ast.Module(body=[node],type_ignores=[]),"actual-history-checks","exec"),module.__dict__)
                with patch.dict(sys.modules,{module.__name__:module}),patch.object(policy,"validate_bindings",side_effect=lambda x:x),\
                     patch.object(policy,"validate_request",side_effect=lambda x,b:x),patch.object(grants,"validate_grant",return_value=grant):
                    facts=module.history_checks(Path("/not-read"),binding,current_request,policy.encode(current_request),
                        history[current_id]["head_sha"],{}, {"GITHUB_RUN_ID":current_id},None,resolver,NOW,
                        diagnostic=None if reverse else selected())
                self.assertEqual(len(captured),1)
                self.assertNotIn(diag_id,captured[0]["ids"])
                self.assertNotIn(hold_id,captured[0]["ids"])
                self.assertNotIn("888888",captured[0]["ids"])
                self.assertEqual(captured[0]["current"],current_id if reverse else model.PRIOR["runId"])
                self.assertEqual(facts["currentBookingMinutes"],1075 if reverse else 160)
                self.assertEqual(facts["separateDiagnosticRecords"],3 if reverse else 2)
                self.assertEqual(facts["sourceExecutionAdvanced"],reverse)
                self.assertEqual(facts["historicalMinutes"],2944)

    def capture_fixture(self, temporary):
        import manifest_capture as capture
        root=Path(temporary).resolve();source=root/"source";source.mkdir()
        for plugin,path in capture.PLUGIN_PATHS.items():
            file=source/path;file.parent.mkdir(parents=True,exist_ok=True)
            file.write_bytes((HERE/"public-originals"/(plugin+".json")).read_bytes());file.chmod(0o644)
        events,outputs=[],[]
        def loader(pipeline,name,relative,pin):
            self.assertEqual(relative,model.CAPTURE_MODULE);self.assertEqual(pin,model.CAPTURE_SHA256)
            return capture
        def read(source,*args,deadline):
            return (model.H.encode()+b"\n"if args==("rev-parse","HEAD")else
                model.H_TREE.encode()+b"\n"if args==("rev-parse","HEAD^{tree}")else b" M extensions/workboard/openclaw.plugin.json\n")
        fake=types.SimpleNamespace(load_owner=loader,source_binding=lambda *a:None,git_read=read,
            emit=events.append,write_outputs=lambda env,value:outputs.append(value))
        env={"RUNNER_TEMP":str(root),"GITHUB_RUN_ID":"123456"};context={"deadlineEpoch":time.time()+60}
        return capture,source,fake,env,context,events,outputs

    def capture_metadata(self,capture,source):
        path=capture.PLUGIN_PATHS["workboard"];raw=(HERE/"public-originals/workboard.json").read_bytes()
        blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
        return {"checks":{"head":{"matches":True},"tree":{"matches":True},"trackedStatus":{"clean":False}},
            "paths":[{"path":path,"statusCode":" M","before":{"availability":"hashed","mode":"100644","gitOid":blob},
                "index":[{"gitOid":blob,"mode":"100644","stage":0}],"after":{"availability":"hashed","mode":"100644"}}],
            "unknownPathCount":0,"omittedKnownPaths":0,"issueCodes":[]}

    def test_capture_adapter_accepts_only_complete_validated_five_file_payload(self):
        import source_profile_diagnostic_v109 as diagnostic
        with tempfile.TemporaryDirectory()as tmp:
            capture,source,fake,env,context,events,outputs=self.capture_fixture(tmp)
            state=model.capture_before(fake,HERE.parents[1],source,env,context,selected(),"models-1",SOURCE)
            after=json.loads((HERE/"public-originals/workboard.json").read_bytes());after["controlUi"]={
                "entry":"dist/control-ui/"+"a"*64+"/index.js","styles":["dist/control-ui/"+"a"*64+"/index.css"]}
            (source/capture.PLUGIN_PATHS["workboard"]).write_bytes(capture._encode(after))
            with patch.object(diagnostic,"report",return_value=self.capture_metadata(capture,source)):
                model.capture_after(fake,source,SOURCE,env,context,"models-1",state)
            self.assertEqual(outputs,[{"public_payload":"true"}])
            payload=state[1]/"validated-payload"
            self.assertEqual({p.name for p in payload.iterdir()},{"workboard.after.json","workboard.diff","x.after.json","x.diff","manifest-capture-receipt.json"})
            self.assertLessEqual(sum(p.stat().st_size for p in payload.iterdir()),2*1024*1024)
            self.assertEqual(events[-1]["producerObservedCheck"],"not_collected")
            self.assertFalse(events[-1]["assetContentAuthenticated"])
            self.assertFalse(events[-1]["qualified"])

    def test_capture_adapter_rejects_unknown_dirty_paths_or_moved_head_without_raw_export(self):
        import source_profile_diagnostic_v109 as diagnostic
        for kind in ("unknown", "moved", "staged", "cap"):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory()as tmp:
                capture,source,fake,env,context,events,outputs=self.capture_fixture(tmp)
                state=model.capture_before(fake,HERE.parents[1],source,env,context,selected(),"models-1",SOURCE)
                metadata=self.capture_metadata(capture,source)
                if kind=="unknown":metadata["unknownPathCount"]=1
                elif kind=="moved":metadata["checks"]["head"]["matches"]=False
                elif kind=="staged":metadata["paths"][0]["statusCode"]="M "
                else:metadata["omittedKnownPaths"]=1
                with patch.object(diagnostic,"report",return_value=metadata):
                    model.capture_after(fake,source,SOURCE,env,context,"models-1",state)
                self.assertEqual(outputs,[])
                self.assertFalse((state[1]/"validated-payload").exists())
                self.assertEqual(events[-1]["status"],"metadata_only")

    def test_capture_rejected_manifest_fields_never_enable_upload(self):
        import source_profile_diagnostic_v109 as diagnostic
        with tempfile.TemporaryDirectory()as tmp:
            capture,source,fake,env,context,events,outputs=self.capture_fixture(tmp)
            state=model.capture_before(fake,HERE.parents[1],source,env,context,selected(),"models-1",SOURCE)
            raw=json.loads((HERE/"public-originals/workboard.json").read_bytes());raw["privateInserted"]="DO-NOT-EXPORT"
            (source/capture.PLUGIN_PATHS["workboard"]).write_bytes(capture._encode(raw))
            with patch.object(diagnostic,"report",return_value=self.capture_metadata(capture,source)):
                model.capture_after(fake,source,SOURCE,env,context,"models-1",state)
            self.assertEqual(outputs,[])
            self.assertNotIn("DO-NOT-EXPORT",json.dumps(events))
            self.assertFalse((state[1]/"validated-payload").exists())

    def test_capture_native_io_and_partial_export_failure_never_leak_or_enable_upload(self):
        import source_profile_diagnostic_v109 as diagnostic
        with tempfile.TemporaryDirectory()as tmp:
            capture,source,fake,env,context,events,outputs=self.capture_fixture(tmp)
            with patch.object(capture,"capture_before",side_effect=OSError("/PRIVATE/DO-NOT-EMIT")):
                state=model.capture_before(fake,HERE.parents[1],source,env,context,selected(),"models-1",SOURCE)
            self.assertFalse(state[2]);self.assertNotIn("PRIVATE",json.dumps(events))
            # No snapshot was created by the failed-before stub; use a genuine
            # fresh capture for the partial adjudication failure below.
            state=model.capture_before(fake,HERE.parents[1],source,env,context,selected(),"models-1",SOURCE)
            def partial(*args):
                out=state[1]/"validated-payload";out.mkdir();(out/"workboard.after.json").write_bytes(b"synthetic partial")
                raise OSError("/PRIVATE/DO-NOT-EMIT")
            with patch.object(diagnostic,"report",return_value=self.capture_metadata(capture,source)),\
                 patch.object(capture,"capture_after",return_value={}),patch.object(capture,"adjudicate",side_effect=partial):
                model.capture_after(fake,source,SOURCE,env,context,"models-1",state)
            self.assertEqual(outputs,[]);self.assertNotIn("PRIVATE",json.dumps(events))
            self.assertEqual(events[-1]["status"],"metadata_only")

    def test_upload_workflow_names_only_accepted_payload_never_capture_root(self):
        workflow=(HERE/"fixtures/v109-model-diagnostic.yml").read_text()
        self.assertIn("if: always() && steps.model.outputs.public_payload == 'true'",workflow)
        lines=[l.strip()for l in workflow.splitlines()if"/validated-payload/"in l]
        self.assertEqual(len(lines),5)
        self.assertTrue(all(l.startswith("${{ runner.temp }}/v109-model-manifest-capture-${{ matrix.profile }}/validated-payload/")for l in lines))
        self.assertFalse(any("*."in l or l.endswith("/validated-payload")for l in lines))

    def test_actual_profile_postguard_exception_still_adjudicates_then_reraises_original(self):
        import source_profile_diagnostic_v109 as diagnostic
        with tempfile.TemporaryDirectory()as tmp:
            capture,source,fake,env,context,events,outputs=self.capture_fixture(tmp)
            error=policy.Refusal("v9.profile_changed_tracked_source")
            post_calls=[]
            fake.safe_refusal_code=runtime.safe_refusal_code
            fake.post_profile_binding=lambda *a:post_calls.append(a)
            def actual_failed_boundary(*args):
                snapshot=Path(env["RUNNER_TEMP"])/"v109-model-manifest-capture-models-1/before.workboard.raw.json"
                self.assertEqual(snapshot.read_bytes(),(HERE/"public-originals/workboard.json").read_bytes())
                raw=json.loads(snapshot.read_bytes());raw["controlUi"]={"entry":"dist/control-ui/"+"b"*64+"/index.js"}
                (source/capture.PLUGIN_PATHS["workboard"]).write_bytes(capture._encode(raw))
                raise error
            fake.run_profile=actual_failed_boundary
            with patch.object(diagnostic,"report",return_value=self.capture_metadata(capture,source)),\
                 self.assertRaises(policy.Refusal)as observed:
                model.run_model(fake,HERE.parents[1],source,{},SOURCE,"models-1",env,None,context,selected())
            self.assertIs(observed.exception,error)
            self.assertEqual(post_calls,[])
            self.assertEqual(outputs,[{"public_payload":"true"}])
            self.assertEqual(len(list((Path(env["RUNNER_TEMP"])/"v109-model-manifest-capture-models-1/validated-payload").iterdir())),5)
            self.assertFalse(any(e.get("status")=="clean_at_check"for e in events))
            self.assertFalse(events[-1]["qualified"])

    def test_actual_command_failure_collects_metadata_but_preserves_original_failure(self):
        import source_profile_diagnostic_v109 as diagnostic
        with tempfile.TemporaryDirectory()as tmp:
            capture,source,fake,env,context,events,outputs=self.capture_fixture(tmp)
            error=policy.Refusal("v9.profile_failed");post_calls=[]
            fake.safe_refusal_code=runtime.safe_refusal_code
            def post(*args):
                post_calls.append(args)
                raise policy.Refusal("v9.profile_changed_tracked_source")
            fake.post_profile_binding=post
            def failed(*args):
                (source/capture.PLUGIN_PATHS["workboard"]).write_bytes(b"unadjudicated raw must not export")
                raise error
            fake.run_profile=failed
            with patch.object(diagnostic,"report",return_value=self.capture_metadata(capture,source)),\
                 self.assertRaises(policy.Refusal)as observed:
                model.run_model(fake,HERE.parents[1],source,{},SOURCE,"models-1",env,None,context,selected())
            self.assertIs(observed.exception,error)
            self.assertEqual(len(post_calls),1)
            self.assertEqual(outputs,[])
            self.assertEqual(events[-1]["status"],"metadata_only")
            self.assertNotIn("unadjudicated raw",json.dumps(events))

    def test_real_policy_main_preflight_reaches_fixed_API_boundary_only_for_exact_authority(self):
        """The actual main and actual canonical digest run. Existing file/code
        and provider boundaries are mocked; the API constructor is a sentinel
        so no request, process, candidate or operational binding can occur.
        """
        import test_source_validation_runtime_v109 as old_runtime_fixture
        class ReachedFixedAPI(Exception):pass
        raw=(HERE/"fixtures/v109-published-H-ci-bindings.json").read_bytes()
        self.assertEqual(policy.digest(raw),"4282645c2583d2714ed33b48d92c926883a633cfcda7b7073c0aa6bb460c56fc")
        binding=policy.parse(raw)
        authority=binding["authorization"]
        self.assertEqual(policy.digest(policy.canonical(authority)),model.AUTHORIZATION)
        event,env=old_runtime_fixture.event_env()
        event["pull_request"]["body"]=model.HOLD_MARKER
        env.update(GITHUB_WORKFLOW_REF=policy.REPOSITORY+"/"+model.WORKFLOW+"@refs/pull/28/merge",
            GITHUB_WORKSPACE="/synthetic-not-read",GITHUB_EVENT_PATH="/synthetic-event-not-read",
            V109_APPROVED_AT=model.START,V109_EXPIRES_AT=model.END,PATH="SYNTHETIC",GH_TOKEN="synthetic-not-used")
        env[runtime.CLOCK]=str(int(NOW)-1)
        def regular(path,*args):
            if str(path).endswith(model.REQUEST_PATH):return policy.encode(selected())
            if str(path)==env["GITHUB_EVENT_PATH"]:return policy.encode(event)
            raise AssertionError("unbound preflight file")
        core=types.SimpleNamespace(profile_signals=lambda:None)
        for valid in (True,False):
            b=deepcopy(binding)
            if not valid:b["authorization"]["newSecretsAllowedHere"]=True
            with patch.object(model.time,"time",return_value=NOW),\
                 patch.object(runtime,"load_metadata",return_value=(b,SOURCE,SOURCE_RAW)),\
                 patch.object(runtime,"regular",side_effect=regular),patch.object(runtime,"load_owner",return_value=core),\
                 patch.object(runtime,"code_binding",return_value=event["pull_request"]["head"]["sha"]),\
                 patch.object(runtime,"API",side_effect=ReachedFixedAPI)as api:
                if valid:
                    with self.assertRaises(ReachedFixedAPI):model.main(["admit"],env)
                    api.assert_called_once()
                else:
                    with self.assertRaisesRegex(policy.Refusal,"original_authority"):model.main(["admit"],env)
                    api.assert_not_called()

    def test_real_content_guard_allows_only_exact_new_request_path(self):
        value=policy.encode(model.template());calls=[]
        def api(path):
            calls.append(path)
            return {"type":"file","encoding":"base64","size":len(value),"content":base64.b64encode(value).decode()}
        self.assertEqual(runtime.content(api,model.REQUEST_PATH,"b"*40,16384),value)
        self.assertEqual(calls,["/repos/"+policy.REPOSITORY+"/contents/"+model.REQUEST_PATH+"?ref="+"b"*40])
        for path in (model.REQUEST_PATH+".backup",model.REQUEST_PATH.replace("request.json","other.json"),
            "https://invalid.example/request.json","../private"):
            with self.assertRaisesRegex(policy.Refusal,"fixed_content_read"):runtime.content(api,path,"b"*40)
        with self.assertRaises(policy.Refusal):runtime.content(api,model.REQUEST_PATH,"main")
        self.assertEqual(len(calls),1)

    def test_broken_capture_fallback_output_cannot_replace_original_postguard_refusal(self):
        import source_profile_diagnostic_v109 as diagnostic
        with tempfile.TemporaryDirectory()as tmp:
            capture,source,fake,env,context,events,outputs=self.capture_fixture(tmp)
            error=policy.Refusal("v9.profile_changed_tracked_source")
            fake.safe_refusal_code=runtime.safe_refusal_code
            fake.post_profile_binding=lambda *a:None
            fake.emit=lambda value:(_ for _ in ()).throw(OSError("/PRIVATE/DO-NOT-EMIT"))
            fake.run_profile=lambda *a:(_ for _ in ()).throw(error)
            with patch.object(diagnostic,"report",return_value=self.capture_metadata(capture,source)),\
                 self.assertRaises(policy.Refusal)as observed:
                model.run_model(fake,HERE.parents[1],source,{},SOURCE,"models-1",env,None,context,selected())
            self.assertIs(observed.exception,error)
            self.assertEqual(outputs,[])


if __name__ == "__main__":
    unittest.main()

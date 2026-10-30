"""Closed, pure policy for one private 10.9 image build.

A record is a constraint, never approval. Publication, temporary access and the
one physical build require the coordinating owner's genuine action-time scope.
The default request is DISARMED; final H and its passed CI proof cannot exist
until the approved secretless lock derivation and validation have completed.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import re
import stat
import zipfile

REPOSITORY = "fr-meyer/openclaw"
ACTOR = "fr-meyer"
BRANCH = "task/v107-source-binding"
REF = "refs/heads/" + BRANCH
WORKFLOW = ".github/workflows/future-v109-image-build.yml"
WORKFLOW_NAME = "future-v109-private-image-20261030"
SOURCE_WORKFLOW = ".github/workflows/future-v109-source-validation.yml"
SOURCE_NAME = "future-v109-grouped-validation-20261030"
CAMPAIGN = "future-v109-grouped-validation-20261030"
OPERATION = "hosted-private-grouped-20261030-01"
PREPARATION_SOURCE = "ba04217f6642091b94f396669318d068e6007ed7"
SCHEMA = "openclaw.v109.private-image-request.v1"
BUCKET = "openclaw-build-guard-source-1046324571444"
SIGNER = "openclaw-build-submitter@openclaw-family-gateway.iam.gserviceaccount.com"
SECRET = "OPENCLAW_PRIVATE_OCI_CAPABILITY_V109"
MAX_ARCHIVE = 2147483648
MAX_ARTIFACT = 2097152
MAX_RESULT = 16384
BUILD_MINUTES = 90
FAMILY_MINUTES = 180
RESERVE_SECONDS = 300
MIN_UPLOAD_WINDOW = 2700
SHA = re.compile(r"[0-9a-f]{40}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
RUN = re.compile(r"[1-9][0-9]{0,19}\Z")
PROFILES = ("dependency", "types-production", "types-tests", "types-scripts", "workboard-1", "workboard-2",
            "models-1", "models-2", "sqlite", "doctor-1", "doctor-2", "doctor-3", "memory", "pipeline-contracts", "compatibility")


class Refusal(ValueError):
    pass


def need(value, code):
    if not value:
        raise Refusal(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fields(value, names, code):
    need(type(value) is dict and set(value) == set(names), code)
    return value


def pin(value, commit=False):
    return type(value) is str and (SHA if commit else HEX).fullmatch(value) is not None


def encode(value):
    return (json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode()


def parse(raw, limit=MAX_ARTIFACT):
    need(type(raw) is bytes and 0 < len(raw) <= limit, "image.bounded_json")
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "image.duplicate_json_key")
            result[key] = value
        return result
    def constant(_):
        raise Refusal("image.json_constant")
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except Refusal:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise Refusal("image.invalid_json") from None


def utc(value):
    need(type(value) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value), "image.canonical_utc")
    try:
        stamp = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise Refusal("image.canonical_utc") from None
    need(stamp.strftime("%Y-%m-%dT%H:%M:%SZ") == value, "image.canonical_utc")
    return stamp


def disarmed_request():
    return {"schema": SCHEMA, "state": "DISARMED", "campaignId": CAMPAIGN, "repository": REPOSITORY,
        "workflow": WORKFLOW, "workflowBranch": BRANCH, "operationId": OPERATION,
        "preparationSourceSha": PREPARATION_SOURCE, "previousPipelineHead": None, "sourceSha": None, "sourceTree": None,
        "sourceBindingsSha256": None, "sourceRequestSha256": None, "generationReceiptSha256": None,
        "manifestSha256": None, "inventorySha256": None, "builtAt": None, "sourceValidation": None,
        "privateObject": {"bucket": BUCKET, "object": None, "signer": SIGNER, "secretName": SECRET,
            "maximumBytes": MAX_ARCHIVE, "putMaximumSeconds": 3600, "getMaximumSeconds": 900,
            "uploadGrantMaximumSeconds": 7200, "readerGrantMaximumSeconds": 900},
        "authorization": None}


def expected_object(source):
    need(pin(source, True), "image.source_pin")
    return f"oci-quarantine/v2026.10.9/{source}/{OPERATION}/retained-oci.tar"


def validate_request(value, active=False, now=None):
    template = disarmed_request()
    fields(value, template, "image.request_fields")
    for key in ("schema", "campaignId", "repository", "workflow", "workflowBranch", "operationId"):
        need(value[key] == template[key], "image.fixed_scope")
    need(value["state"] in ("DISARMED", "PREPARED_BUILD", "APPROVED_BUILD"), "image.state")
    obj = fields(value["privateObject"], template["privateObject"], "image.object_fields")
    need({k:v for k,v in obj.items() if k != "object"} ==
        {k:v for k,v in template["privateObject"].items() if k != "object"}, "image.object_scope")
    if value["state"] == "DISARMED":
        need(value == template and not active, "image.disarmed")
        return value
    need(all(pin(value[k], True) for k in ("preparationSourceSha", "previousPipelineHead", "sourceSha", "sourceTree")),
         "image.source_identity")
    need(all(pin(value[k]) for k in ("sourceBindingsSha256", "sourceRequestSha256", "generationReceiptSha256",
                                     "manifestSha256", "inventorySha256")), "image.input_pins")
    need(obj["object"] == expected_object(value["sourceSha"]), "image.exact_object")
    need(value["sourceSha"] != value["preparationSourceSha"], "image.prelock_source_refused")
    built = utc(value["builtAt"])
    if now is not None:
        need(built.timestamp() <= now, "image.future_build_input")
    proof = fields(value["sourceValidation"], ("runId", "attempt", "pipelineHead", "phase", "artifactId",
        "artifactSha256", "resultSha256"), "image.validation_pin_fields")
    need(type(proof["runId"]) is str and RUN.fullmatch(proof["runId"]) and
        type(proof["attempt"]) is int and proof["attempt"] == 1 and pin(proof["pipelineHead"], True) and
        proof["phase"] in ("validation", "correction") and type(proof["artifactId"]) is int and proof["artifactId"] > 0 and
        pin(proof["artifactSha256"]) and pin(proof["resultSha256"]) and
        value["previousPipelineHead"] == proof["pipelineHead"], "image.validation_pins")
    if value["state"] == "PREPARED_BUILD":
        need(value["authorization"] is None and not active, "image.prepared_not_authorized")
        return value
    auth = fields(value["authorization"], ("schema", "approvedAt", "expiresAt", "approvalScopeSha256",
        "actionTimeAccessApprovalSha256", "maximumPhysicalBuilds", "maximumBuildMinutes", "maximumFamilyMinutes",
        "maximumArchiveBytes", "maximumNewRunnerMinutes", "moneyCeilingUSDIncludingAllowance",
        "producedImageExecutionAllowed", "publicImageExportAllowed", "cloudGrantFromRunnerAllowed"), "image.authorization_fields")
    need(auth["schema"] == "openclaw.v109.private-image-authorization.v1" and pin(auth["approvalScopeSha256"]) and
        pin(auth["actionTimeAccessApprovalSha256"]), "image.action_time_approval_binding")
    start, end = utc(auth["approvedAt"]), utc(auth["expiresAt"])
    need(end-start == timedelta(hours=72), "image.exact_72_hour_window")
    expected = {"maximumPhysicalBuilds":1, "maximumBuildMinutes":BUILD_MINUTES, "maximumFamilyMinutes":FAMILY_MINUTES,
        "maximumArchiveBytes":MAX_ARCHIVE, "maximumNewRunnerMinutes":2500,
        "moneyCeilingUSDIncludingAllowance":"2.25", "producedImageExecutionAllowed":False,
        "publicImageExportAllowed":False, "cloudGrantFromRunnerAllowed":False}
    need(all(type(auth[k]) is type(v) and auth[k] == v for k,v in expected.items()), "image.exact_limits")
    if now is not None:
        need(type(now) in (int,float) and start.timestamp() <= now < end.timestamp(), "image.authorization_clock")
    if active:
        need(now is not None, "image.live_clock_required")
    return value


def validate_context(context, request, now):
    validate_request(request, active=True, now=now)
    fields(context, ("repository", "actor", "event", "ref", "sha", "workflowSha", "runId", "attempt",
        "before", "after", "created", "deleted", "forced"), "image.context_fields")
    need(context["repository"] == REPOSITORY and context["actor"] == ACTOR and context["event"] == "push" and
        context["ref"] == REF and pin(context["sha"], True) and context["sha"] == context["workflowSha"] == context["after"] and
        context["before"] == request["previousPipelineHead"] and type(context["runId"]) is str and RUN.fullmatch(context["runId"]) and
        type(context["attempt"]) is int and context["attempt"] == 1 and context["created"] is False and
        context["deleted"] is False and context["forced"] is False, "image.exact_push_context")
    return context


def artifact_result(zip_raw):
    need(type(zip_raw) is bytes and len(zip_raw)<=MAX_ARTIFACT,"image.source_artifact_bound")
    try:
        with zipfile.ZipFile(io.BytesIO(zip_raw)) as archive:
            entries = archive.infolist()
            need(len(entries)==1 and entries[0].filename=="source-validation.json" and
                not entries[0].is_dir() and entries[0].flag_bits&1 == 0 and entries[0].file_size<=MAX_RESULT and
                stat.S_IFMT(entries[0].external_attr >> 16) in (0, stat.S_IFREG),
                "image.source_artifact_member")
            raw = archive.read(entries[0])
    except Refusal:
        raise
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
        raise Refusal("image.source_artifact_zip") from None
    return raw


def validate_source_snapshot(request, run, jobs, artifacts, zip_raw, result_validator):
    """Consume actual GitHub facts; neither request nor a claimed pass is proof."""
    validate_request(request)
    p = request["sourceValidation"]
    need(type(run) is dict and str(run.get("id")) == p["runId"] and type(run.get("run_attempt")) is int and run.get("run_attempt") == 1 and
        run.get("head_sha") == p["pipelineHead"] and run.get("path") == SOURCE_WORKFLOW and
        run.get("event") == "pull_request" and run.get("head_branch") == BRANCH and
        run.get("display_title") == SOURCE_NAME and run.get("status") == "completed" and run.get("conclusion") == "success" and
        run.get("repository",{}).get("full_name") == REPOSITORY and run.get("repository",{}).get("private") is False and
        run.get("actor",{}).get("login") == ACTOR and run.get("triggering_actor",{}).get("login") == ACTOR,
        "image.source_run_binding")
    need(type(jobs) is dict and type(jobs.get("total_count")) is int and
        jobs["total_count"] == len(jobs.get("jobs", [])) == 17, "image.complete_source_jobs")
    expected = {"admission", "final"} | {f"source ({p})" for p in PROFILES}
    rows = jobs["jobs"]
    need({j.get("name") for j in rows} == expected and len({j.get("id") for j in rows}) == 17 and
        all(j.get("status") == "completed" and j.get("conclusion") == "success" and
            str(j.get("run_id")) == p["runId"] for j in rows), "image.all15_actual_source_passed")
    need(type(artifacts) is dict and type(artifacts.get("total_count")) is int and
        artifacts["total_count"] == len(artifacts.get("artifacts", [])) == 1, "image.single_source_artifact")
    a = artifacts["artifacts"][0]
    need(a.get("id") == p["artifactId"] and a.get("name") == f"v109-source-validation-{p['runId']}-attempt1" and
        a.get("expired") is False and type(a.get("size_in_bytes")) is int and 0<a["size_in_bytes"]<=MAX_ARTIFACT and
        a.get("digest") == "sha256:"+p["artifactSha256"] and
        a.get("workflow_run",{}).get("head_sha") == p["pipelineHead"] and
        str(a.get("workflow_run",{}).get("id")) == p["runId"], "image.source_artifact_metadata")
    need(type(zip_raw) is bytes and len(zip_raw)<=MAX_ARTIFACT and sha(zip_raw)==p["artifactSha256"], "image.source_artifact_digest")
    raw = artifact_result(zip_raw)
    need(len(raw)<=MAX_RESULT and sha(raw)==p["resultSha256"], "image.source_result_pin")
    value = result_validator(raw)
    need(type(value) is dict and value.get("sourceSha")==request["sourceSha"] and value.get("sourceTree")==request["sourceTree"] and
        value.get("manifestSha256")==request["manifestSha256"] and value.get("inventorySha256")==request["inventorySha256"] and
        value.get("requestSha256")==request["sourceRequestSha256"] and
        value.get("generationReceiptSha256")==request["generationReceiptSha256"] and value.get("status")=="passed" and
        value.get("imageBuilt") is False and value.get("nativeImageExecuted") is False and value.get("productionAuthorized") is False,
        "image.exact_source_result")
    return value


def validate_image_history(request, context, runs, jobs_by_run):
    """Any previously admitted physical job, pending outcome or retry refuses."""
    need(type(runs) is dict and type(runs.get("total_count")) is int and
        runs["total_count"]==len(runs.get("workflow_runs",[])) and 1<=runs["total_count"]<=64,
        "image.complete_history")
    rows=runs["workflow_runs"]
    need(len({r.get("id") for r in rows})==len(rows), "image.duplicate_run")
    found=False
    for run in rows:
        rid=str(run.get("id"))
        need(run.get("path")==WORKFLOW and run.get("event")=="push" and run.get("head_branch")==BRANCH and
            type(run.get("run_attempt")) is int and run.get("run_attempt")==1 and run.get("actor",{}).get("login")==ACTOR and
            run.get("triggering_actor",{}).get("login")==ACTOR,
            "image.history_identity")
        if rid==context["runId"]:
            need(not found and run.get("head_sha")==context["sha"] and run.get("status") in ("queued","in_progress"),
                 "image.current_run_identity")
            found=True
            continue
        need(run.get("status")=="completed" and rid in jobs_by_run, "image.prior_outcome_unsettled")
        page=jobs_by_run[rid]
        need(type(page) is dict and page.get("total_count")==len(page.get("jobs",[]))==2 and
            {j.get("name") for j in page["jobs"]}=={"image-admission","build-private-image"} and
            len({j.get("id") for j in page["jobs"]})==2, "image.prior_jobs_complete")
        for job in page["jobs"]:
            need(job.get("status")=="completed" and str(job.get("run_id"))==rid, "image.prior_job_unsettled")
            if job.get("name")=="image-admission":
                need(job.get("conclusion")=="success", "image.prior_admission_refusal")
            if job.get("name")=="build-private-image":
                need(job.get("conclusion")=="skipped" and not job.get("steps"), "image.physical_attempt_already_consumed")
    need(found, "image.current_run_missing")
    return True


def family_budget(prior_minutes):
    """Reserve the full current admission/build caps after all prior actual use."""
    need(type(prior_minutes)is list and all(type(v)is int and v>=0 for v in prior_minutes),
         "image.measured_family_minutes")
    actual=sum(prior_minutes);reserved=15+BUILD_MINUTES
    need(actual+reserved<=FAMILY_MINUTES,"image.family_budget_exhausted")
    return {"priorRunnerMinutes":actual,"currentReservedMinutes":reserved,
            "maximumFamilyMinutes":FAMILY_MINUTES}


def validate_envelope(envelope_raw, request, context, transfer_validator, now, *, before_build=True):
    envelope=parse(envelope_raw,32768)
    fields(envelope,("schema","sourceSha","workflowSha","bucket","object","signer","url"),"image.capability_fields")
    need(envelope["schema"]=="openclaw.private-oci-capability.v1" and envelope["sourceSha"]==request["sourceSha"] and
        envelope["workflowSha"]==context["sha"] and
        all(envelope[k]==request["privateObject"][k] for k in ("bucket","object","signer")), "image.capability_scope")
    need(type(envelope["url"]) is str and 0<len(envelope["url"])<=16384 and
        all(32<ord(c)<127 for c in envelope["url"]), "image.capability_string")
    # A one-byte validation plan checks signed URL scope without a network action.
    plan={"schema":"openclaw.private-oci-transfer-plan.v1","sourceSha":request["sourceSha"],"toolingSha":context["sha"],
        "runId":context["runId"],"attempt":"1","archiveSha256":"0"*64,"archiveBytes":1,
        "bucket":envelope["bucket"],"object":envelope["object"],"signer":envelope["signer"],"generation":None}
    try:
        _,_,deadline=transfer_validator(envelope["url"],plan,"PUT",now)
    except Exception:
        raise Refusal("image.capability_refused") from None
    need(type(before_build) is bool and type(deadline) in (int,float), "image.capability_clock")
    if before_build:
        need(deadline-now>=MIN_UPLOAD_WINDOW, "image.insufficient_upload_window_before_build")
    return deadline


def build_window(upload_deadline, now, authorization_deadline):
    need(type(upload_deadline) in (int,float) and type(now) in (int,float) and
        upload_deadline-now>=MIN_UPLOAD_WINDOW, "image.insufficient_upload_window_before_build")
    end=utc(authorization_deadline).timestamp()
    need(min(upload_deadline,end)-now>=MIN_UPLOAD_WINDOW, "image.insufficient_authorized_build_window")
    last=min(upload_deadline-RESERVE_SECONDS,end-RESERVE_SECONDS)
    minutes=min(BUILD_MINUTES,int((last-now)//60))
    need(minutes>=1,"image.build_deadline")
    return {"timeoutMinutes":minutes,"buildDeadlineEpoch":int(last),"uploadDeadlineEpoch":int(upload_deadline),
        "archiveAttestUploadReserveSeconds":RESERVE_SECONDS,"capacityGuaranteed":False}


def validate_transfer_plan(plan, request, context, archive_sha, archive_bytes):
    need(type(archive_bytes) is int and 0<archive_bytes<=MAX_ARCHIVE and pin(archive_sha), "image.archive_binding")
    expected={"schema":"openclaw.private-oci-transfer-plan.v1","sourceSha":request["sourceSha"],"toolingSha":context["sha"],
        "runId":context["runId"],"attempt":"1","archiveSha256":archive_sha,"archiveBytes":archive_bytes,
        "bucket":request["privateObject"]["bucket"],"object":request["privateObject"]["object"],
        "signer":request["privateObject"]["signer"],"generation":None}
    need(plan==expected,"image.exact_transfer_plan")
    return plan


def prepare_from_passed_source(bindings_raw, source_request_raw, generation_raw, manifest_raw, inventory_raw,
                               run, jobs, artifacts, zip_raw, *, built_at):
    """Pure constructor over captured genuine facts; it creates no authority.

    The image CI admission independently reacquires and authenticates the native
    run/jobs/artifact before a physical build. No final H is guessed here.
    """
    import source_validation_contract_v109 as source_owner
    bindings=source_owner.validate_bindings(source_owner.parse(bindings_raw))
    selected=source_owner.validate_request(source_owner.parse(source_request_raw),bindings)
    need(selected["phase"] in ("validation","correction"),"image.final_source_required")
    source_owner.validate_generation(generation_raw,bindings,selected["phase"])
    need(type(artifacts)is dict and artifacts.get("total_count")==1 and
        len(artifacts.get("artifacts",[]))==1,"image.single_source_artifact")
    a=artifacts["artifacts"][0]
    need(type(a.get("digest"))is str and a["digest"]=="sha256:"+sha(zip_raw),"image.source_artifact_digest")
    result_raw=artifact_result(zip_raw)
    source=selected["source"]
    request=disarmed_request()
    request.update(state="PREPARED_BUILD",preparationSourceSha=source_owner.preparation_for(bindings,selected["preparationAttempt"])["sourceSha"],
        previousPipelineHead=run.get("head_sha"),sourceSha=source["sourceSha"],sourceTree=source["sourceTree"],
        sourceBindingsSha256=sha(bindings_raw),sourceRequestSha256=sha(source_request_raw),generationReceiptSha256=sha(generation_raw),
        manifestSha256=sha(manifest_raw),inventorySha256=sha(inventory_raw),builtAt=built_at,
        sourceValidation={"runId":str(run.get("id")),"attempt":1,"pipelineHead":run.get("head_sha"),"phase":selected["phase"],
            "artifactId":a.get("id"),"artifactSha256":sha(zip_raw),"resultSha256":sha(result_raw)})
    request["privateObject"]["object"]=expected_object(source["sourceSha"])
    validate_request(request)
    expected={"runId":str(run.get("id")),"runAttempt":1,"pipelineHead":run.get("head_sha"),"requestSha256":sha(source_request_raw)}
    validator=lambda raw:source_owner.validate_source_result(raw,bindings,source_request_raw,expected,expected_result_sha256=sha(result_raw))
    validate_source_snapshot(request,run,jobs,artifacts,zip_raw,validator)
    return request


def arm_prepared(request, authorization, now):
    validate_request(request)
    need(request["state"]=="PREPARED_BUILD","image.prepared_source_required")
    result=deepcopy(request);result["state"]="APPROVED_BUILD";result["authorization"]=deepcopy(authorization)
    validate_request(result,active=True,now=now)
    return result

#!/usr/bin/env python3
"""One fixed, nonqualifying model diagnostic on unchanged authenticated H.

No operation on import. Only the fixed public PR workflow can enter main().
This is separate from the source execution sequence and the H2 correction.
"""
import argparse
from pathlib import Path
import re
import time

import source_validation_contract_v109 as policy

WORKFLOW = ".github/workflows/future-v109-model-diagnostic.yml"
CAMPAIGN = "future-v109-model-cleanliness-diagnostic-20261030"
REQUEST_PATH = "scripts/fork-release/candidates/v2026.10.9-model-diagnostic/request.json"
HOLD_MARKER = "<!-- openclaw-v109-model-diagnostic-only -->"
SCHEMA = "openclaw.v109.fixed-model-diagnostic-request.v1"
H = "edd010829dcb622d7dc60dc90f7097048cb78819"
H_TREE = "2e553992d3f93937dcb4b85683e4aae24a087074"
H_REQUEST = "139ef96602ea6920715a9802a829e60424e0ddc3187e1d6a8196e7e9d2470cb9"
H_SOURCE = "3c9f36ea1d45f9787cf08198a4de869e57f689311521acfe4f10295962eb0a63"
H_GENERATION = "83dfb391140b1f575cc9cdc012422125a263b58fce516b80b1852045be4f5262"
PRIOR = {"runId": "41052090949", "pipelineHead": "3722c8935ded3b3e249054fe6db2f3a50def8b8c",
    "requestSha256": H_REQUEST}
AUTHORITY = "801209d1bbbd51b5dd315f7c9367aacc4f12cf15430c23a0f46775d568ccf532"
AUTHORIZATION = "af503856db977750026d77e0e53d63ad2ec0f617254c346ca55ef2a8e110f3d8"
START, END = "2026-10-30T03:14:21Z", "2026-11-03T03:14:21Z"
MODELS = ("models-1", "models-2")
LIMITS = {"admission": 30, "diagnostic (models-1)": 60, "diagnostic (models-2)": 60, "final": 10}
UNEXPANDED = "diagnostic (${{ matrix.profile }})"
NATIVE_LIMITS = {**LIMITS, UNEXPANDED: 60}
SOURCE_WORKFLOW_RESTORED = "900d09f9d415c104147975aaa9e95eba10d97ca8e09775b2e6a84e1a5f72ded1"
SOURCE_WORKFLOW_HELD = "3f47abf66812703f36df874443865c0c54766fc0040f0517cefa0aeb22c7123c"
DIAGNOSTIC_WORKFLOW_SHA256 = "df300028082b34beb89db8199adb402d9af550cfd37f0264702e3dc3f95bc27b"
CAPTURE = "workboard-x-public-r2"
CAPTURE_MODULE = "scripts/fork-release/manifest_capture.py"
CAPTURE_SHA256 = "d5fd42317bf538720b48949a9503dc3c58df6a0035f200ac30a20400c1ed3eac"
REQUEST_FIELDS = ("schema", "status", "routingMode", "diagnosticId", "sourceSha", "sourceTree",
    "sourceRequestSha256", "sourceDescriptorSha256", "generationSha256", "priorValidation",
    "authorizationSha256", "runAllowanceSha256", "approvedAt", "expiresAt", "reviewSha256",
    "profiles", "reservations", "publicManifestCapture")


def need(value, suffix):
    policy.need(value, "v9.model_diagnostic_" + suffix)


def template():
    return {"schema": SCHEMA, "status": "DISARMED", "routingMode": "SOURCE",
        "diagnosticId": "model-cleanliness-r1", "sourceSha": H, "sourceTree": H_TREE,
        "sourceRequestSha256": H_REQUEST, "sourceDescriptorSha256": H_SOURCE,
        "generationSha256": H_GENERATION, "priorValidation": dict(PRIOR),
        "authorizationSha256": AUTHORIZATION, "runAllowanceSha256": AUTHORITY,
        "approvedAt": START, "expiresAt": END, "reviewSha256": None, "profiles": list(MODELS),
        "reservations": {"current": 160, "pendingCorrection": 1075, "conditionalImage": 180, "incidental": 50},
        "publicManifestCapture": CAPTURE}


def validate(value, source_raw=None, active=False, now=None):
    policy.fields(value, REQUEST_FIELDS, "v9.model_diagnostic_request_fields")
    expected = template()
    variable = {"status", "routingMode", "reviewSha256", "reservations"}
    need(all(value[k] == expected[k] for k in expected if k not in variable), "fixed_request")
    need(value["status"] in ("DISARMED", "REVIEWED") and value["routingMode"] in ("SOURCE", "DIAGNOSTIC"), "routing")
    if value["status"] == "DISARMED":
        need(value["reviewSha256"] is None and value["routingMode"] == "SOURCE", "disarmed")
    else:
        need(policy.pin(value["reviewSha256"]) and value["reviewSha256"] != "0" * 64 and
            value["routingMode"] == "DIAGNOSTIC", "review")
    r = value["reservations"]
    policy.fields(r, ("current", "pendingCorrection", "conditionalImage", "incidental"), "v9.model_diagnostic_reservations")
    need(all(type(r[k]) is int for k in r) and r["current"] == 160 and r["pendingCorrection"] == 1075 and
        r["conditionalImage"] == 180 and 0 <= r["incidental"] <= 50, "reservations")
    if source_raw is not None:
        source = policy.parse(source_raw)
        need(policy.digest(source_raw) == H_REQUEST and source["phase"] == "validation" and
            source["source"]["sourceSha"] == H and source["source"]["sourceTree"] == H_TREE and
            policy.digest(policy.canonical(source["source"])) == H_SOURCE and
            policy.digest(policy.canonical(source["generation"])) == H_GENERATION, "unchanged_H")
    if active:
        need(value["status"] == "REVIEWED" and value["routingMode"] == "DIAGNOSTIC" and
            type(now) in (int, float) and policy.utc(START).timestamp() <= now < policy.utc(END).timestamp(), "active")
    return value


def at_head(runtime, api, head):
    raw = runtime.content(api, REQUEST_PATH, head, 16384)
    value = policy.parse(raw)
    # A later full-source H2 publication restores SOURCE/DISARMED routing. Its
    # source request is independently validated by the normal source owner;
    # this inactive diagnostic still identifies its original H, not H2.
    source_raw = (runtime.content(api, runtime.REQUEST, head, 65536)
        if value.get("routingMode") == "DIAGNOSTIC" else None)
    return validate(value, source_raw), raw


def diagnostic_heads(history):
    return {run["head_sha"] for run in history.values() if run.get("path") == WORKFLOW}


def native_role(runtime, run, value):
    need(runtime.public_run(run) and run.get("event") == "pull_request" and
        run.get("head_branch") == policy.PIPELINE_BRANCH and run.get("path") == WORKFLOW and
        run.get("name") == run.get("display_title") == CAMPAIGN, "native_role")
    return NATIVE_LIMITS


def zero_runner_jobs(jobs, names):
    need(type(jobs) is list and len(jobs) == len(names) and {j.get("name") for j in jobs} == set(names), "hold_shape")
    for job in jobs:
        need(all(k in job for k in ("status", "conclusion", "runner_id", "runner_name", "runner_group_name", "steps")) and
            job["status"] == "completed" and job["conclusion"] == "skipped" and
            (job["runner_id"] is None or type(job["runner_id"]) is int and job["runner_id"] == 0) and
            job.get("runner_name") in (None, "") and
            job.get("runner_group_name") in (None, "") and job.get("steps") == [], "positive_zero_runner_hold")


def validate_record(runtime, run, value, jobs, artifacts, current_id):
    if run.get("path") == WORKFLOW:
        native_role(runtime, run, value)
        if value["routingMode"] == "SOURCE":
            zero_runner_jobs(jobs, ("admission", UNEXPANDED, "final"))
            need(artifacts == [], "held_artifacts")
        else:
            need(run.get("status") == "completed" or str(run["id"]) == current_id, "diagnostic_overlap")
            if run.get("status") == "completed":
                expanded = any(j.get("name") == "admission" and j.get("conclusion") == "success" for j in jobs)
                need({j.get("name") for j in jobs} == (set(LIMITS) if expanded else
                    {"admission", UNEXPANDED, "final"}), "job_shape")
    else:
        need(run.get("path") == policy.WORKFLOW and run.get("name") == run.get("display_title") == policy.CAMPAIGN and
            runtime.public_run(run) and run.get("event") == "pull_request" and
            run.get("head_branch") == policy.PIPELINE_BRANCH and value["routingMode"] == "DIAGNOSTIC", "held_source_role")
        zero_runner_jobs(jobs, ("admission", "source (${{ matrix.profile }})", "final"))
        need(artifacts == [], "held_artifacts")


def predecessor(source_rows, value):
    rows = [row for row in source_rows if row[0] == PRIOR["runId"]]
    need(len(rows) == 1, "prior_missing")
    rid, run, request, raw = rows[0]
    need(run.get("status") == "completed" and run.get("conclusion") == "failure" and
        run.get("head_sha") == PRIOR["pipelineHead"] and policy.digest(raw) == H_REQUEST and
        request["phase"] == "validation" and request["source"]["sourceSha"] == H and
        request["source"]["sourceTree"] == H_TREE, "actual_failed_H_predecessor")
    need(all(run.get("status") == "completed" for _, run, _, _ in source_rows), "source_overlap")
    return rid


def once_current(rows, current_id):
    selected = [rid for rid, run, value in rows if run.get("path") == WORKFLOW and
        value["routingMode"] == "DIAGNOSTIC"]
    need(selected == [current_id], "single_reviewed_diagnostic")


def budget(runtime, grant, run_minutes, current_id, current_minutes, value):
    from bounded_run_contract_v109 import PREFIX_RUN_IDS, PREFIX_MINUTES, validate_budget
    need(all((rid, 1) in run_minutes for rid in PREFIX_RUN_IDS), "prefix_minutes")
    prefix = sum(run_minutes[(rid, 1)] for rid in PREFIX_RUN_IDS)
    need(prefix >= PREFIX_MINUTES == 38, "prefix_minute_floor")
    charges = dict(run_minutes)
    for row in grant["bookedAdditionalAttempts"]:
        key = (row["runId"], row["nativeAttempt"])
        need(key in charges and key != (current_id, 1), "booked_prior_identity")
        charges[key] = max(charges[key], row["runnerMinutes"])
    need(run_minutes.get((current_id, 1)) == current_minutes, "current_minutes")
    facts = validate_budget(grant, {"reservations": value["reservations"]}, sum(charges.values()), current_minutes)
    facts.update({"diagnosticOnly": True, "sourceExecutionAdvanced": False, "futureFull15Reserved": 1075,
        "prefixMinutesObserved": prefix})
    return sum(charges.values()), facts


def route_event(event, diagnostic):
    present = HOLD_MARKER in (event.get("pull_request", {}).get("body") or "")
    need(present is diagnostic, "mutual_workflow_hold")


def workflow_routing(runtime, pipeline, diagnostic):
    value = validate(policy.parse(runtime.regular(pipeline / REQUEST_PATH, 16384)))
    need((value["routingMode"] == "DIAGNOSTIC") is diagnostic, "request_workflow_route")
    need(policy.digest(runtime.regular(pipeline / policy.WORKFLOW, 32768)) ==
        (SOURCE_WORKFLOW_HELD if diagnostic else SOURCE_WORKFLOW_RESTORED), "exact_full_source_hold_or_restore")
    need(policy.digest(runtime.regular(pipeline / WORKFLOW, 32768)) == DIAGNOSTIC_WORKFLOW_SHA256,
        "exact_diagnostic_workflow")


def manifest_capture(source, value):
    """There is no request-chosen module/path or generic raw upload option."""
    need(value["publicManifestCapture"] == CAPTURE, "manifest_capture_not_bound")
    return {"status": "fixed_public_validator_bound", "moduleSha256": CAPTURE_SHA256,
        "rawRootUploadAllowed": False}


def capture_before(runtime, pipeline, source, env, context, value, profile, source_request):
    manifest_capture(source, value)
    need(profile in MODELS and time.time() < context["deadlineEpoch"], "capture_deadline")
    module = runtime.load_owner(pipeline, "model_diagnostic_public_manifest_capture", CAPTURE_MODULE, CAPTURE_SHA256)
    output = Path(env["RUNNER_TEMP"]) / ("v109-model-manifest-capture-" + profile)
    # Bind actual clean H before the private snapshot. The next maintained
    # static/preflight path still runs before candidate commands.
    runtime.source_binding(source, source_request, context["deadlineEpoch"])
    try:
        module.capture_before(source, output)
        return module, output, True
    except Exception:
        runtime.emit({"schema": "openclaw.v109.model-manifest-capture.v1", "status": "before_unavailable",
            "profile": profile, "portablePayloadAuthorized": False, "rawPrivateCustodyClaimed": False})
        return module, output, False


def capture_after(runtime, source, source_request, env, context, profile, capture):
    from source_profile_diagnostic_v109 import report
    module, output, ready = capture
    try:
        need(time.time() < context["deadlineEpoch"], "capture_deadline")
        read = lambda *args: runtime.git_read(source, *args, deadline=context["deadlineEpoch"])
        observations = {"head": read("rev-parse", "HEAD"), "tree": read("rev-parse", "HEAD^{tree}"),
            "status": read("status", "--porcelain=v1", "--untracked-files=no")}
        metadata = report(source, source_request, observations, read,
            {"runId": env["GITHUB_RUN_ID"], "runAttempt": 1, "profile": profile}, context["deadlineEpoch"])
        runtime.emit(metadata)
        # These are capture eligibility checks, NEVER a source dirty allowlist.
        # The original source gate's refusal is preserved by the caller.
        rows = metadata["paths"]
        eligible = (ready and metadata["checks"]["head"]["matches"] is True and
            metadata["checks"]["tree"]["matches"] is True and metadata["checks"]["trackedStatus"]["clean"] is False and
            metadata["unknownPathCount"] == metadata["omittedKnownPaths"] == 0 and metadata["issueCodes"] == [] and
            1 <= len(rows) <= 2 and all(row["path"] in module.PLUGIN_PATHS.values() and row["statusCode"] == " M" and
                row["before"]["availability"] == "hashed" and row["before"]["mode"] == "100644" and
                row["index"] == [{"gitOid": row["before"]["gitOid"], "mode": "100644", "stage": 0}] and
                row["after"]["availability"] == "hashed" and row["after"]["mode"] == "100644" for row in rows))
        need(eligible, "capture_not_fixed_worktree_manifests")
        module.capture_after(source, output, [row["path"] for row in rows])
        receipt = module.adjudicate(output)
        hashes = receipt.get("controlUiSha256")
        need(receipt.get("schema") == "openclaw.plugin-manifest-capture.v1" and receipt.get("sourceH") == H and
            receipt.get("qualified") is False and receipt.get("assetContentAuthenticated") is False and
            type(hashes) is dict and set(hashes) == {"workboard", "x"} and
            all(policy.pin(v) for v in hashes.values()), "capture_receipt")
        # Publish ONLY after adjudicate has successfully written ALL five
        # accepted files. A failed/partial directory never enables the upload.
        runtime.emit({"schema": "openclaw.v109.model-manifest-capture.v1", "status": "validated_public_payload",
            "profile": profile, "sourceH": H, "receiptSha256": policy.digest(policy.canonical(receipt)),
            "controlUiSha256": receipt["controlUiSha256"], "portablePayloadAuthorized": True,
            "assetContentAuthenticated": False, "producerObservedCheck": "not_collected",
            "qualified": False, "sourceExecutionAdvanced": False})
        runtime.write_outputs(env, {"public_payload": "true"})
    except Exception:
        runtime.emit({"schema": "openclaw.v109.model-manifest-capture.v1", "status": "metadata_only",
            "profile": profile, "portablePayloadAuthorized": False, "rawPrivateCustodyClaimed": False,
            "qualified": False, "sourceExecutionAdvanced": False})


def context_for(runtime, bindings, source_request, env, profile=None):
    # Reuse the existing environment/resource context; override ONLY this fixed
    # role's clock, not an application/source phase or execution sequence.
    context = runtime.prepare_context(Path(env["GITHUB_WORKSPACE"]) / "pipeline", source_request, bindings, env,
        profile if profile in MODELS else None)
    start = env.get(runtime.CLOCK)
    need(type(start) is str and start.isdigit(), "job_clock")
    minutes = 60 if profile in MODELS else 10 if profile == "final" else 30
    context["deadlineEpoch"] = min(int(start) + minutes * 60 - 60, policy.utc(END).timestamp() - 60)
    need(time.time() < context["deadlineEpoch"], "job_deadline")
    context["profile"] = profile or "diagnostic-admission"
    return context


def run_model(runtime, pipeline, source, bindings, source_request, profile, env, core, context, value):
    capture = capture_before(runtime, pipeline, source, env, context, value, profile, source_request)
    try:
        runtime.run_profile(pipeline, source, bindings, source_request, profile, env, core, context)
    except Exception as error:
        # Custody/adjudication after failure cannot accept a source profile.
        # Always re-raise the ORIGINAL error after bounded safe collection.
        if runtime.safe_refusal_code(error) != "v9.profile_changed_tracked_source":
            try:
                runtime.post_profile_binding(source, source_request, context["deadlineEpoch"],
                    {"runId": env["GITHUB_RUN_ID"], "runAttempt": 1, "profile": profile})
            except Exception:
                pass
        try:
            capture_after(runtime, source, source_request, env, context, profile, capture)
        except Exception:
            pass
        raise
    capture_after(runtime, source, source_request, env, context, profile, capture)
    runtime.emit({"schema": "openclaw.v109.model-diagnostic-observation.v1", "status": "clean_at_check",
        "profile": profile, "sourceSha": H, "qualified": False, "sourceExecutionAdvanced": False})
    return 0


def main(argv=None, environment=None):
    import os
    import source_validation_v109 as runtime
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("admit", "fetch-closure", "run", "finalize"))
    parser.add_argument("--profile", choices=MODELS)
    args = parser.parse_args(argv)
    env = dict(os.environ if environment is None else environment)
    pipeline = Path(env["GITHUB_WORKSPACE"]) / "pipeline"
    source = Path(env["GITHUB_WORKSPACE"]) / "source"
    bindings, source_request, source_raw = runtime.load_metadata(pipeline, active=True, now=time.time())
    value_raw = runtime.regular(pipeline / REQUEST_PATH, 16384)
    value = validate(policy.parse(value_raw), source_raw, active=True, now=time.time())
    need(policy.digest(policy.canonical(bindings["authorization"])) == AUTHORIZATION and
        policy.run_grant(bindings)["authoritySha256"] == AUTHORITY and bindings["correction"] is None, "original_authority")
    need(env.get("V109_APPROVED_AT") == START and env.get("V109_EXPIRES_AT") == END, "workflow_clock")
    event = policy.parse(runtime.regular(Path(env["GITHUB_EVENT_PATH"]), 1024 * 1024))
    head = runtime.event_binding(event, env, diagnostic=True)
    core = runtime.load_owner(pipeline, "model_diagnostic_shared_owner", runtime.CORE, runtime.CORE_HASH)
    context = context_for(runtime, bindings, source_request, env, args.profile if args.command in ("run", "fetch-closure") else
        "final" if args.command == "finalize" else None)
    context["modelDiagnosticRequest"] = value
    core.profile_signals()
    runtime.code_binding(pipeline, None, event, env, source_request, core, context)
    if args.command == "admit":
        api = runtime.API(env.get("GH_TOKEN"), context["deadlineEpoch"])
        runtime.live_identity(api, head, source_request, event)
        live = api("/repos/" + policy.REPOSITORY + "/pulls/28")
        route_event({"pull_request": live}, True)
        resolver = runtime.load_owner(pipeline, "model_diagnostic_closed_usage", "scripts/fork-release/composite_closed_usage_v109.py")
        facts = runtime.history_checks(pipeline, bindings, source_request, source_raw, head, event, env, api,
            resolver, time.time(), diagnostic=value)
        runtime.validate_generation_provider(pipeline, bindings, source_request, api)
        api.cache.clear()
        runtime.live_identity(api, head, source_request, event)
        route_event({"pull_request": api("/repos/" + policy.REPOSITORY + "/pulls/28")}, True)
        runtime.write_outputs(env, {"source_sha": H, "request_sha": H_REQUEST, "pipeline_head": head,
            "run_id": env["GITHUB_RUN_ID"], "diagnostic_request_sha": policy.digest(value_raw)})
        runtime.emit({"schema": "openclaw.v109.model-diagnostic-admission.v1", "status": "admitted_diagnostic_only",
            **facts, "qualified": False, "sourceExecutionAdvanced": False, "productionAuthorized": False})
        return 0
    if args.command == "finalize":
        result = {"schema": "openclaw.v109.model-diagnostic-result.v1", "status": "diagnostic_only",
            "runId": env["GITHUB_RUN_ID"], "runAttempt": 1, "pipelineHead": head, "sourceSha": H, "sourceTree": H_TREE,
            "diagnosticRequestSha256": policy.digest(value_raw), "admissionResult": env.get("V109_DIAGNOSTIC_ADMISSION_RESULT"),
            "modelMatrixResult": env.get("V109_DIAGNOSTIC_MODELS_RESULT"),
            "qualified": False, "freshCoverage": False, "sourceExecutionAdvanced": False,
            "applicationCorrectionConsumed": False, "imageBuilt": False, "productionAuthorized": False}
        need(all(result[k] in ("success", "failure", "cancelled", "skipped") for k in
            ("admissionResult", "modelMatrixResult")), "final_results")
        raw = policy.encode(result)
        need(len(raw) <= 16384, "final_result_cap")
        runtime.private_write(Path(env["RUNNER_TEMP"]) / "v109-model-diagnostic" / "diagnostic-result.json", raw)
        runtime.emit(result)
        return 0
    runtime.check_admission_outputs(env, source_request, source_raw, head)
    need(env.get("V109_DIAGNOSTIC_REQUEST_SHA256") == policy.digest(value_raw) and args.profile in MODELS,
        "same_diagnostic_admission")
    if args.command == "fetch-closure":
        runtime.fetch_closure(pipeline, source, bindings, source_request, event, env, core, context)
        return 0
    return run_model(runtime, pipeline, source, bindings, source_request, args.profile, env, core, context, value)


if __name__ == "__main__":
    import source_validation_v109 as runtime
    try:
        raise SystemExit(main())
    except Exception as error:
        runtime.emit({"schema": "openclaw.v109.model-diagnostic-refusal.v1", "status": "refused",
            "code": runtime.safe_refusal_code(error), "qualified": False, "sourceExecutionAdvanced": False,
            "imageBuilt": False, "productionAuthorized": False})
        raise SystemExit(1)

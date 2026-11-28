"""Pure historical usage composition for the future 10.9 caller.

The existing owner resolves the213+30 records unchanged. This owner appends
only the pinned public 15-record projection; it grants no new execution,
publication or spending authority and performs no I/O, clock or transport.
Callers still verify live provider headers, job timing and current admission.
"""
import hashlib
import json

from composite_closed_usage import resolve_composite

REPOSITORY = "fr-meyer/openclaw"
HISTORICAL_CAMPAIGN = "future-v108-source-validation-20261027"
SCHEMA = "openclaw.v109.closed-baseline-reference.v1"
RESOLVED_SCHEMA = "openclaw.v109.closed-historical-usage-resolved.v1"
STAGE_SCHEMA = "openclaw.v109.closed-v108-provider-stage.v1"
CLOSED_AT = "2026-10-29T18:26:15.518985+00:00"
PROOF243_SHA256 = "2188800522988ac5837c554db7d4be01186f1031a86bd782deab839765919fd8"
RESOLVED243_SHA256 = "de4bede2d3c1bece03aa7093097c1fd89f9f8014f307507583a7a953dfeea9c3"
STAGE15_SHA256 = "47b8aabed22262aaf8f4cc3d1cc34f6567ac2b2406d905a4867668f264532791"
STAGE15_BYTES = 183880
PROOF_SHA256 = 'dfc2cda1a2c7c5f3f4e1bc235e8a6e2aca615e62c5ce20a79102a794779770df'
RESOLVED_SHA256 = 'e811ce042eaf2b5b111f785ed5c5aecfab079f19b1a35116a5d23aa216dfff87'
PIPELINE_HEAD = "37400d942839bee0b92852037d6f8bf99e60358c"
SOURCE_HEAD = "e6c4786dafbc8308661ea8fa14a81e06873d1630"
WORKFLOW = ".github/workflows/future-v108-source-validation.yml"
SOURCE_IDS = ["40616416909", "40609889437", "40607329263", "40639374411", "40647629182",
              "40681376480", "40688279536", "40706982753", "40804517284", "40808362032",
              "40816927196", "40851844749", "40856125444", "40901336241"]
PROFILE_NAMES = ("dependency", "types-production", "types-tests", "types-scripts", "workboard-1",
                 "workboard-2", "models-1", "models-2", "sqlite", "doctor-1", "doctor-2",
                 "doctor-3", "memory", "pipeline-contracts", "compatibility")
HEADERS = {"id", "name", "path", "event", "head_branch", "head_sha", "run_attempt", "status",
           "conclusion", "created_at", "updated_at", "html_url"}
TERMINAL = {"success", "failure", "neutral", "cancelled", "skipped", "timed_out", "action_required",
            "stale", "startup_failure"}
STAGE_SUMMARY = {
    "schema": STAGE_SCHEMA, "repository": REPOSITORY, "historicalCampaignId": HISTORICAL_CAMPAIGN,
    "closedAt": CLOSED_AT, "runCount": 15, "runnerMinutesObserved": 507,
    "incidentalMinutesObserved": 11, "sourceRunIds": ["40901336241"],
    "artifactSnapshot": {"count": 1, "bytes": 622},
    "closedSourceExecutions": [{"runId": 40901336241, "pipelineHead": PIPELINE_HEAD,
        "sourceHead": SOURCE_HEAD, "terminal": True, "conclusion": "success"}],
}
SEGMENTS = [
    {"kind": "existing-243-reference", "sha256": PROOF243_SHA256, "bytes": 1288,
     "resolvedSha256": RESOLVED243_SHA256, "runCount": 243, "runnerMinutesObserved": 2437},
    {"kind": "public-15-provider-projection", "sha256": STAGE15_SHA256,
     "bytes": STAGE15_BYTES, "runCount": 15, "runnerMinutesObserved": 507},
]


def need(condition, code):
    if not condition:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def decode(raw, maximum):
    need(type(raw) is bytes and 0 < len(raw) <= maximum, "baseline258.bounded_bytes")
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, "baseline258.duplicate_json_key")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: need(False, "baseline258.nonfinite_json"))


def _derive(previous, stage):
    """Internal semantic check, also exercised with focused tamper fixtures."""
    need(type(previous) is dict and previous.get("schema") ==
        "openclaw.v108.closed-usage-reference-resolved.v1" and previous.get("repository") == REPOSITORY and
        previous.get("campaignId") == HISTORICAL_CAMPAIGN and type(previous.get("runCount")) is int and
        previous["runCount"] == 243 and type(previous.get("runnerMinutesObserved")) is int and
        previous["runnerMinutesObserved"] == 2437 and previous.get("sourceRunIds") == SOURCE_IDS[:-1] and
        previous.get("artifactSnapshot") == {"count": 22, "bytes": 387192} and
        type(previous.get("runs")) is list and len(previous["runs"]) == 243,
        "baseline258.previous243_identity")
    need(type(stage) is dict and set(stage) == set(STAGE_SUMMARY) | {"records"} and
        canonical({k: v for k, v in stage.items() if k != "records"}) == canonical(STAGE_SUMMARY) and
        type(stage.get("records")) is list and len(stage["records"]) == 15,
        "baseline258.closed15_summary")
    appended = []
    for record in stage["records"]:
        need(type(record) is dict and set(record) == {"run", "jobs", "artifacts", "observedMinutes",
            "actorLogin", "triggeringActorLogin"} and type(record["run"]) is dict and
            set(record["run"]) == HEADERS and record["actorLogin"] == record["triggeringActorLogin"] ==
            "fr-meyer" and type(record["jobs"]) is list and type(record["artifacts"]) is list and
            type(record["observedMinutes"]) is int and record["observedMinutes"] >= 0,
            "baseline258.public_provider_record")
        header = record["run"]
        need(header["head_sha"] == PIPELINE_HEAD and header["head_branch"] == "task/v107-source-binding" and
            header["event"] in {"pull_request", "pull_request_target"} and
            header["html_url"] == "https://github.com/fr-meyer/openclaw/actions/runs/" + str(header["id"]),
            "baseline258.public_provider_header")
        appended.append({**header, "jobs": record["jobs"],
            "observedRunnerMinutes": record["observedMinutes"], "artifactRows": record["artifacts"],
            "actorLogin": record["actorLogin"], "triggeringActorLogin": record["triggeringActorLogin"]})
    ids, job_ids, artifact_ids, source_ids = set(), set(), set(), set()
    total = 0
    for run in previous["runs"] + appended:
        need(type(run) is dict and type(run.get("id")) is int and run["id"] > 0 and run["id"] not in ids and
            type(run.get("run_attempt")) is int and run["run_attempt"] == 1 and run.get("status") == "completed" and
            run.get("conclusion") in TERMINAL and type(run.get("observedRunnerMinutes")) is int and
            run["observedRunnerMinutes"] >= 0 and type(run.get("jobs")) is list,
            "baseline258.unique_terminal_run")
        ids.add(run["id"])
        total += run["observedRunnerMinutes"]
        for job in run["jobs"]:
            need(type(job) is dict and type(job.get("id")) is int and job["id"] > 0 and
                job["id"] not in job_ids and job.get("status") == "completed" and
                job.get("conclusion") in TERMINAL, "baseline258.unique_terminal_job")
            job_ids.add(job["id"])
        for artifact in run.get("artifactRows", []):
            need(type(artifact) is dict and type(artifact.get("id")) is int and artifact["id"] > 0 and
                artifact["id"] not in artifact_ids and type(artifact.get("size_in_bytes")) is int and
                artifact["size_in_bytes"] >= 0 and type(artifact.get("expired")) is bool,
                "baseline258.unique_artifact")
            artifact_ids.add(artifact["id"])
        if run.get("path") == WORKFLOW:
            source_ids.add(str(run["id"]))
    main = [r for r in appended if r["id"] == 40901336241]
    need(len(main) == 1 and main[0]["path"] == WORKFLOW and main[0]["name"] == HISTORICAL_CAMPAIGN and
        main[0]["event"] == "pull_request" and main[0]["conclusion"] == "success" and
        main[0]["observedRunnerMinutes"] == 496 and len(main[0]["jobs"]) == 17 and
        {j.get("name") for j in main[0]["jobs"]} == {"admission", "final", *["source (" + p + ")" for p in PROFILE_NAMES]} and
        all(j.get("conclusion") == "success" for j in main[0]["jobs"]),
        "baseline258.closed_main_role")
    need(len(ids) == 258 and total == 2944 and source_ids == set(SOURCE_IDS) and
        sum(r["observedRunnerMinutes"] for r in appended) == 507 and
        sum(r["observedRunnerMinutes"] for r in appended if r["id"] != 40901336241) == 11,
        "baseline258.measured_totals")
    artifacts = [a for r in appended for a in r["artifactRows"]]
    need(len(artifacts) == 1 and sum(a["size_in_bytes"] for a in artifacts) == 622,
        "baseline258.appended_artifact_snapshot")
    return {"schema": RESOLVED_SCHEMA, "repository": REPOSITORY,
        "historicalCampaignId": HISTORICAL_CAMPAIGN, "closedAt": CLOSED_AT,
        "runCount": 258, "runnerMinutesObserved": 2944, "sourceRunIds": list(SOURCE_IDS),
        "artifactSnapshot": {"count": 23, "bytes": 387814},
        "currentArtifactSnapshot": {"count": 23, "bytes": 387814},
        "referenceComposition": {"segments": [dict(s) for s in SEGMENTS], "oldUnusedAuthorityCarried": False},
        "previous243CompositionPreserved": True, "closedProviderStage15": dict(STAGE_SUMMARY),
        "historicalCoverageTransferred": False, "executionAuthorized": False,
        "runs": previous["runs"] + appended}


def resolve_baseline_258(proof_raw, proof243_raw, original213_raw, stage30_raw, stage15_raw):
    """Resolve fixed immutable inputs; never infer authority from historical usage."""
    proof = decode(proof_raw, 16384)
    need(len(proof_raw) == 1354 and digest(proof_raw) == PROOF_SHA256 and
        type(proof) is dict and set(proof) == {"schema", "repository", "historicalCampaignId", "closedAt",
            "segments", "runCount", "runnerMinutesObserved", "sourceRunIds", "artifactSnapshot",
            "oldUnusedAuthorityCarried", "historicalCoverageTransferred", "resolvedCanonicalSha256"} and
        proof["schema"] == SCHEMA and proof["repository"] == REPOSITORY and
        proof["historicalCampaignId"] == HISTORICAL_CAMPAIGN and proof["closedAt"] == CLOSED_AT and
        canonical(proof["segments"]) == canonical(SEGMENTS) and type(proof["runCount"]) is int and
        proof["runCount"] == 258 and type(proof["runnerMinutesObserved"]) is int and
        proof["runnerMinutesObserved"] == 2944 and proof["sourceRunIds"] == SOURCE_IDS and
        proof["artifactSnapshot"] == {"count": 23, "bytes": 387814} and
        proof["oldUnusedAuthorityCarried"] is False and proof["historicalCoverageTransferred"] is False and
        proof["resolvedCanonicalSha256"] == RESOLVED_SHA256, "baseline258.closed_proof")
    need(type(proof243_raw) is bytes and len(proof243_raw) == 1288 and digest(proof243_raw) == PROOF243_SHA256 and
        type(stage15_raw) is bytes and len(stage15_raw) == STAGE15_BYTES and digest(stage15_raw) == STAGE15_SHA256,
        "baseline258.exact_segment_bytes")
    previous = resolve_composite(proof243_raw, original213_raw, stage30_raw)
    need(digest(canonical(previous)) == RESOLVED243_SHA256, "baseline258.existing_owner_result")
    stage = decode(stage15_raw, 2 * 1024 * 1024)
    resolved = _derive(previous, stage)
    need(digest(canonical(resolved)) == RESOLVED_SHA256, "baseline258.resolved_canonical_pin")
    return resolved

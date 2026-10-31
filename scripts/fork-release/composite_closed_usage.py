"""Pure fixed-segment closed-usage composition. No I/O, clock, transport or execution."""
import hashlib
import json

SCHEMA = "openclaw.v108.closed-usage-reference-composition.v1"
RESOLVED_SCHEMA = "openclaw.v108.closed-usage-reference-resolved.v1"
REPOSITORY = "fr-meyer/openclaw"
CAMPAIGN = "future-v108-source-validation-20261027"
CLOSED_AT = "2026-10-29T14:09:37.976704+00:00"
PREFIX_SHA = "c2438e2b10555f396f662c6fb8e142bafd61f7b32b172fd8a5cb982ccac567ec"
STAGE_SHA = "0fe119c063939a29bb2b40b4af06bb0313532aef1133e07bf4ef11645a199619"
SEGMENTS = [
    {"kind": "closed-213-prefix", "sha256": PREFIX_SHA, "bytes": 1376744,
     "runCount": 213, "runnerMinutesObserved": 1798},
    {"kind": "closed-30-provider-projection", "sha256": STAGE_SHA, "bytes": 296173,
     "originSha256": "b9b25f829010edac35df36a143043ae1ab0581bed8ba5de50b9f2517c8e9dcc7",
     "runCount": 30, "runnerMinutesObserved": 639},
]
SOURCE_IDS = ["40616416909", "40609889437", "40607329263", "40639374411", "40647629182",
              "40681376480", "40688279536", "40706982753", "40804517284", "40808362032",
              "40816927196", "40851844749", "40856125444"]
ARTIFACT_SNAPSHOT = {"count": 22, "bytes": 387192}
WORKFLOW = ".github/workflows/future-v108-source-validation.yml"
TERMINAL = {"success", "failure", "neutral", "cancelled", "skipped", "timed_out", "action_required", "stale", "startup_failure"}


def need(ok, code):
    if not ok:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def decode(raw, maximum):
    need(type(raw) is bytes and 0 < len(raw) <= maximum, "composite.bounded_bytes")
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, "composite.duplicate_key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, "composite.nonfinite_json"))


def _derive(prefix, stage):
    need(prefix.get("schema") == "openclaw.v108.closed-source-usage.v5" and
         prefix.get("repository") == REPOSITORY and prefix.get("campaignId") == CAMPAIGN and
         prefix.get("runCount") == 213 and prefix.get("runnerMinutesObserved") == 1798 and
         prefix.get("sourceRunIds") == SOURCE_IDS[:11] and type(prefix.get("runs")) is list and
         len(prefix["runs"]) == 213 and prefix.get("currentArtifactSnapshot") == {"count": 19, "bytes": 198278},
         "composite.original_prefix")
    need(type(stage) is dict and set(stage) == {"schema", "repository", "campaignId", "closedAt", "runCount",
         "runnerMinutesObserved", "incidentalMinutesObserved", "sourceRunIds", "artifactSnapshot",
         "closedSourceExecutions", "records"} and stage["schema"] == "openclaw.v108.closed-provider-stage-usage.v1" and
         stage["repository"] == REPOSITORY and stage["campaignId"] == CAMPAIGN and stage["closedAt"] == CLOSED_AT and
         stage["runCount"] == 30 and stage["runnerMinutesObserved"] == 639 and
         stage["incidentalMinutesObserved"] == 19 and stage["artifactSnapshot"] == {"count": 3, "bytes": 188914} and
         stage["sourceRunIds"] == SOURCE_IDS[-2:] and
         type(stage.get("records")) is list and len(stage["records"]) == 30 and
         [s.get("runId") for s in stage.get("closedSourceExecutions", [])] == [40851844749, 40856125444] and
         all(s.get("terminal") is True for s in stage["closedSourceExecutions"]), "composite.closed_stage")
    appended = []
    for row in stage["records"]:
        need(type(row) is dict and set(row) == {"run", "jobs", "artifacts", "observedMinutes", "actorLogin", "triggeringActorLogin"} and
             type(row["run"]) is dict and row["actorLogin"] == row["triggeringActorLogin"] == "fr-meyer" and
             type(row["artifacts"]) is list, "composite.stage_record")
        appended.append({**row["run"], "jobs": row["jobs"], "observedRunnerMinutes": row["observedMinutes"],
                         "artifactRows": row["artifacts"], "actorLogin": row["actorLogin"],
                         "triggeringActorLogin": row["triggeringActorLogin"]})
    runs = prefix["runs"] + appended
    ids, source_ids, total = set(), set(), 0
    for row in runs:
        need(type(row) is dict and type(row.get("id")) is int and row["id"] > 0 and row["id"] not in ids and
             type(row.get("run_attempt")) is int and row["run_attempt"] == 1 and row.get("status") == "completed" and
             row.get("conclusion") in TERMINAL and type(row.get("jobs")) is list and
             type(row.get("observedRunnerMinutes")) is int and row["observedRunnerMinutes"] >= 0,
             "composite.unique_terminal_run")
        ids.add(row["id"]); total += row["observedRunnerMinutes"]
        job_ids = set()
        for job in row["jobs"]:
            need(type(job) is dict and type(job.get("id")) is int and job["id"] > 0 and job["id"] not in job_ids and
                 job.get("status") == "completed" and job.get("conclusion") in TERMINAL,
                 "composite.positive_terminal_job")
            job_ids.add(job["id"])
        if row.get("path") == WORKFLOW:
            source_ids.add(str(row["id"]))
    need(len(ids) == 243 and total == 2437 and source_ids == set(SOURCE_IDS) and
         sum(r["observedRunnerMinutes"] for r in prefix["runs"]) == 1798 and
         sum(r["observedRunnerMinutes"] for r in appended) == 639, "composite.measured_totals")
    need(sum(len(r["artifacts"]) for r in stage["records"]) == 3 and
         sum(a["size_in_bytes"] for r in stage["records"] for a in r["artifacts"]) == 188914,
         "composite.appended_artifact_snapshot")
    return {"schema": RESOLVED_SCHEMA, "repository": REPOSITORY, "campaignId": CAMPAIGN, "closedAt": CLOSED_AT,
            "runCount": 243, "runnerMinutesObserved": 2437, "sourceRunIds": list(SOURCE_IDS),
            "artifactSnapshot": dict(ARTIFACT_SNAPSHOT),
            "currentArtifactSnapshot": dict(ARTIFACT_SNAPSHOT),
            "referenceComposition": {"segments": [dict(s) for s in SEGMENTS], "oldUnusedAuthorityCarried": False},
            "closedProviderStage": {k: v for k, v in stage.items() if k != "records"}, "runs": runs}


def resolve_composite(proof_raw, original213_raw, stage30_raw):
    """Resolve only the two reviewed immutable segments; callers own fixed byte retrieval.

    The third input is the public provider projection, never the private stage ledger.
    Historical stored minutes and complete original rows are preserved. The existing
    provider-history measurement owners must still verify fresh headers and job timing;
    this reference composition makes no fresh provider observation or qualification.
    """
    proof = decode(proof_raw, 16384)
    need(type(proof) is dict and set(proof) == {"schema", "repository", "campaignId", "closedAt", "segments", "runCount",
         "runnerMinutesObserved", "sourceRunIds", "artifactSnapshot", "oldUnusedAuthorityCarried", "resolvedCanonicalSha256"} and
         proof["schema"] == SCHEMA and proof["repository"] == REPOSITORY and proof["campaignId"] == CAMPAIGN and
         proof["closedAt"] == CLOSED_AT and
         canonical(proof["segments"]) == canonical(SEGMENTS) and type(proof["runCount"]) is int and proof["runCount"] == 243 and
         type(proof["runnerMinutesObserved"]) is int and proof["runnerMinutesObserved"] == 2437 and
         proof["sourceRunIds"] == SOURCE_IDS and canonical(proof["artifactSnapshot"]) == canonical(ARTIFACT_SNAPSHOT) and
         proof["oldUnusedAuthorityCarried"] is False, "composite.closed_proof")
    prefix = decode(original213_raw, 2 * 1024 * 1024)
    stage = decode(stage30_raw, 2 * 1024 * 1024)
    need(len(original213_raw) == SEGMENTS[0]["bytes"] and digest(original213_raw) == PREFIX_SHA and
         len(stage30_raw) == SEGMENTS[1]["bytes"] and digest(stage30_raw) == STAGE_SHA,
         "composite.exact_segment_bytes")
    resolved = _derive(prefix, stage)
    need(type(proof["resolvedCanonicalSha256"]) is str and
         digest(canonical(resolved)) == proof["resolvedCanonicalSha256"], "composite.resolved_canonical_pin")
    return resolved

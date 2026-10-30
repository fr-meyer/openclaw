"""Pure finite CI allowance. No scheduler, transport, authority writer or I/O."""
from datetime import datetime, timezone
import hashlib
import json
import re

SCHEMA = "openclaw.v109.bounded-ci-run-grant.v1"
PLAN_SCHEMA = "openclaw.v109.reviewed-next-ci-execution.v1"
AUTHORITY_SHA256 = "801209d1bbbd51b5dd315f7c9367aacc4f12cf15430c23a0f46775d568ccf532"
APPROVED_AT = "2026-10-30T06:12:01Z"
EXPIRES_AT = "2026-11-03T03:14:21Z"
ORIGINAL_AUTHORIZATION_SHA256 = "af503856db977750026d77e0e53d63ad2ec0f617254c346ca55ef2a8e110f3d8"
PREFIX_PRODUCER_SHA256 = "d39edc5b60bee4ea822b32c1dec885ce67316fbfea193a26321f6cc297961327"
PREFIX_RECORDS = 42
PREFIX_MINUTES = 38
MAXIMUM_ADDITIONAL_ATTEMPTS = 1000
MAXIMUM_STAGE_ATTEMPTS = 1042
MAXIMUM_NEW_MINUTES = 2500
MAXIMUM_SOURCE_PARALLEL = 3
DIAGNOSTIC_BYTES = 67108864
MONEY_USD = "2.25"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
ID = re.compile(r"[1-9][0-9]{0,19}\Z")
FIRST_SOURCE = "ba04217f6642091b94f396669318d068e6007ed7"
LAST_PREFIX_SOURCE = {"runId": "41003661031", "pipelineHead": "409704dd078c83d2f41ed709660633c619b172be",
    "requestSha256": "5c4f7d4a56d959ba21d77dd00ca6868a49eb18519ada393e639d002fe68ae5ff"}


class Refusal(ValueError):
    """A fixed refusal from this closed controller, never arbitrary child text."""


def need(value, code):
    if not value:
        raise Refusal("v9.run_grant_" + code)


def fields(value, names, code):
    need(type(value) is dict and set(value) == set(names), code)
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def pin(value, bits=256):
    return type(value) is str and (SHA256 if bits == 256 else SHA).fullmatch(value) is not None


def utc(value):
    need(type(value) is str and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value), "clock")
    try:
        result = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise Refusal("v9.run_grant_clock")
    need(result.strftime("%Y-%m-%dT%H:%M:%SZ") == value, "clock")
    return result


def validate_plan(plan, active=False):
    fields(plan, ("schema", "status", "sequence", "phase", "preparationAttempt", "source",
        "priorSourceRun", "reasonCode", "reviewSha256", "requestSha256", "reservations"), "plan_fields")
    need(plan["schema"] == PLAN_SCHEMA and plan["status"] in ("DISARMED", "REVIEWED") and
        type(plan["sequence"]) is int and 1 <= plan["sequence"] <= MAXIMUM_ADDITIONAL_ATTEMPTS and
        plan["phase"] in ("lock-preparation", "validation", "correction") and
        type(plan["preparationAttempt"]) is int and 3 <= plan["preparationAttempt"] <= 1002 and
        plan["reasonCode"] in ("initial_recovery", "prior_failure", "generation_ready", "reviewed_pipeline_correction"),
        "plan_scope")
    prior = fields(plan["priorSourceRun"], ("runId", "pipelineHead", "requestSha256"), "prior_source_fields")
    need(type(prior["runId"]) is str and ID.fullmatch(prior["runId"]) and
        pin(prior["pipelineHead"], 160) and pin(prior["requestSha256"]), "prior_source_identity")
    need(type(plan["source"]) is dict and pin(plan["source"].get("sourceSha"), 160), "source_pin")
    r = fields(plan["reservations"], ("current", "pendingValidation", "conditionalImage", "incidental"), "reservation_fields")
    need(all(type(v) is int and 0 <= v <= MAXIMUM_NEW_MINUTES for v in r.values()) and
        r["current"] in ((45,) if plan["phase"] == "lock-preparation" else (1075, 740)) and
        r["pendingValidation"] == (1075 if plan["phase"] == "lock-preparation" else 0) and
        r["conditionalImage"] in (0, 180) and sum(r.values()) <= MAXIMUM_NEW_MINUTES,
        "reservation_scope")
    if r["current"] == 740:
        need(plan["phase"] == "correction" and plan["sequence"] >= 10, "lower_source_schedule_scope")
    if plan["sequence"] == 1:
        need(plan["phase"] == "lock-preparation" and plan["preparationAttempt"] == 3 and
            plan["source"]["sourceSha"] == FIRST_SOURCE and plan["priorSourceRun"] == LAST_PREFIX_SOURCE and
            plan["reasonCode"] == "initial_recovery" and
            r == {"current": 45, "pendingValidation": 1075, "conditionalImage": 180, "incidental": 28},
            "first_needed_execution")
    if plan["status"] == "DISARMED":
        need(plan["reviewSha256"] is None and plan["requestSha256"] is None and not active, "plan_disarmed")
    else:
        need(pin(plan["reviewSha256"]) and pin(plan["requestSha256"]), "reviewed_request_identity")
    return plan


def validate_grant(grant, original_authorization, active=False, now=None):
    fields(grant, ("schema", "status", "authoritySha256", "approvedAt", "expiresAt",
        "originalAuthorizationSha256", "closedPrefixProducerSha256", "maximumAdditionalAttempts",
        "maximumStageAttempts", "maximumNewRunnerMinutes", "maximumSourceParallelJobs",
        "diagnosticBytes", "moneyCeilingUSD", "bookedAdditionalAttempts", "nextExecution"), "fields")
    need(grant["schema"] == SCHEMA and grant["status"] in ("DISARMED", "APPROVED") and
        grant["authoritySha256"] == AUTHORITY_SHA256 and grant["approvedAt"] == APPROVED_AT and
        grant["expiresAt"] == EXPIRES_AT and grant["originalAuthorizationSha256"] ==
        ORIGINAL_AUTHORIZATION_SHA256 == digest(original_authorization) and
        grant["closedPrefixProducerSha256"] == PREFIX_PRODUCER_SHA256 and
        type(grant["maximumAdditionalAttempts"]) is int and grant["maximumAdditionalAttempts"] == 1000 and
        type(grant["maximumStageAttempts"]) is int and grant["maximumStageAttempts"] == 1042 and
        type(grant["maximumNewRunnerMinutes"]) is int and grant["maximumNewRunnerMinutes"] == 2500 and
        type(grant["maximumSourceParallelJobs"]) is int and grant["maximumSourceParallelJobs"] == 3 and
        type(grant["diagnosticBytes"]) is int and grant["diagnosticBytes"] == DIAGNOSTIC_BYTES and
        grant["moneyCeilingUSD"] == MONEY_USD, "exact_scope")
    need(type(grant["bookedAdditionalAttempts"]) is list and len(grant["bookedAdditionalAttempts"]) <= 1000,
        "booked_attempt_list")
    keys = set()
    for row in grant["bookedAdditionalAttempts"]:
        fields(row, ("runId", "nativeAttempt", "runnerMinutes"), "booked_attempt_fields")
        need(type(row["runId"]) is str and ID.fullmatch(row["runId"]) and
            type(row["nativeAttempt"]) is int and 1 <= row["nativeAttempt"] <= 1001 and
            type(row["runnerMinutes"]) is int and 0 <= row["runnerMinutes"] <= MAXIMUM_NEW_MINUTES,
            "booked_attempt_identity")
        key = (row["runId"], row["nativeAttempt"])
        need(key not in keys and not (key[0] in PREFIX_RUN_IDS and key[1] == 1), "booked_attempt_duplicate")
        keys.add(key)
    validate_plan(grant["nextExecution"], active=active)
    if active:
        need(grant["status"] == "APPROVED" and grant["nextExecution"]["status"] == "REVIEWED" and
            type(now) in (int, float) and utc(APPROVED_AT).timestamp() <= now < utc(EXPIRES_AT).timestamp(),
            "active_clock_or_review")
    return grant


def count_attempts(history, historical_ids, grant):
    """Count creation/attempt identities, including unsupported reruns, no refunds."""
    need(type(history) is dict and type(historical_ids) is set, "history_type")
    prefix = {(rid, 1) for rid in PREFIX_RUN_IDS}
    observed, native_reruns, observed_ids = set(), [], set()
    for rid, run in history.items():
        need(type(rid) is str and ID.fullmatch(rid) and type(run) is dict and
            type(run.get("id")) is int and str(run["id"]) == rid and
            type(run.get("run_attempt")) is int and run["run_attempt"] >= 1, "native_attempt_identity")
        n = run["run_attempt"]
        need(n <= 1001, "native_attempt_count_exhausted")
        # Only the original historical attempt1 belongs to the old closed
        # campaign. Any newly observed rerun is charged before refusing it.
        first = 2 if rid in historical_ids else 1
        observed.update((rid, attempt) for attempt in range(first, n + 1))
        observed_ids.add(rid)
        if n != 1:
            native_reruns.append(rid)
    booked = {(r["runId"], r["nativeAttempt"]) for r in grant["bookedAdditionalAttempts"]}
    union = prefix | observed | booked
    additional = union - prefix
    missing_prefix = sorted(set(PREFIX_RUN_IDS) - observed_ids)
    missing_booked = sorted(booked - observed)
    return {"prefixAttemptsBooked": 42, "additionalAttemptCount": len(additional),
        "stageAttemptCount": len(union), "remainingAttemptAllowance": max(0, 1000 - len(additional)),
        "unsupportedNativeReruns": sorted(native_reruns), "missingPrefixIds": missing_prefix,
        "missingBookedAttempts": [list(x) for x in missing_booked],
        "withinCountLimit": len(additional) <= 1000,
        "supportedFreshNativeFirstAttempts": not native_reruns and not missing_prefix and not missing_booked,
        "attemptIdentities": [list(x) for x in sorted(union)]}


def validate_budget(grant, plan, new_observed_minutes, current_observed_minutes):
    need(type(new_observed_minutes) is int and type(current_observed_minutes) is int and
        0 <= current_observed_minutes <= new_observed_minutes, "observed_minutes")
    booked = PREFIX_MINUTES + sum(r["runnerMinutes"] for r in grant["bookedAdditionalAttempts"])
    need(current_observed_minutes <= plan["reservations"]["current"], "current_phase_cap")
    # The active job's elapsed time is covered by its full current reservation,
    # not charged a second time. Completed recorded attempts are never refunded.
    other = max(new_observed_minutes - current_observed_minutes, booked)
    observed = other + current_observed_minutes
    maximum = other + sum(plan["reservations"].values())
    need(maximum <= MAXIMUM_NEW_MINUTES, "cumulative_runner_budget")
    return {"newObservedOrBookedMinutes": observed, "otherMinutesCharged": other,
        "reservedMinutes": sum(plan["reservations"].values()), "maximumNewMinutesBooked": maximum,
        "maximumNewRunnerMinutes": MAXIMUM_NEW_MINUTES, "noConsumedMinuteRefund": True}


# Inserted from the fixed, hash-verified closed 42-record producer, not API input.
PREFIX_RUN_IDS = ('40997862688', '40997862829', '40997862875', '40997862939', '40997862991', '40997863063', '40997866196', '40997866229', '40997866323', '40997866357', '40997866390', '40997868003', '40997868027', '40997868031', '40997868050', '40997868053', '40997868069', '40997868135', '40997868140', '40997868144', '40997868160', '41003655563', '41003655675', '41003655688', '41003655715', '41003655723', '41003655733', '41003658923', '41003658958', '41003659018', '41003659182', '41003659256', '41003660893', '41003660895', '41003660898', '41003660902', '41003660906', '41003660952', '41003660969', '41003660972', '41003661031', '41003661223')

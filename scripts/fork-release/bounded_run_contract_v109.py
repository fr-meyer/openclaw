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
BUDGET_AMENDMENT_SCHEMA = "openclaw.v109.budget-ceiling-amendment-binding.v1"
BUDGET_AMENDMENT_SHA256 = "fabe093988e258a99b7cccc83e812d274200880cc300f78a73f795905e507f6e"
MINUTE_AMENDMENT_SHA256 = "a87532d38ff05c0d5d8e253d76abac4a2ea191a603037f22f553099b3c379cf2"
SPENDING_AMENDMENT_SHA256 = "c31ba60a02c44ef2525b187ea058a8de45c8e2199c60630bd4601d30d8acabc6"
AMENDED_MAXIMUM_NEW_MINUTES = 25000  # Total, not an additional allocation.
AMENDED_MONEY_USD = "25.00"
AMENDED_SOURCE = "0d0b3dbcbb571509df403e98d7e9be69a8f46f4f"
AMENDED_SOURCE_TREE = "30f2e6f97ed0d3db6239b00c3550a6ab4e18a63f"

# The H3 amendment extends material-source scope and time, never old receipt bytes.
H3_AMENDMENT_SHA256 = "6fa3c7efad07c76ddb4c6a3a8b53ec143a4c177a0260d7707a11957678060520"
H3_PRIVATE_AUTHORIZATION_SHA256 = "8df97c688f5273be12a4dad408b282660df2473bdbd1e02260c5613d04958446"
H3_PREFIX_LEDGER_SHA256 = "56f29f04c138fd06ea1ecfbd38ab27acfd24e99a48269066f7e2f57ad7a1043b"
H3_PREFIX_PROOF_SHA256 = "f06d0031f82f06b155ca9e1c93e60da1fb5bc3bd88dc9ca218a2ed9fea3b7153"
H3_NOT_BEFORE = "2026-11-04T09:59:50Z"  # Ceiling of the recorded .641s direct-patch floor, not full closure proof.
H3_EXPIRES_AT = "2026-11-06T03:14:21Z"
H3_PREFIX_MINUTES = 2215
H3_STAGE_MINUTES = 3700
H3_MAXIMUM_BOOKED_MINUTES = H3_PREFIX_MINUTES + H3_STAGE_MINUTES
H3_MAXIMUM_SOURCE_GENERATIONS = 3
H3_STAGE_POOLS = {"source": 3225, "preparation": 135, "incidental": 160, "image": 180}
H3_DESCRIPTOR_FIELDS = ("publicAmendmentSha256", "privateAuthorizationSha256", "expiresAt",
    "minimumPackageUseAt", "stagePrefixLedgerSha256", "stagePrefixNewMinutes",
    "maximumStageRunnerMinutes", "maximumStageBookedMinutes", "maximumSourceGenerations")
H3_ARTIFACT_FIELDS = ("id", "name", "size_in_bytes", "expired", "digest", "created_at",
    "expires_at", "updated_at", "workflow_run")
H3_ARTIFACT_CONTEXT_FIELDS = ("id", "repository_id", "head_repository_id", "head_branch", "head_sha")
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


def validate_budget_amendment(value):
    fields(value, ("schema", "scope", "publicAmendmentSha256", "minuteAmendmentSha256",
        "spendingAmendmentSha256", "isTotalNotAdditional"), "budget_amendment_fields")
    need(value == {"schema": BUDGET_AMENDMENT_SCHEMA, "scope": "minute-and-spending-ceilings-only",
        "publicAmendmentSha256": BUDGET_AMENDMENT_SHA256, "minuteAmendmentSha256": MINUTE_AMENDMENT_SHA256,
        "spendingAmendmentSha256": SPENDING_AMENDMENT_SHA256, "isTotalNotAdditional": True} and
        value["isTotalNotAdditional"] is True, "budget_amendment_binding")
    return value


def vendor_repair_continuation():
    """Exact approved G4/conditional-G5 scope; no execution or mutable authority."""
    return {"schema": "openclaw.v109.vendor-repair-continuation.v1",
        "proposalSha256": "40468f07a09278c71d8998a80f3f40b3e46239bfff9475828df25a27f9da676f",
        "authorizationSha256": "46b498143d1f8fc7bcb52d12bde43518ab1476811249cb5ec0b8165ce318cf5e",
        "priorLedgerSha256": "1948b1b2f08eeab7f00f5160ceda4d1f105e142ffc3e63613bad9f5888bf7482",
        "maximumMaterialSourceGenerations": 5, "maximumAdditionalSourceGenerations": 2,
        "conditionalSecondRevisionEvidenceRequired": True, "maximumAdditionalPreparations": 2,
        "maximumValidationWaves": 2, "maximumSameSourcePipelineCorrections": 1,
        "maximumAdditionalRunnerMinutes": 2290, "vendorAggregateMaximumMinutes": 2360,
        "vendorComponentMaximumMinutes": {"preparation": 180, "source": 2150, "incidental": 80},
        "stagePools": {"preparation": 225, "source": 3135, "incidental": 160, "image": 180},
        "latestWholePlanAdmission": "2026-11-05T07:14:21Z"}


def vendor_repair_resource_allocation():
    """Closed internal allocation record; never new human/source authority."""
    value = vendor_repair_continuation()
    value["vendorComponentMaximumMinutes"]["incidental"] = 110
    value["resourceAllocationRecord"] = {
        "decisionSha256": "4edb729e1c99e689fcd2436f13dc766d97d5e949a0b1b3dd4392b67d37ec1071",
        "kind": "internal-resource-allocation", "newHumanApproval": False}
    return value


def vendor_repair_derivation_recovery_allocation():
    """Closed funded preparation recovery; all human authority is unchanged."""
    value = vendor_repair_resource_allocation()
    value["vendorComponentMaximumMinutes"]["preparation"] = 225
    value["stagePools"].update(preparation=270, source=3090)
    value["resourceAllocationRecord"] = {
        "decisionSha256": "ec861a2d06b6c0b11d5f4b44138dff44817503ab8d8d55d7d5b896c68e388f82",
        "kind": "internal-resource-allocation", "newHumanApproval": False}
    return value


def vendor_repair_combined_source_allocation():
    """Exact Gen6/conditional-Gen7 approval, preserving every prior debit.

    The two full-cost slots are a resource plan. The original needed-record
    allowance still counts every failed, partial, held and unknown attempt.
    """
    return {"schema": "openclaw.v109.vendor-repair-continuation.v1",
        "proposalSha256": "aa8ce7f20d173176361d582fc955399c949b4148ee22e12b508aa6e0e9dea8a4",
        "authorizationSha256": "dc24e48bfe15dcb343affc4e04573fca260fdb119560d2a4e47332a02e0cd423",
        "priorLedgerSha256": "5b1af3981177a487115cc185667dbb06bd25f930cf984c1895cf51165e66c354",
        "maximumMaterialSourceGenerations": 7, "maximumAdditionalSourceGenerations": 2,
        "conditionalSecondRevisionEvidenceRequired": True,
        "plannedFullCostPreparationSlots": 2, "plannedFullCostValidationSlots": 2,
        "maximumAdditionalRunnerMinutes": 3122,
        "privateComponentMaximumMinutes": {"preparation": 218, "source": 2760, "incidental": 144},
        "vendorAggregateMaximumMinutes": 3192,
        "vendorComponentMaximumMinutes": {"preparation": 267, "source": 2760, "incidental": 165},
        "stagePools": {"preparation": 310, "source": 3189, "incidental": 194, "image": 180},
        "futureEnvelopeRunnerMinutes": 2300, "carriedUnusedRunnerMinutes": 1468,
        "netStageIncreaseRunnerMinutes": 832,
        "futurePools": {"preparation": 90, "source": 2150, "incidental": 60},
        "expiresAt": "2026-11-07T03:14:21Z", "latestWholePlanAdmission": "2026-11-06T07:04:21Z",
        "resourceAllocationRecord": {
            "decisionSha256": "dc24e48bfe15dcb343affc4e04573fca260fdb119560d2a4e47332a02e0cd423",
            "kind": "human-approved-source-repair-scope-extension", "newHumanApproval": True}}


def vendor_repair_combined_source_deadline_extension():
    """Exact time-only successor; original allocation and history stay immutable."""
    value = vendor_repair_combined_source_allocation()
    value.update(expiresAt="2026-11-09T03:14:21Z", latestWholePlanAdmission="2026-11-08T07:04:21Z")
    value["deadlineExtension"] = {"schema": "openclaw.v109.time-only-deadline-extension.v1",
        "authorizationSha256": "8350ab78bfeaaef2779c94f725e0fbb030f454261903192c5c180585c8d73337",
        "previousExpiresAt": "2026-11-07T03:14:21Z", "expiresAt": "2026-11-09T03:14:21Z",
        "resourceScopeChanged": False}
    return value


def is_combined_source_deadline_extension(value):
    return type(value) is dict and canonical(value) == canonical(vendor_repair_combined_source_deadline_extension())


def is_combined_source_repair(value):
    return type(value) is dict and (canonical(value) == canonical(vendor_repair_combined_source_allocation()) or
        is_combined_source_deadline_extension(value))


def validate_vendor_repair_continuation(value):
    record = value.get("resourceAllocationRecord") if type(value)is dict else None
    expected = (vendor_repair_combined_source_deadline_extension() if type(value)is dict and "deadlineExtension" in value else
        vendor_repair_combined_source_allocation() if type(record)is dict and
        record.get("decisionSha256") == "dc24e48bfe15dcb343affc4e04573fca260fdb119560d2a4e47332a02e0cd423" else
        vendor_repair_derivation_recovery_allocation() if type(record)is dict and
        record.get("decisionSha256") == "ec861a2d06b6c0b11d5f4b44138dff44817503ab8d8d55d7d5b896c68e388f82" else
        vendor_repair_resource_allocation() if type(value)is dict and "resourceAllocationRecord" in value else
        vendor_repair_continuation())
    fields(value, expected, "vendor_continuation_fields")
    # Canonical JSON also distinguishes booleans from integer limits.
    need(canonical(value) == canonical(expected), "vendor_continuation_scope")
    return value


def vendor_continuation_from_digest(value):
    need(pin(value), "vendor_continuation_digest")
    for projection in (vendor_repair_continuation(), vendor_repair_resource_allocation(),
            vendor_repair_derivation_recovery_allocation(), vendor_repair_combined_source_allocation(),
            vendor_repair_combined_source_deadline_extension()):
        if value == digest(projection):
            return projection
    need(False, "vendor_continuation_digest")


def validate_vendor_continuation_request(grant, request):
    """Match this request to its OWN closed grant; known digest is not authority."""
    need(type(request)is dict, "vendor_continuation_request")
    value = vendor_continuation_for(grant) if grant is not None else None
    if value is None:
        need("vendorRepairContinuationSha256" not in request, "vendor_continuation_request_without_grant")
    else:
        need(request.get("vendorRepairContinuationSha256") == digest(value), "vendor_continuation_request_binding")
    return value


def vendor_continuation_for(grant):
    need(type(grant) is dict, "vendor_continuation_grant")
    amendment = grant.get("sourceSuccessorAmendment")
    if type(amendment) is not dict or "vendorRepairContinuation" not in amendment:
        return None
    return validate_vendor_repair_continuation(amendment["vendorRepairContinuation"])


def h3_stage_pools(grant):
    value = vendor_continuation_for(grant)
    return dict(value["stagePools"] if value is not None else H3_STAGE_POOLS)


def h3_stage_descriptor(continuation=False, combined_source_repair=False, deadline_extension=False):
    need(type(continuation) is bool and type(combined_source_repair) is bool and type(deadline_extension) is bool and
        (not combined_source_repair or continuation) and (not deadline_extension or combined_source_repair),
        "vendor_continuation_selector")
    combined = (vendor_repair_combined_source_deadline_extension() if deadline_extension else
        vendor_repair_combined_source_allocation()) if combined_source_repair else None
    stage_minutes = sum(combined["stagePools"].values()) if combined is not None else H3_STAGE_MINUTES
    return {"publicAmendmentSha256": H3_AMENDMENT_SHA256,
        "privateAuthorizationSha256": H3_PRIVATE_AUTHORIZATION_SHA256,
        "expiresAt": combined["expiresAt"] if combined is not None else H3_EXPIRES_AT, "minimumPackageUseAt": H3_NOT_BEFORE,
        "stagePrefixLedgerSha256": H3_PREFIX_LEDGER_SHA256,
        "stagePrefixNewMinutes": H3_PREFIX_MINUTES, "maximumStageRunnerMinutes": stage_minutes,
        "maximumStageBookedMinutes": H3_PREFIX_MINUTES + stage_minutes,
        "maximumSourceGenerations": 7 if combined is not None else (5 if continuation else H3_MAXIMUM_SOURCE_GENERATIONS)}


def validate_h3_stage_descriptor(value, continuation=False, combined_source_repair=False, deadline_extension=False):
    fields(value, H3_DESCRIPTOR_FIELDS, "h3_stage_descriptor_fields")
    expected = h3_stage_descriptor(continuation=continuation, combined_source_repair=combined_source_repair,
        deadline_extension=deadline_extension)
    need(all(type(value[k]) is type(v) and value[k] == v for k, v in expected.items()),
        "h3_stage_descriptor_scope")
    return value


def validate_h3_artifact_booking(row):
    fields(row, ("producerRunId", "producerHead", "nativeResponseSha256", "metadata",
        "fieldPresence", "workflowRunFieldPresence"), "h3_artifact_booking_fields")
    need(type(row["producerRunId"]) is str and ID.fullmatch(row["producerRunId"]) and
        pin(row["producerHead"], 160) and pin(row["nativeResponseSha256"]), "h3_artifact_producer")
    meta = row["metadata"]
    presence = fields(row["fieldPresence"], H3_ARTIFACT_FIELDS, "h3_artifact_presence_fields")
    context_presence = fields(row["workflowRunFieldPresence"], H3_ARTIFACT_CONTEXT_FIELDS,
        "h3_artifact_context_presence_fields")
    need(all(type(x) is bool for x in (*presence.values(), *context_presence.values())) and
        type(meta) is dict and set(meta) == {k for k, present in presence.items() if present} and
        all(presence[k] for k in ("id", "name", "size_in_bytes", "expired")), "h3_artifact_presence")
    need(type(meta["id"]) is int and meta["id"] > 0 and type(meta["name"]) is str and
        0 < len(meta["name"]) <= 300 and type(meta["size_in_bytes"]) is int and
        0 <= meta["size_in_bytes"] <= DIAGNOSTIC_BYTES and type(meta["expired"]) is bool,
        "h3_artifact_metadata")
    if presence["digest"]:
        need(type(meta["digest"]) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", meta["digest"]),
            "h3_artifact_digest")
    for key in ("created_at", "expires_at", "updated_at"):
        if presence[key]: utc(meta[key])
    if presence["created_at"] and presence["expires_at"]:
        need(utc(meta["created_at"]) <= utc(meta["expires_at"]), "h3_artifact_expiry_order")
    if presence["workflow_run"]:
        context = meta["workflow_run"]
        need(type(context) is dict and set(context) == {k for k, present in context_presence.items() if present},
            "h3_artifact_context_presence")
        expected = {"id": int(row["producerRunId"]), "repository_id": 1309456040,
            "head_repository_id": 1309456040, "head_sha": row["producerHead"]}
        need(all(k not in context or type(context[k]) is type(v) and context[k] == v
            for k, v in expected.items()), "h3_artifact_context")
        if "head_branch" in context:
            need(context["head_branch"] in ("task/v107-source-binding", "prep/v2026.10.9-remediation"),
                "h3_artifact_context_branch")
    else:
        need(not any(context_presence.values()), "h3_artifact_absent_context")
    return row


def source_successor_amendment(grant):
    need(type(grant) is dict, "h3_grant_type")
    if "sourceSuccessorAmendment" not in grant:
        return None
    value = fields(grant["sourceSuccessorAmendment"], (*H3_DESCRIPTOR_FIELDS,
        "sourceFamilySha256", "sourceGeneration", "bookedArtifacts") +
        (("vendorRepairContinuation",) if "vendorRepairContinuation" in grant["sourceSuccessorAmendment"] else ()),
        "h3_amendment_fields")
    continuation = vendor_continuation_for(grant)
    validate_h3_stage_descriptor({k: value[k] for k in H3_DESCRIPTOR_FIELDS}, continuation=continuation is not None,
        combined_source_repair=is_combined_source_repair(continuation),
        deadline_extension=is_combined_source_deadline_extension(continuation))
    need(pin(value["sourceFamilySha256"]) and type(value["sourceGeneration"]) is int and
        (6 if is_combined_source_repair(continuation) else (4 if continuation is not None else 1)) <= value["sourceGeneration"] <= value["maximumSourceGenerations"] and type(value["bookedArtifacts"]) is list and
        26 <= len(value["bookedArtifacts"]) <= 4096, "h3_amendment_family")
    ids = set()
    for row in value["bookedArtifacts"]:
        validate_h3_artifact_booking(row)
        aid = row["metadata"]["id"]
        need(aid not in ids, "h3_artifact_duplicate"); ids.add(aid)
    need(sum(r["metadata"]["size_in_bytes"] for r in value["bookedArtifacts"]) <= DIAGNOSTIC_BYTES,
        "h3_booked_artifact_bytes")
    return value


def effective_expires_at(grant):
    amendment = source_successor_amendment(grant)
    return amendment["expiresAt"] if amendment is not None else EXPIRES_AT


def amended_source_scope(value):
    need(type(value) is dict and value.get("phase") == "correction" and
        type(value.get("sequence")) is int and 12 <= value["sequence"] <= MAXIMUM_ADDITIONAL_ATTEMPTS and
        type(value.get("source")) is dict and value["source"].get("sourceSha") == AMENDED_SOURCE and
        value["source"].get("sourceTree") == AMENDED_SOURCE_TREE, "budget_amendment_source_scope")


def has_budget_amendment(grant):
    need(type(grant) is dict, "budget_grant_type")
    if "budgetCeilingAmendment" not in grant:
        return False
    validate_budget_amendment(grant["budgetCeilingAmendment"])
    need(grant.get("authoritySha256") == AUTHORITY_SHA256 and
        grant.get("originalAuthorizationSha256") == ORIGINAL_AUTHORIZATION_SHA256 and
        grant.get("expiresAt") == effective_expires_at(grant) and grant.get("moneyCeilingUSD") == AMENDED_MONEY_USD and
        type(grant.get("maximumNewRunnerMinutes")) is int and
        grant["maximumNewRunnerMinutes"] == AMENDED_MAXIMUM_NEW_MINUTES and
        type(grant.get("maximumAdditionalAttempts")) is int and grant["maximumAdditionalAttempts"] == 1000 and
        type(grant.get("maximumStageAttempts")) is int and grant["maximumStageAttempts"] == 1042 and
        type(grant.get("maximumSourceParallelJobs")) is int and grant["maximumSourceParallelJobs"] == 3 and
        type(grant.get("diagnosticBytes")) is int and grant["diagnosticBytes"] == DIAGNOSTIC_BYTES,
        "budget_amendment_unchanged_scope")
    h3 = source_successor_amendment(grant)
    if h3 is None:
        amended_source_scope(grant.get("nextExecution"))
    else:
        plan = grant.get("nextExecution")
        need(type(plan) is dict and type(plan.get("sequence")) is int and 12 <= plan["sequence"] <= 1000 and
            plan.get("phase") in ("lock-preparation", "validation") and
            plan.get("sourceGeneration") == h3["sourceGeneration"] and
            type(plan.get("sourceGeneration")) is int and
            plan.get("sourceFamilySha256") == h3["sourceFamilySha256"], "h3_plan_binding")
        r = plan.get("reservations")
        need(type(r) is dict and r.get("current") == (45 if plan["phase"] == "lock-preparation" else 1075) and
            r.get("pendingValidation") == (1075 if plan["phase"] == "lock-preparation" else 0) and
            r.get("conditionalImage") == 180 and r.get("incidental") == h3_stage_pools(grant)["incidental"], "h3_plan_reservations")
    return True


def maximum_new_minutes(grant):
    return AMENDED_MAXIMUM_NEW_MINUTES if has_budget_amendment(grant) else MAXIMUM_NEW_MINUTES


def validate_plan(plan, active=False):
    fields(plan, ("schema", "status", "sequence", "phase", "preparationAttempt", "source",
        "priorSourceRun", "reasonCode", "reviewSha256", "requestSha256", "reservations") +
        (("sourceGeneration", "sourceFamilySha256") if type(plan) is dict and
            ("sourceGeneration" in plan or "sourceFamilySha256" in plan) else ()), "plan_fields")
    need(plan["schema"] == PLAN_SCHEMA and plan["status"] in ("DISARMED", "REVIEWED") and
        type(plan["sequence"]) is int and 1 <= plan["sequence"] <= MAXIMUM_ADDITIONAL_ATTEMPTS and
        plan["phase"] in ("lock-preparation", "validation", "correction") and
        type(plan["preparationAttempt"]) is int and 3 <= plan["preparationAttempt"] <= 1002 and
        plan["reasonCode"] in ("initial_recovery", "prior_failure", "generation_ready", "reviewed_pipeline_correction", "approved_source_successor"),
        "plan_scope")
    if "sourceGeneration" in plan:
        need(type(plan["sourceGeneration"]) is int and 1 <= plan["sourceGeneration"] <= 7 and
            pin(plan["sourceFamilySha256"]) and plan["sequence"] >= 12, "h3_plan_family")
    else:
        need(plan["reasonCode"] != "approved_source_successor", "h3_reason_requires_binding")
    prior = fields(plan["priorSourceRun"], ("runId", "pipelineHead", "requestSha256"), "prior_source_fields")
    need(type(prior["runId"]) is str and ID.fullmatch(prior["runId"]) and
        pin(prior["pipelineHead"], 160) and pin(prior["requestSha256"]), "prior_source_identity")
    need(type(plan["source"]) is dict and pin(plan["source"].get("sourceSha"), 160), "source_pin")
    r = fields(plan["reservations"], ("current", "pendingValidation", "conditionalImage", "incidental"), "reservation_fields")
    need(all(type(v) is int and 0 <= v <= MAXIMUM_NEW_MINUTES for v in r.values()) and
        r["current"] in ((45,) if plan["phase"] == "lock-preparation" else (1075, 740, 690)) and
        r["pendingValidation"] == (1075 if plan["phase"] == "lock-preparation" else 0) and
        r["conditionalImage"] in (0, 180) and sum(r.values()) <= MAXIMUM_NEW_MINUTES,
        "reservation_scope")
    if r["current"] == 740:
        need(plan["phase"] == "correction" and plan["sequence"] >= 10, "lower_source_schedule_scope")
    if r["current"] == 690:
        need(plan["phase"] == "correction" and plan["sequence"] >= 11, "next_source_schedule_scope")
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
        "diagnosticBytes", "moneyCeilingUSD", "bookedAdditionalAttempts", "nextExecution") +
        (("budgetCeilingAmendment",) if type(grant) is dict and "budgetCeilingAmendment" in grant else ()) +
        (("sourceSuccessorAmendment",) if type(grant) is dict and "sourceSuccessorAmendment" in grant else ()), "fields")
    h3 = source_successor_amendment(grant)
    need(h3 is None or "budgetCeilingAmendment" in grant, "h3_requires_total_amendment")
    amended = has_budget_amendment(grant)
    maximum = maximum_new_minutes(grant)
    need(grant["schema"] == SCHEMA and grant["status"] in ("DISARMED", "APPROVED") and
        grant["authoritySha256"] == AUTHORITY_SHA256 and grant["approvedAt"] == APPROVED_AT and
        grant["expiresAt"] == effective_expires_at(grant) and grant["originalAuthorizationSha256"] ==
        ORIGINAL_AUTHORIZATION_SHA256 == digest(original_authorization) and
        grant["closedPrefixProducerSha256"] == PREFIX_PRODUCER_SHA256 and
        type(grant["maximumAdditionalAttempts"]) is int and grant["maximumAdditionalAttempts"] == 1000 and
        type(grant["maximumStageAttempts"]) is int and grant["maximumStageAttempts"] == 1042 and
        type(grant["maximumNewRunnerMinutes"]) is int and grant["maximumNewRunnerMinutes"] == maximum and
        type(grant["maximumSourceParallelJobs"]) is int and grant["maximumSourceParallelJobs"] == 3 and
        type(grant["diagnosticBytes"]) is int and grant["diagnosticBytes"] == DIAGNOSTIC_BYTES and
        grant["moneyCeilingUSD"] == (AMENDED_MONEY_USD if amended else MONEY_USD), "exact_scope")
    need(type(grant["bookedAdditionalAttempts"]) is list and len(grant["bookedAdditionalAttempts"]) <= 1000,
        "booked_attempt_list")
    keys = set()
    for row in grant["bookedAdditionalAttempts"]:
        fields(row, ("runId", "nativeAttempt", "runnerMinutes"), "booked_attempt_fields")
        need(type(row["runId"]) is str and ID.fullmatch(row["runId"]) and
            type(row["nativeAttempt"]) is int and 1 <= row["nativeAttempt"] <= 1001 and
            type(row["runnerMinutes"]) is int and 0 <= row["runnerMinutes"] <= maximum,
            "booked_attempt_identity")
        key = (row["runId"], row["nativeAttempt"])
        need(key not in keys and not (key[0] in PREFIX_RUN_IDS and key[1] == 1), "booked_attempt_duplicate")
        keys.add(key)
    validate_plan(grant["nextExecution"], active=active)
    if h3 is None:
        need("sourceGeneration" not in grant["nextExecution"] and "sourceFamilySha256" not in grant["nextExecution"],
            "h3_family_requires_amendment")
    else:
        need(PREFIX_MINUTES + sum(r["runnerMinutes"] for r in grant["bookedAdditionalAttempts"]) >=
            H3_PREFIX_MINUTES and len(grant["bookedAdditionalAttempts"]) >= 251, "h3_prefix_booking_floor")
    if active:
        need(grant["status"] == "APPROVED" and grant["nextExecution"]["status"] == "REVIEWED" and
            type(now) in (int, float) and
            utc(H3_NOT_BEFORE if h3 is not None else APPROVED_AT).timestamp() <= now <
            utc(effective_expires_at(grant)).timestamp(),
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
    ceiling = maximum_new_minutes(grant)
    if has_budget_amendment(grant):
        need(plan == grant["nextExecution"], "budget_amendment_exact_plan")
        validate_plan(plan)
    need(type(new_observed_minutes) is int and type(current_observed_minutes) is int and
        0 <= current_observed_minutes <= new_observed_minutes, "observed_minutes")
    booked = PREFIX_MINUTES + sum(r["runnerMinutes"] for r in grant["bookedAdditionalAttempts"])
    need(current_observed_minutes <= plan["reservations"]["current"], "current_phase_cap")
    # The active job's elapsed time is covered by its full current reservation,
    # not charged a second time. Completed recorded attempts are never refunded.
    other = max(new_observed_minutes - current_observed_minutes, booked)
    observed = other + current_observed_minutes
    maximum = other + sum(plan["reservations"].values())
    need(maximum <= ceiling, "cumulative_runner_budget")
    return {"newObservedOrBookedMinutes": observed, "otherMinutesCharged": other,
        "reservedMinutes": sum(plan["reservations"].values()), "maximumNewMinutesBooked": maximum,
        "maximumNewRunnerMinutes": ceiling, "noConsumedMinuteRefund": True}


# Inserted from the fixed, hash-verified closed 42-record producer, not API input.
PREFIX_RUN_IDS = ('40997862688', '40997862829', '40997862875', '40997862939', '40997862991', '40997863063', '40997866196', '40997866229', '40997866323', '40997866357', '40997866390', '40997868003', '40997868027', '40997868031', '40997868050', '40997868053', '40997868069', '40997868135', '40997868140', '40997868144', '40997868160', '41003655563', '41003655675', '41003655688', '41003655715', '41003655723', '41003655733', '41003658923', '41003658958', '41003659018', '41003659182', '41003659256', '41003660893', '41003660895', '41003660898', '41003660902', '41003660906', '41003660952', '41003660969', '41003660972', '41003661031', '41003661223')


def validate_h3_budget(grant, plan, charged_total, current_minutes, components):
    """Book all retained debits and the remaining approved component pools."""
    h3 = source_successor_amendment(grant)
    need(h3 is not None, "h3_budget_requires_authority")
    validate_plan(plan)
    fields(components, ("preparationObservedMinutes", "sourceObservedMinutes", "incidentalObservedMinutes",
        "imageObservedMinutes", "remainingImageFamilyReserveMinutes", "remainingIncidentalReserveMinutes"), "h3_budget_component_fields")
    need(type(charged_total) is int and charged_total >= H3_PREFIX_MINUTES and type(current_minutes) is int and
        0 <= current_minutes <= charged_total and all(type(v) is int and v >= 0 for v in components.values()),
        "h3_budget_positive_native_facts")
    pools = h3_stage_pools(grant)
    observed = {"preparation": components["preparationObservedMinutes"], "source": components["sourceObservedMinutes"],
        "incidental": components["incidentalObservedMinutes"], "image": components["imageObservedMinutes"]}
    need(all(observed[k] <= pools[k] for k in observed) and
        sum(observed.values()) <= charged_total - H3_PREFIX_MINUTES and
        components["remainingImageFamilyReserveMinutes"] == pools["image"] - observed["image"] and
        components["remainingIncidentalReserveMinutes"] == pools["incidental"] - observed["incidental"],
        "h3_budget_pool_bounds")
    pool = "preparation" if plan["phase"] == "lock-preparation" else "source"
    need(current_minutes <= plan["reservations"]["current"] and observed[pool] >= current_minutes and
        observed[pool] - current_minutes + plan["reservations"]["current"] <= pools[pool] and
        (plan["phase"] != "lock-preparation" or observed["source"] + plan["reservations"]["pendingValidation"] <= pools["source"]),
        "h3_budget_next_operation_pool")
    remaining = sum(pools[k] - observed[k] for k in observed)
    booked = charged_total + remaining
    need(booked <= min(maximum_new_minutes(grant), h3["maximumStageBookedMinutes"]), "h3_budget_cumulative_ceiling")
    return {"newObservedOrBookedMinutes": charged_total, "currentObservedMinutes": current_minutes,
        "remainingStagePoolReservationMinutes": remaining, "totalBookedMinutes": booked,
        "maximumStageBookedMinutes": h3["maximumStageBookedMinutes"],
        "maximumNewMinutes": maximum_new_minutes(grant), "perAttemptBookedMinuteFloorsApplied": True,
        "stagePoolObservedMinutes": observed}

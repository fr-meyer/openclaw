#!/usr/bin/env python3
"""Rehearsal entry point: daily snapshot lifecycle or legacy offline WIF plan."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
import uuid

REPOSITORY_ID = "1309456040"
OWNER_ID = "26621962"
WORKFLOW = "fr-meyer/openclaw/.github/workflows/gcp-rehearsal.yml"
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
AUDIENCE = re.compile(
    r"//iam\.googleapis\.com/projects/[1-9][0-9]*/locations/global/"
    r"workloadIdentityPools/[a-z][a-z0-9-]{3,31}/providers/[a-z][a-z0-9-]{3,31}\Z"
)
PHASES = {"snapshot", "restore", "doctor", "startup", "readiness", "rollback", "cleanup"}
STATES = {"pending", "running", "passed", "failed", "stalled", "unknown"}


class Refusal(ValueError):
    """Messages contain stable codes only, never supplied values."""


def need(ok, code):
    if not ok:
        raise Refusal(code)


def fields(value, names, code):
    need(type(value) is dict and set(value) == set(names.split()), code)


def matches(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def positive(value, maximum):
    return type(value) is int and 0 < value <= maximum


def utc(value):
    need(type(value) is str and re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value), "timestamp.format")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise Refusal("timestamp.value") from None


def validate_binding(binding):
    fields(binding, "sourceSha toolingSha imageDigest", "binding.fields")
    need(matches(SHA, binding["sourceSha"]), "binding.source")
    need(matches(SHA, binding["toolingSha"]), "binding.tooling")
    need(matches(DIGEST, binding["imageDigest"]), "binding.image")


def validate_plan(plan, now):
    """Validate a proposed resource envelope, not its approval or observations."""
    fields(plan, "schema createdAt expiresAt audience environment binding snapshot resources",
           "plan.fields")
    need(plan["schema"] == "openclaw.gcp-rehearsal-plan.v1", "plan.schema")
    created, expires = utc(plan["createdAt"]), utc(plan["expiresAt"])
    # Absolute expiration survives retries; recreating a plan is a new approval.
    need(created <= now < expires, "plan.expired_or_future")
    need(0 < (expires - created).total_seconds() <= 86400, "plan.ttl")
    need(matches(AUDIENCE, plan["audience"]), "plan.audience")
    need(plan["environment"] == "openclaw-rehearsal", "plan.environment")
    validate_binding(plan["binding"])
    snapshot = plan["snapshot"]
    fields(snapshot, "id sizeGiB purpose", "snapshot.fields")
    need(matches(re.compile(r"[1-9][0-9]{0,19}\Z"), snapshot["id"]), "snapshot.id")
    need(snapshot["purpose"] == "rehearsal_only", "snapshot.purpose")
    need(positive(snapshot["sizeGiB"], 1024), "snapshot.size")
    resources = plan["resources"]
    fields(resources,
           "machineType bootDiskGiB dataDiskGiB concurrency estimatedCostMicrousd approvedCostMicrousd",
           "resources.fields")
    need(resources["machineType"] in ("e2-standard-4", "e2-standard-8"), "resources.machine")
    need(positive(resources["bootDiskGiB"], 32), "resources.boot")
    need(positive(resources["dataDiskGiB"], 1024) and
         resources["dataDiskGiB"] >= snapshot["sizeGiB"], "resources.data")
    need(type(resources["concurrency"]) is int and resources["concurrency"] == 1,
         "resources.concurrency")
    # These numbers are privately approved inputs, not a price estimate by this script.
    need(positive(resources["approvedCostMicrousd"], 1_000_000_000), "resources.cost_cap")
    need(positive(resources["estimatedCostMicrousd"], resources["approvedCostMicrousd"]),
         "resources.cost_estimate")


def proposed_oidc_condition(plan):
    """Return proposed CEL; the provider must verify the JWT and enforce it."""
    validate_plan(plan, utc(plan["createdAt"]))
    expected = {
        "repository_id": REPOSITORY_ID,
        "repository_owner_id": OWNER_ID,
        "ref": "refs/heads/main",
        "event_name": "workflow_dispatch",
        "environment": plan["environment"],
        "workflow_ref": WORKFLOW + "@refs/heads/main",
        "workflow_sha": plan["binding"]["toolingSha"],
        "aud": plan["audience"],
    }
    return " && ".join(
        f"assertion.{key} == {json.dumps(value)}" for key, value in expected.items()
    )


def public_receipt(binding, observation):
    """For trusted supervisor measurements only; never pass candidate JSON here."""
    validate_binding(binding)
    fields(observation, "phase state observedAt elapsedSeconds", "public.fields")
    need(type(observation["phase"]) is str and observation["phase"] in PHASES,
         "public.phase")
    need(type(observation["state"]) is str and observation["state"] in STATES,
         "public.state")
    utc(observation["observedAt"])
    elapsed = observation["elapsedSeconds"]
    need(type(elapsed) is int and 0 <= elapsed <= 86400, "public.duration")
    return {
        "schema": "openclaw.gcp-rehearsal-observation.v1",
        "receiptId": uuid.uuid4().hex,
        **binding,
        **observation,
        # Even a successful rehearsal observation never authorizes promotion.
        "promotionAuthorized": False,
    }


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'daily':
        import gcp_daily_snapshot
        return gcp_daily_snapshot.main(sys.argv[2:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path, help="Private proposed plan JSON; never uploaded")
    args = parser.parse_args()
    try:
        plan = json.loads(args.plan.read_text())
        validate_plan(plan, datetime.now(timezone.utc))
    except (OSError, ValueError, TypeError, KeyError):
        # JSON parser/path exceptions can include sensitive input. Emit no values.
        print(json.dumps({"valid": False, "activationAuthorized": False,
                          "errors": ["gcp.plan.invalid"]}))
        return 1
    print(json.dumps({"valid": True, "activationAuthorized": False,
                      "implementation": "offline_contract_only"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

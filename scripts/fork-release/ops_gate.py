#!/usr/bin/env python3
"""Bind the existing private runtime-tools gate to a prepared OCI receipt."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from release import DIGEST, Refusal, manifest_at, need, receipt_at


def object_at(value, name):
    need(type(value) is dict, f"invalid {name} gate payload")
    return value


def validate_gate(payload, mode, receipt, source_sha):
    payload = object_at(payload, "root")
    need(type(payload.get("schemaVersion")) is int and payload["schemaVersion"] == 1 and
         payload.get("status") == "ok", "runtime-tools gate did not pass")
    image_id = receipt["configDigest"]
    need(DIGEST.fullmatch(image_id) is not None, "invalid approved image ID")
    if mode == "image":
        need(payload.get("mode") == "pre-deploy" and payload.get("imageId") == image_id,
             "pre-deploy gate image ID differs from OCI receipt")
        need(object_at(payload.get("cumulative"), "cumulative").get("revision") == source_sha,
             "pre-deploy gate source revision differs from manifest")
        need(type(payload.get("manifestSha256")) is str and
             re.fullmatch(r"[0-9a-f]{64}", payload["manifestSha256"]) is not None,
             "runtime-tools manifest is missing")
    else:
        need(payload.get("mode") == "post-deploy" and
             object_at(payload.get("contract"), "contract").get("imageId") == image_id,
             "running gateway image ID differs from OCI receipt")
        state = object_at(payload.get("state"), "state")
        need(state.get("running") is True and state.get("oomKilled") is False and
             state.get("restartCount") == 0 and state.get("health") == "healthy",
             "running gateway state failed admission")
        endpoints = object_at(payload.get("endpoints"), "endpoints")
        need(object_at(endpoints.get("healthz"), "healthz").get("ok") is True and
             object_at(endpoints.get("readyz"), "readyz").get("ready") is True,
             "gateway endpoints failed admission")
        preflight = object_at(object_at(payload.get("broker"), "broker").get(
            "captionBridgePushPreflight"), "broker preflight")
        need(preflight.get("status") == "ready" and
             preflight.get("selected_auth_actor") == "mergeguez[bot]" and
             preflight.get("write_performed") is False,
             "Caption Bridge capability preflight failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("image", "post"))
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--image-receipt", required=True, type=Path)
    parser.add_argument("--gate", required=True, type=Path)
    parser.add_argument("--candidate-image")
    parser.add_argument("--container")
    args = parser.parse_args()
    need(args.gate.is_absolute() and args.gate.is_file(), "reviewed gate path required")
    manifest, manifest_hash = manifest_at(args.manifest)
    receipt = receipt_at(args.image_receipt, manifest, manifest_hash)
    if args.mode == "image":
        need(args.candidate_image and not args.container, "candidate image required")
        command = [str(args.gate), "image", args.candidate_image, receipt["configDigest"]]
    else:
        need(args.container and not args.candidate_image, "running container required")
        command = [str(args.gate), "post", args.container]
    result = subprocess.run(command, capture_output=True, text=True, timeout=180, check=False)
    need(result.returncode == 0, "runtime-tools gate command failed")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise Refusal("runtime-tools gate returned invalid JSON") from error
    validate_gate(payload, args.mode, receipt, manifest["source"]["commit"])
    print(json.dumps({"schema": "openclaw.fork-release-ops-gate.v1",
                      "mode": args.mode, "sourceSha": manifest["source"]["commit"],
                      "indexDigest": receipt["indexDigest"],
                      "imageId": receipt["configDigest"],
                      "gateEvidenceSha256": hashlib.sha256(result.stdout.encode()).hexdigest()},
                     sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (Refusal, OSError, subprocess.TimeoutExpired, ValueError, KeyError) as error:
        print(f"Fork operations gate refused: {error}", file=sys.stderr)
        sys.exit(1)

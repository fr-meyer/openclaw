#!/usr/bin/env python3
"""Prepare canonical GCS V4 requests; signing is a separate explicit operation.

This owner creates no IAM grants, service-account keys or storage objects. Its
private capability is transport authority only, never image qualification.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from urllib.parse import parse_qsl, quote, urlsplit

import private_oci_transfer as transfer

IAM_HOST = "iamcredentials.googleapis.com"
GCLOUD_PATHS = ("/opt/homebrew/bin/gcloud", "/usr/local/bin/gcloud", "/usr/bin/gcloud")
LIMIT = 16 * 1024
need = transfer.need
Refusal = transfer.Refusal


def prepare(plan, operator, now):
    """Pure canonical blueprint. It contains no OAuth token or signed URL."""
    required = {"schema", "sourceSha", "workflowSha", "bucket", "object", "signer",
                "operator", "method", "expiresSeconds", "generation"}
    need(isinstance(plan, dict) and required <= set(plan) <= required | {"maximumBytes"}, "plan_fields")
    need(plan["schema"] == "openclaw.private-oci-signing-plan.v1", "plan_schema")
    need(plan["sourceSha"] == transfer.SOURCE, "source_binding")
    need(isinstance(plan["workflowSha"], str) and transfer.COMMIT.fullmatch(plan["workflowSha"]), "workflow_binding")
    need(isinstance(operator, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._%+-]{0,127}@[A-Za-z0-9.-]{1,190}", operator)
         and plan["operator"] == operator, "operator_binding")
    need(isinstance(plan["signer"], str) and re.fullmatch(
        r"[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com", plan["signer"]), "signer")
    need(isinstance(plan["bucket"], str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", plan["bucket"]), "bucket")
    name = plan["object"]
    need(isinstance(name, str) and len(name) <= 512 and re.fullmatch(r"[A-Za-z0-9._/-]+", name)
         and all(part not in ("", ".", "..") for part in name.split("/"))
         and name.startswith(f"oci-quarantine/v2026.10.5/{transfer.SOURCE}/"), "object_binding")
    method = plan["method"]
    need(method in ("PUT", "GET"), "method")
    expiry = plan["expiresSeconds"]
    need(type(expiry) is int and 1 <= expiry <= (3600 if method == "PUT" else 900), "expiry")
    headers = {"host": transfer.HOST}
    if method == "PUT":
        bound = plan.get("maximumBytes", transfer.MAX_BYTES)
        need(type(bound) is int and 1 <= bound <= transfer.MAX_BYTES, "size_bound")
        need(plan["generation"] is None, "put_generation")
        headers.update({"content-type": "application/octet-stream", "x-goog-content-length-range": f"1,{bound}",
                        "x-goog-if-generation-match": "0"})
    else:
        need("maximumBytes" not in plan and isinstance(plan["generation"], str)
             and transfer.DECIMAL.fullmatch(plan["generation"]), "get_generation")
    date = datetime.fromtimestamp(now, timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    scope = date[:8] + "/auto/storage/goog4_request"
    signed_headers = ";".join(sorted(headers))
    query = {"X-Goog-Algorithm": "GOOG4-RSA-SHA256", "X-Goog-Credential": plan["signer"] + "/" + scope,
             "X-Goog-Date": date, "X-Goog-Expires": str(expiry), "X-Goog-SignedHeaders": signed_headers}
    if method == "GET":
        query["generation"] = plan["generation"]
    canonical_query = "&".join(quote(key, safe="-_.~") + "=" + quote(value, safe="-_.~")
                               for key, value in sorted(query.items()))
    uri = "/" + plan["bucket"] + "/" + quote(name, safe="/-_.~")
    canonical_headers = "".join(key + ":" + headers[key] + "\n" for key in sorted(headers))
    canonical = "\n".join((method, uri, canonical_query, canonical_headers, signed_headers, "UNSIGNED-PAYLOAD"))
    canonical_hash = hashlib.sha256(canonical.encode()).hexdigest()
    string_to_sign = "\n".join(("GOOG4-RSA-SHA256", date, scope, canonical_hash))
    return {"schema": "openclaw.private-oci-signing-blueprint.v1", "method": method,
            "canonicalRequest": canonical, "canonicalRequestSha256": canonical_hash,
            "stringToSign": string_to_sign, "stringToSignSha256": hashlib.sha256(string_to_sign.encode()).hexdigest(),
            "headers": headers, "unsignedUrl": "https://" + transfer.HOST + uri + "?" + canonical_query,
            "expiresAt": int(datetime.strptime(date, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).timestamp()) + expiry,
            "signBlobPath": "/v1/projects/-/serviceAccounts/" + quote(plan["signer"], safe="") + ":signBlob",
            "signBlobBody": {"payload": base64.b64encode(string_to_sign.encode()).decode("ascii")}}


def load_plan(path, expected_hash):
    need(isinstance(expected_hash, str) and transfer.HEX.fullmatch(expected_hash), "plan_hash")
    raw = transfer.read_private(path, LIMIT)
    need(hashlib.sha256(raw).hexdigest() == expected_hash, "plan_hash_mismatch")
    try:
        return json.loads(raw, object_pairs_hook=transfer.unique_object)
    except (ValueError, UnicodeError):
        raise Refusal("invalid_plan") from None


def gcloud_executable():
    # Fixed installation roots; neither a caller-selected executable nor PATH
    # from the environment can substitute the credential acquisition program.
    for name in GCLOUD_PATHS:
        path = Path(name)
        if path.exists():
            path = path.resolve(strict=True)
            info = path.stat()
            need(stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.geteuid())
                 and not info.st_mode & 0o022 and os.access(path, os.X_OK), "gcloud_executable")
            return str(path)
    raise Refusal("gcloud_unavailable")


def token_environment(environ):
    result = {key: environ[key] for key in ("HOME", "TMPDIR", "CLOUDSDK_CONFIG") if key in environ}
    result.update({"PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8",
                   "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT": "", "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE": "",
                   "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE": "", "CLOUDSDK_CORE_LOG_HTTP": "false",
                   "CLOUDSDK_CORE_DISABLE_FILE_LOGGING": "true", "CLOUDSDK_CORE_DISABLE_PROMPTS": "true"})
    # Cloud SDK properties treat even empty environment overrides as present;
    # credential loading then ignores these falsey alternative-auth settings.
    return result


def sign(plan, plan_hash, operator, output, *, runner, factory, clock, environ):
    blueprint = prepare(plan, operator, clock())
    # Persist a separate immutable attempt before any credential/network call.
    # Failure leaves this marker and an empty/partial private output; no retry.
    transfer.durable_json(str(output) + ".attempt.json", {
        "schema": "openclaw.private-oci-signing-attempt.v1", "planSha256": plan_hash,
        "canonicalRequestSha256": blueprint["canonicalRequestSha256"], "productionAuthorized": False})
    connection = None
    with transfer.output_file(output) as destination:
        destination.flush()
        os.fsync(destination.fileno())
        command = [gcloud_executable(), "auth", "print-access-token", "--account", operator, "--quiet", "--verbosity=error"]
        result = runner(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=30,
                        env=token_environment(environ))
        need(result.returncode == 0 and isinstance(result.stdout, bytes) and len(result.stdout) <= LIMIT, "operator_token_failed")
        token = result.stdout.strip()
        need(re.fullmatch(rb"[A-Za-z0-9._~-]{16,16384}", token), "operator_token_failed")
        body = json.dumps(blueprint["signBlobBody"], separators=(",", ":")).encode()
        remaining = blueprint["expiresAt"] - clock()
        need(remaining > 0, "capability_expired")
        try:
            with transfer.network_deadline(min(30, remaining)):
                connection = factory(IAM_HOST, timeout=min(30, remaining))
                connection.request("POST", blueprint["signBlobPath"], body=body,
                                   headers={"Authorization": "Bearer " + token.decode("ascii"),
                                            "Content-Type": "application/json", "Content-Length": str(len(body))})
                response = connection.getresponse()
                need(response.status == 200 and transfer.response_header(response, "location") is None
                     and transfer.response_header(response, "content-encoding") in (None, "identity"), "sign_blob_refused")
                data = response.read(LIMIT + 1)
                need(len(data) <= LIMIT, "sign_blob_response_size")
        finally:
            token = b""
            if connection is not None:
                connection.close()
        try:
            signed = json.loads(data, object_pairs_hook=transfer.unique_object)
            need(isinstance(signed, dict) and set(signed) == {"keyId", "signedBlob"}, "sign_blob_response")
            need(isinstance(signed["keyId"], str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", signed["keyId"]), "sign_blob_response")
            signature = base64.b64decode(signed["signedBlob"], validate=True)
            need(len(signature) == 256 and base64.b64encode(signature).decode("ascii") == signed["signedBlob"], "sign_blob_signature")
        except (ValueError, TypeError):
            raise Refusal("sign_blob_response") from None
        need(clock() < blueprint["expiresAt"], "capability_expired")
        envelope = {"schema": "openclaw.private-oci-capability.v1", "sourceSha": plan["sourceSha"],
                    "workflowSha": plan["workflowSha"], "bucket": plan["bucket"], "object": plan["object"],
                    "signer": plan["signer"], "url": blueprint["unsignedUrl"] + "&X-Goog-Signature=" + signature.hex()}
        raw = (json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n").encode()
        destination.write(raw)
        destination.flush()
        os.fsync(destination.fileno())
    parent_fd = os.open(Path(output).absolute().parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return {"status": "signed", "planSha256": plan_hash, "capabilitySha256": hashlib.sha256(raw).hexdigest(),
            "canonicalRequestSha256": blueprint["canonicalRequestSha256"], "productionAuthorized": False}


def probe_capability(plan, operator, path, expected_hash, now):
    need(plan.get("method") == "PUT" and type(plan.get("maximumBytes")) is int
         and plan["maximumBytes"] == 8 and type(plan.get("expiresSeconds")) is int
         and 1 <= plan["expiresSeconds"] <= 120, "probe_plan_bounds")
    need(isinstance(expected_hash, str) and transfer.HEX.fullmatch(expected_hash), "capability_hash")
    raw = transfer.read_private(path, LIMIT)
    need(hashlib.sha256(raw).hexdigest() == expected_hash, "capability_hash_mismatch")
    try:
        envelope = json.loads(raw, object_pairs_hook=transfer.unique_object)
        need(isinstance(envelope, dict) and set(envelope) == {
            "schema", "sourceSha", "workflowSha", "bucket", "object", "signer", "url"}, "capability_fields")
        need(envelope["schema"] == "openclaw.private-oci-capability.v1"
             and all(envelope[key] == plan[key] for key in ("sourceSha", "workflowSha", "bucket", "object", "signer")), "capability_binding")
        url = envelope["url"]
        need(isinstance(url, str) and len(url) <= LIMIT, "capability_url")
        parsed = urlsplit(url)
        pairs = parse_qsl(parsed.query, strict_parsing=True, max_num_fields=7)
        query = dict(pairs)
        need(len(pairs) == len(query) and re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", query.get("X-Goog-Date", "")), "capability_query")
        issued = datetime.strptime(query["X-Goog-Date"], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).timestamp()
        blueprint = prepare(plan, operator, issued)
        signature = query.get("X-Goog-Signature", "")
        need(re.fullmatch(r"[0-9a-f]{512}", signature)
             and url == blueprint["unsignedUrl"] + "&X-Goog-Signature=" + signature, "capability_canonical_binding")
        need(issued <= now < blueprint["expiresAt"], "capability_expired")
    except (ValueError, TypeError, KeyError):
        raise Refusal("invalid_probe_capability") from None
    return parsed.path + "?" + parsed.query, blueprint


def probe(plan, plan_hash, operator, capability, capability_hash, output, *, factory, clock):
    """Four fixed nonsecret requests; stop on the first unexpected observation.

    This deliberately creates an eight-byte object on success. It never deletes
    that generation, retries, acquires credentials, signs or enables image upload.
    """
    target, blueprint = probe_capability(plan, operator, capability, capability_hash, clock())
    result = {"schema": "openclaw.private-oci-provider-probe.v1", "planSha256": plan_hash,
              "capabilitySha256": capability_hash, "sourceSha": plan["sourceSha"],
              "workflowSha": plan["workflowSha"], "canonicalRequestSha256": blueprint["canonicalRequestSha256"],
              "signingOwnerSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "httpStatuses": [], "generation": None, "status": "failed",
              "providerEnforcementVerified": False, "productionAuthorized": False}
    with transfer.output_file(output) as destination:
        transfer.durable_json(str(output) + ".attempt.json", {
            "schema": "openclaw.private-oci-provider-probe-attempt.v1", "planSha256": plan_hash,
            "capabilitySha256": capability_hash, "signingOwnerSha256": result["signingOwnerSha256"],
            "productionAuthorized": False})
        try:
            with transfer.network_deadline(blueprint["expiresAt"] - clock()):
                for body, bound, expected in ((b"OCIprobe!", "1,8", 400), (b"OCIprobe!", "1,9", 403),
                                              (b"OCIprobe", "1,8", 200), (b"OCIprobe", "1,8", 412)):
                    need(clock() < blueprint["expiresAt"], "capability_expired")
                    headers = dict(blueprint["headers"], **{"x-goog-content-length-range": bound,
                                                          "content-length": str(len(body))})
                    connection = None
                    try:
                        connection = factory(transfer.HOST, timeout=min(30, blueprint["expiresAt"] - clock()))
                        connection.request("PUT", target, body=body, headers=headers)
                        response = connection.getresponse()
                        need(clock() < blueprint["expiresAt"], "capability_expired")
                        need(type(response.status) is int and 100 <= response.status <= 599, "probe_response_status")
                        result["httpStatuses"].append(response.status)
                        need(transfer.response_header(response, "location") is None, "probe_redirect_refused")
                        generation = transfer.response_header(response, "x-goog-generation")
                        if response.status == 200 and isinstance(generation, str) and transfer.DECIMAL.fullmatch(generation):
                            result["generation"] = generation
                        need(response.status == expected, "probe_unexpected_status")
                        if expected == 200:
                            need(result["generation"] is not None, "probe_response_generation")
                    finally:
                        if connection is not None:
                            connection.close()
            result.update(status="passed", providerEnforcementVerified=True)
        except Exception as error:
            result["reason"] = str(error) if isinstance(error, Refusal) else "probe_io_error"
            result["outcome"] = "inspect_retained_attempt_and_object_before_any_retry"
        destination.write((json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode())
        destination.flush()
        os.fsync(destination.fileno())
    return result


def main(argv=None, *, runner=subprocess.run, connection_factory=http.client.HTTPSConnection,
         clock=time.time, environ=None):
    parser = transfer.PrivateArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", choices=("prepare", "sign", "probe"), default="prepare")
    parser.add_argument("--plan", required=True)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--output")
    parser.add_argument("--capability-file")
    parser.add_argument("--capability-sha256")
    try:
        args = parser.parse_args(argv)
        plan = load_plan(args.plan, args.plan_sha256)
        if args.action == "prepare":
            blueprint = prepare(plan, args.operator, clock())
            if args.output:
                transfer.durable_json(args.output, blueprint)
            result = {"status": "prepared", "planSha256": args.plan_sha256,
                      "canonicalRequestSha256": blueprint["canonicalRequestSha256"],
                      "stringToSignSha256": blueprint["stringToSignSha256"], "productionAuthorized": False}
        elif args.action == "sign":
            need(args.output is not None, "private_output_required")
            result = sign(plan, args.plan_sha256, args.operator, args.output, runner=runner,
                          factory=connection_factory, clock=clock, environ=os.environ if environ is None else environ)
        else:
            need(args.output and args.capability_file and args.capability_sha256, "probe_private_inputs_required")
            result = probe(plan, args.plan_sha256, args.operator, args.capability_file, args.capability_sha256,
                           args.output, factory=connection_factory, clock=clock)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 1 if result.get("status") == "failed" else 0
    except Exception as error:
        print(json.dumps({"status": "failed", "reason": str(error) if isinstance(error, Refusal) else "signing_io_error",
                          "outcome": "inspect_retained_attempt_before_any_retry", "productionAuthorized": False}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

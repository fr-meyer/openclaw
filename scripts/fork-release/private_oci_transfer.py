#!/usr/bin/env python3
"""One planned opaque OCI transfer; no signing, retries, extraction or admission.

Local URL checks constrain scope, not authenticate signatures. GCS must enforce
the signed headers. A PUT response is transfer evidence, never image qualification.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import stat
import time
from urllib.parse import parse_qsl, quote, urlsplit

SOURCE = "30786562e236aab6a924981c62aa61b920132c76"
HOST = "storage.googleapis.com"
MAX_BYTES = 2_147_483_648
CHUNK = 1024 * 1024
PLAN_LIMIT = 16 * 1024
URL_LIMIT = 16 * 1024
HEX = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
DECIMAL = re.compile(r"[1-9][0-9]{0,19}\Z")
PUT_HEADERS = "content-type;host;x-goog-content-length-range;x-goog-if-generation-match"


class Refusal(ValueError):
    pass


class PrivateArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # Argument mistakes must not echo capability strings or private paths.
        raise Refusal("invalid_arguments")


def need(value, code):
    if not value:
        raise Refusal(code)


def fingerprint(info):
    return tuple(getattr(info, "st_" + key) for key in
                 ("dev", "ino", "size", "mtime_ns", "ctime_ns", "mode", "uid", "nlink"))


def regular(path, limit, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= limit, "input_type_or_size")
        if private:
            need(stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.geteuid()
                 and info.st_nlink == 1, "private_file_required")
        return os.fdopen(fd, "rb"), info
    except BaseException:
        os.close(fd)
        raise


def read_private(path, limit):
    stream, before = regular(path, limit, True)
    with stream:
        data = stream.read(limit + 1)
        need(len(data) == before.st_size and fingerprint(os.fstat(stream.fileno())) == fingerprint(before),
             "input_changed")
    return data


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate_plan_field")
        result[key] = value
    return result


def load_plan(path, expected_hash):
    need(isinstance(expected_hash, str) and HEX.fullmatch(expected_hash), "plan_hash")
    data = read_private(path, PLAN_LIMIT)
    need(hashlib.sha256(data).hexdigest() == expected_hash, "plan_hash_mismatch")
    try:
        plan = json.loads(data, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError):
        raise Refusal("invalid_plan") from None
    fields = {"schema", "sourceSha", "toolingSha", "runId", "attempt", "archiveSha256",
              "archiveBytes", "bucket", "object", "signer", "generation"}
    need(isinstance(plan, dict) and set(plan) == fields, "plan_fields")
    need(plan["schema"] == "openclaw.private-oci-transfer-plan.v1", "plan_schema")
    need(plan["sourceSha"] == SOURCE, "source_binding")
    need(isinstance(plan["toolingSha"], str) and COMMIT.fullmatch(plan["toolingSha"]), "tooling_binding")
    need(all(isinstance(plan[key], str) and DECIMAL.fullmatch(plan[key]) for key in ("runId", "attempt")), "run_binding")
    need(isinstance(plan["archiveSha256"], str) and HEX.fullmatch(plan["archiveSha256"]), "archive_hash")
    need(type(plan["archiveBytes"]) is int and 1 <= plan["archiveBytes"] <= MAX_BYTES, "archive_size")
    need(isinstance(plan["bucket"], str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", plan["bucket"]), "bucket")
    name = plan["object"]
    need(isinstance(name, str) and len(name) <= 512 and re.fullmatch(r"[A-Za-z0-9._/-]+", name)
         and all(part not in ("", ".", "..") for part in name.split("/"))
         and name.startswith(f"oci-quarantine/v2026.10.5/{SOURCE}/")
         and name.endswith("/retained-oci.tar"), "object_binding")
    need(isinstance(plan["signer"], str) and re.fullmatch(
        r"[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com", plan["signer"]), "signer")
    need(plan["generation"] is None or (isinstance(plan["generation"], str)
         and DECIMAL.fullmatch(plan["generation"])), "generation")
    return plan


def capability(args, environ):
    if args.capability_file:
        data = read_private(args.capability_file, URL_LIMIT)
        try:
            value = data.decode("ascii")
        except UnicodeError:
            raise Refusal("invalid_capability") from None
    else:
        need(re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", args.capability_env or ""), "capability_environment_name")
        value = environ.get(args.capability_env, "")
    need(isinstance(value, str) and 0 < len(value) <= URL_LIMIT
         and all(32 < ord(char) < 127 for char in value), "invalid_capability")
    return value


def validate_capability(url, plan, method, now):
    try:
        parsed = urlsplit(url)
        pairs = parse_qsl(parsed.query, strict_parsing=True, max_num_fields=8)
    except ValueError:
        raise Refusal("invalid_capability") from None
    need(method in ("PUT", "GET"), "method")
    need(parsed.scheme == "https" and parsed.netloc == HOST and not parsed.fragment, "capability_host")
    expected_path = "/" + plan["bucket"] + "/" + quote(plan["object"], safe="/-_.~")
    need(parsed.path == expected_path, "capability_object")
    query = dict(pairs)
    required = {"X-Goog-Algorithm", "X-Goog-Credential", "X-Goog-Date", "X-Goog-Expires",
                "X-Goog-SignedHeaders", "X-Goog-Signature"}
    if method == "GET":
        required.add("generation")
    need(len(query) == len(pairs) and set(query) == required, "capability_query")
    need(all(raw == quote(key, safe="-_.~") + "=" + quote(value, safe="-_.~")
             for raw, (key, value) in zip(parsed.query.split("&"), pairs)), "capability_encoding")
    need(query["X-Goog-Algorithm"] == "GOOG4-RSA-SHA256", "signing_algorithm")
    need(re.fullmatch(r"[0-9a-f]{512}", query["X-Goog-Signature"]), "signing_signature")
    date = query["X-Goog-Date"]
    need(re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", date), "signing_date")
    try:
        issued = datetime.strptime(date, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        raise Refusal("signing_date") from None
    need(query["X-Goog-Credential"] == f"{plan['signer']}/{date[:8]}/auto/storage/goog4_request", "signing_scope")
    expires = query["X-Goog-Expires"]
    need(re.fullmatch(r"[1-9][0-9]{0,3}", expires) and int(expires) <= 3600, "signing_expiry")
    deadline = issued + int(expires)
    need(issued <= now < deadline, "capability_expired_or_future")
    headers = {"host": HOST}
    if method == "PUT":
        need(plan["generation"] is None, "put_generation")
        need(query["X-Goog-SignedHeaders"] == PUT_HEADERS, "signed_headers")
        headers.update({"content-type": "application/octet-stream", "x-goog-content-length-range": f"1,{MAX_BYTES}",
                        "x-goog-if-generation-match": "0", "content-length": str(plan["archiveBytes"])})
    else:
        need(plan["generation"] is not None and query["generation"] == plan["generation"], "get_generation")
        need(query["X-Goog-SignedHeaders"] == "host", "signed_headers")
    return parsed.path + "?" + parsed.query, headers, deadline


def output_file(path):
    path = Path(path).absolute()
    parent = path.parent
    need(parent.resolve() == parent, "output_directory_symlink")
    info = parent.stat()
    need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
         and info.st_uid == os.geteuid(), "private_directory_required")
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb")


def durable_json(path, value):
    with output_file(path) as stream:
        stream.write((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode())
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(Path(path).absolute().parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def hash_stream(stream, size):
    digest = hashlib.sha256()
    total = 0
    while chunk := stream.read(min(CHUNK, size - total + 1)):
        total += len(chunk)
        need(total <= size, "archive_size_mismatch")
        digest.update(chunk)
    need(total == size, "archive_size_mismatch")
    return digest.hexdigest()


def response_header(response, name):
    values = [value for key, value in response.getheaders() if key.lower() == name]
    need(len(values) <= 1, "response_headers")
    return values[0] if values else None


@contextmanager
def network_deadline(seconds):
    """Bound DNS/connect/headers/body together in this dedicated POSIX CLI.

    Socket inactivity timeouts alone do not bound a peer that dribbles headers.
    Do not replace another owner's active alarm or run inside a worker thread.
    """
    need(seconds > 0 and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), "deadline_unavailable")
    previous = signal.getsignal(signal.SIGALRM)

    def expired(signum, frame):
        raise Refusal("transfer_deadline")

    signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def transfer(plan, plan_hash, url, method, archive, receipt, factory, clock):
    target, headers, deadline = validate_capability(url, plan, method, clock())
    stream = None
    connection = None
    before = None
    attempted = False
    recorded = False
    result = {"schema": "openclaw.private-oci-transfer.v1", "productionAuthorized": False,
              "imageQualified": False, "sourceSha": plan["sourceSha"], "toolingSha": plan["toolingSha"],
              "runId": plan["runId"], "attempt": plan["attempt"], "planSha256": plan_hash,
              "archiveSha256": plan["archiveSha256"], "archiveBytes": plan["archiveBytes"],
              "objectIdentitySha256": hashlib.sha256((plan["bucket"] + "/" + plan["object"]).encode()).hexdigest(),
              "method": method, "status": "reserved", "remoteOutcome": "not_attempted"}
    try:
        need(not Path(receipt).exists(), "receipt_exists")
        if method == "PUT":
            stream, before = regular(archive, MAX_BYTES)
            need(before.st_size == plan["archiveBytes"], "archive_size_mismatch")
            need(hash_stream(stream, before.st_size) == plan["archiveSha256"], "archive_hash_mismatch")
            need(fingerprint(os.fstat(stream.fileno())) == fingerprint(before), "archive_changed")
            stream.seek(0)
        else:
            stream = output_file(archive)
        # Reserve before network. Preserve this marker and all partial output on
        # failure; neither a new receipt name nor this helper proves global once-only use.
        durable_json(str(receipt) + ".attempt.json", result)
        recorded = True
        target, headers, deadline = validate_capability(url, plan, method, clock())
        with network_deadline(deadline - clock()):
            attempted = True
            connection = factory(HOST, timeout=min(30, deadline - clock()))
            connection.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
            for key, value in headers.items():
                connection.putheader(key, value)
            connection.endheaders()
            if method == "PUT":
                sent = 0
                digest = hashlib.sha256()
                while chunk := stream.read(min(CHUNK, plan["archiveBytes"] - sent + 1)):
                    need(clock() < deadline, "transfer_deadline")
                    sent += len(chunk)
                    need(sent <= plan["archiveBytes"], "archive_size_mismatch")
                    digest.update(chunk)
                    connection.send(chunk)
                need(sent == plan["archiveBytes"] and digest.hexdigest() == plan["archiveSha256"]
                     and fingerprint(os.fstat(stream.fileno())) == fingerprint(before), "archive_changed")
            need(clock() < deadline, "transfer_deadline")
            response = connection.getresponse()
            need(clock() < deadline, "transfer_deadline")
            need(response.status in ((200, 201) if method == "PUT" else (200,)), "http_status_refused")
            need(response_header(response, "location") is None and response_header(response, "content-encoding") in (None, "identity"), "response_headers")
            generation = response_header(response, "x-goog-generation")
            need(isinstance(generation, str) and DECIMAL.fullmatch(generation), "response_generation")
            if method == "GET":
                need(generation == plan["generation"], "response_generation")
                need(response_header(response, "content-length") == str(plan["archiveBytes"]), "response_size")
                total = 0
                digest = hashlib.sha256()
                while True:
                    need(clock() < deadline, "transfer_deadline")
                    chunk = response.read(min(CHUNK, plan["archiveBytes"] - total + 1))
                    if not chunk:
                        break
                    total += len(chunk)
                    need(total <= plan["archiveBytes"], "response_size")
                    stream.write(chunk)
                    digest.update(chunk)
                need(total == plan["archiveBytes"] and digest.hexdigest() == plan["archiveSha256"], "download_hash_or_size")
                stream.flush()
                os.fsync(stream.fileno())
            result.update(status="transferred", generation=generation,
                          remoteOutcome="put_acknowledged" if method == "PUT" else "download_verified")
    except Exception as error:
        result.update(status="failed", reason=str(error) if isinstance(error, Refusal) else "transfer_io_error",
                      remoteOutcome="unknown" if attempted else "not_attempted")
    finally:
        if stream is not None:
            stream.close()
        if connection is not None:
            connection.close()
    if recorded:
        durable_json(receipt, result)
    need(recorded, result.get("reason", "reservation_failed"))
    return result


def main(argv=None, *, connection_factory=http.client.HTTPSConnection, clock=time.time, environ=None):
    parser = PrivateArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", choices=("validate", "put", "get"), default="validate")
    parser.add_argument("--method", choices=("PUT", "GET"), default="PUT", help="Direction for validate only")
    parser.add_argument("--plan", required=True)
    parser.add_argument("--plan-sha256", required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--capability-file")
    group.add_argument("--capability-env")
    parser.add_argument("--archive")
    parser.add_argument("--receipt")
    try:
        args = parser.parse_args(argv)
        plan = load_plan(args.plan, args.plan_sha256)
        url = capability(args, os.environ if environ is None else environ)
        method = args.method if args.action == "validate" else args.action.upper()
        validate_capability(url, plan, method, clock())
        if args.action == "validate":
            result = {"schema": "openclaw.private-oci-transfer-validation.v1", "status": "validated",
                      "planSha256": args.plan_sha256, "method": method, "productionAuthorized": False,
                      "signatureAuthenticated": False, "providerEnforcementVerified": False}
        else:
            need(args.archive and args.receipt, "archive_and_receipt_required")
            result = transfer(plan, args.plan_sha256, url, method, args.archive, args.receipt, connection_factory, clock)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0 if result["status"] in ("validated", "transferred") else 1
    except Exception as error:
        print(json.dumps({"status": "failed", "reason": str(error) if isinstance(error, Refusal) else "local_io_error",
                          "productionAuthorized": False}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

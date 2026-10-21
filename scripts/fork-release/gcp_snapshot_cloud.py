"""Narrow Compute REST transport and native snapshot/operation observations.

No I/O occurs at import. The lifecycle owner records intent before mutations and
retains these native responses; this adapter never retries or infers ownership.
"""
from datetime import datetime
import json
from pathlib import PurePosixPath
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import uuid

from release import Refusal, need

API = "https://compute.googleapis.com/compute/v1/"
SELF_LINK_BASES = (API, "https://www.googleapis.com/compute/v1/")
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_PAGES = 50
SEGMENT = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
NUMERIC_ID = re.compile(r"[1-9][0-9]{0,19}\Z")
TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})\Z")


def resource_path(value):
    """Compare documented Google selfLinks without accepting arbitrary origins."""
    need(type(value) is str, "snapshot.cloud.path")
    for base in SELF_LINK_BASES:
        if value.startswith(base):
            value = value[len(base):]
            break
    parts = value.split("/")
    need(len(parts) >= 4 and parts[0] == "projects" and
         all(SEGMENT.fullmatch(part) for part in parts), "snapshot.cloud.path")
    return value


def numeric_id(value):
    return (type(value) is str and NUMERIC_ID.fullmatch(value) is not None and
            int(value) <= (1 << 64) - 1)


def request_uuid(value):
    try:
        parsed = uuid.UUID(value) if type(value) is str else None
    except ValueError:
        parsed = None
    need(parsed is not None and parsed.int != 0 and str(parsed) == value,
         "snapshot.cloud.request_id")
    return value


def timestamp(value):
    need(type(value) is str and TIMESTAMP.fullmatch(value), "snapshot.cloud.timestamp")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise Refusal("snapshot.cloud.timestamp") from None


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "snapshot.cloud.json_duplicate")
        result[key] = value
    return result


def invalid_json_constant(_):
    raise Refusal("snapshot.cloud.json_constant")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Refusal("snapshot.cloud.redirect")


class Cloud:
    def __init__(self, gcloud="/usr/bin/gcloud"):
        need(type(gcloud) is str and PurePosixPath(gcloud).is_absolute() and
             ".." not in PurePosixPath(gcloud).parts, "snapshot.cloud.gcloud_path")
        self.gcloud = gcloud

    def _token(self):
        try:
            result = subprocess.run(
                [self.gcloud, "auth", "print-access-token", "--quiet", "--verbosity=none"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=30, check=False,
            )
            need(result.returncode == 0 and 0 < len(result.stdout) <= 16384,
                 "snapshot.cloud.auth")
            token = result.stdout.decode("ascii").strip()
            need(re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", token), "snapshot.cloud.auth")
            return token
        except (OSError, subprocess.SubprocessError, UnicodeError):
            raise Refusal("snapshot.cloud.auth") from None

    def request(self, method, path, body=None, query=None, allow_missing=False):
        need(type(method) is str and method in ("GET", "POST", "DELETE"), "snapshot.cloud.method")
        # Callers supply relative paths, so credentials can only reach this host.
        need(type(path) is str and path.startswith("projects/") and
             resource_path(path) == path, "snapshot.cloud.path")
        need(type(allow_missing) is bool, "snapshot.cloud.missing")
        need(query is None or type(query) is dict, "snapshot.cloud.query")
        parameters = {}
        for key, value in (query or {}).items():
            need(type(key) is str and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", key) and
                 type(value) in (str, int, bool), "snapshot.cloud.query")
            if key == "requestId":
                request_uuid(value)
            parameters[key] = str(value).lower() if type(value) is bool else str(value)
        need(method == "GET" or "requestId" in parameters, "snapshot.cloud.request_id")
        need(method == "POST" or body is None, "snapshot.cloud.body")
        try:
            data = None if body is None else json.dumps(
                body, sort_keys=True, separators=(",", ":"), allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, RecursionError):
            raise Refusal("snapshot.cloud.body") from None
        need(data is None or (type(body) is dict and len(data) <= MAX_JSON_BYTES),
             "snapshot.cloud.body")
        url = API + path
        if parameters:
            url += "?" + urllib.parse.urlencode(parameters)
        request = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": "Bearer " + self._token(), "Accept": "application/json",
            "Content-Type": "application/json",
        })
        # Do not forward authorization across redirects or use ambient proxies.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        try:
            with opener.open(request, timeout=60) as response:
                need(200 <= response.status < 300, "snapshot.cloud.http_status")
                raw = response.read(MAX_JSON_BYTES + 1)
            need(len(raw) <= MAX_JSON_BYTES, "snapshot.cloud.response_limit")
            value = json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid_json_constant)
            need(type(value) is dict, "snapshot.cloud.response_shape")
            return value
        except urllib.error.HTTPError as error:
            code = error.code
            error.close()
            if code == 404 and allow_missing:
                return None
            raise Refusal("snapshot.cloud.http_" + str(code)) from None
        except (OSError, urllib.error.URLError, ValueError, RecursionError):
            # Native error bodies, URLs and credential subprocess output remain private.
            raise Refusal("snapshot.cloud.response_unknown") from None


def select_snapshot(rows, source_disk, policy_url, now, max_age_seconds):
    """Select a fresh scheduled native snapshot; this does not own/create a disk.

    The lifecycle owner verifies the observed resource policy has a daily
    schedule, and pins its numeric ID against sourceSnapshotSchedulePolicyId.
    """
    need(type(rows) is list and len(rows) <= 25000, "snapshot.select.rows")
    need(type(source_disk) is dict and numeric_id(source_disk.get("id")),
         "snapshot.select.source")
    source = resource_path(source_disk.get("selfLink"))
    policy = resource_path(policy_url)
    need(re.fullmatch(r"projects/[^/]+/zones/[^/]+/disks/[^/]+", source) and
         re.fullmatch(r"projects/[^/]+/regions/[^/]+/resourcePolicies/[^/]+", policy),
         "snapshot.select.resources")
    need(isinstance(now, datetime) and now.utcoffset() is not None and
         type(max_age_seconds) is int and max_age_seconds > 0, "snapshot.select.age")
    candidates, identities = [], {}
    for row in rows:
        need(type(row) is dict, "snapshot.select.row")
        if (row.get("status") != "READY" or row.get("autoCreated") is not True or
                row.get("sourceDiskId") != source_disk["id"]):
            continue
        if (resource_path(row.get("sourceDisk")) != source or
                resource_path(row.get("sourceSnapshotSchedulePolicy")) != policy):
            continue
        need(numeric_id(row.get("id")) and numeric_id(row.get("sourceSnapshotSchedulePolicyId")),
             "snapshot.select.identity")
        link = resource_path(row.get("selfLink"))
        need(re.fullmatch(r"projects/[^/]+/global/snapshots/[^/]+", link) and
             link.rsplit("/", 1)[-1] == row.get("name"), "snapshot.select.link")
        created = timestamp(row.get("creationTimestamp"))
        if not 0 <= (now - created).total_seconds() <= max_age_seconds:
            continue
        need(row["id"] not in identities or identities[row["id"]] == row,
             "snapshot.select.duplicate")
        identities[row["id"]] = row
        candidates.append((created, int(row["id"]), row["name"], row))
    need(candidates, "snapshot.select.none_ready")
    return max(candidates, key=lambda item: item[:3])[3]


def operation_receipt(op, request_id, operation_type, target_link, expected_target_id=None, allow_failed=False):
    """Validate a native result; failures remain explicit when requested."""
    request_uuid(request_id)
    need(type(operation_type) is str and SEGMENT.fullmatch(operation_type),
         "snapshot.operation.type")
    target = resource_path(target_link)
    need(type(op) is dict and op.get("kind") == "compute#operation" and
         numeric_id(op.get("id")) and type(op.get("name")) is str and
         SEGMENT.fullmatch(op["name"]), "snapshot.operation.identity")
    need(op.get("clientOperationId") == request_id and
         op.get("operationType") == operation_type and
         resource_path(op.get("targetLink")) == target, "snapshot.operation.binding")
    failed = bool(op.get("error") or op.get("httpErrorStatusCode") or op.get("httpErrorMessage"))
    absent_failed_insert = allow_failed and failed and operation_type == "insert" and expected_target_id is None and "targetId" not in op
    need(absent_failed_insert or (numeric_id(op.get("targetId")) and (expected_target_id is None or
         (numeric_id(expected_target_id) and op["targetId"] == expected_target_id))),
         "snapshot.operation.target_id")
    need(op.get("status") == "DONE", "snapshot.operation.not_done")
    need(allow_failed or not failed, "snapshot.operation.failed")
    need("warnings" not in op or type(op["warnings"]) is list, "snapshot.operation.warnings")
    return op


def inspect_operation(cloud, project, zone, request_id, operation_name=None):
    """Return one matching native operation, or None meaning outcome UNKNOWN.

    Completed operations are retained for only >=1 hour. Absence never proves
    that a mutation was not executed and must not cause a fresh mutation UUID.
    """
    request_uuid(request_id)
    need(type(project) is str and SEGMENT.fullmatch(project) and
         type(zone) is str and SEGMENT.fullmatch(zone), "snapshot.operation.scope")
    path = f"projects/{project}/zones/{zone}/operations"
    if operation_name is not None:
        need(type(operation_name) is str and SEGMENT.fullmatch(operation_name),
             "snapshot.operation.name")
        observed = cloud.request("GET", path + "/" + operation_name, allow_missing=True)
        if observed is not None:
            need(type(observed) is dict and observed.get("clientOperationId") == request_id,
                 "snapshot.operation.request_mismatch")
            return observed
    matches, tokens, page = {}, set(), None
    for _ in range(MAX_PAGES):
        query = {"filter": f'clientOperationId = "{request_id}"', "maxResults": 500}
        if page is not None:
            query["pageToken"] = page
        response = cloud.request("GET", path, query=query)
        need(type(response) is dict and type(response.get("items", [])) is list and
             len(response.get("items", [])) <= 500,
             "snapshot.operation.list")
        for op in response.get("items", []):
            need(type(op) is dict and op.get("clientOperationId") == request_id and
                 numeric_id(op.get("id")), "snapshot.operation.list_binding")
            prior = matches.get(op["id"])
            need(prior is None or prior.get("name") == op.get("name"),
                 "snapshot.operation.ambiguous")
            matches[op["id"]] = op
        need(len(matches) <= 1, "snapshot.operation.ambiguous")
        page = response.get("nextPageToken")
        if not page:
            return next(iter(matches.values()), None)
        need(type(page) is str and len(page) <= 8192 and page not in tokens,
             "snapshot.operation.pagination")
        tokens.add(page)
    raise Refusal("snapshot.operation.page_limit")

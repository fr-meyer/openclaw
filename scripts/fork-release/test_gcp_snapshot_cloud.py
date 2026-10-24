"""Synthetic REST boundary tests; no credentials, cloud or subprocess execution."""
import copy
from datetime import datetime, timezone
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import urllib.error

import gcp_snapshot_cloud as cloud
from release import Refusal

PROJECT = "synthetic-project"
ZONE = "asia-northeast3-b"
SCOPE = f"projects/{PROJECT}/zones/{ZONE}"
SOURCE = {"id": "12345678901234567890", "selfLink": cloud.API + SCOPE + "/disks/production-data"}
POLICY = cloud.API + f"projects/{PROJECT}/regions/asia-northeast3/resourcePolicies/daily"
REQUEST = "12345678-1234-4234-8234-123456789abc"
TARGET = cloud.API + SCOPE + "/disks/unique-trial"
CANARY = "SYNTHETIC_PRIVATE_CANARY"


def snapshot(identity="9223372036854775808", created="2026-10-21T01:00:00Z", **changes):
    name = "daily-" + identity
    return {
        "id": identity, "name": name,
        "selfLink": cloud.API + f"projects/{PROJECT}/global/snapshots/" + name,
        "creationTimestamp": created, "status": "READY", "autoCreated": True,
        "sourceDiskId": SOURCE["id"], "sourceDisk": SOURCE["selfLink"],
        "sourceSnapshotSchedulePolicy": POLICY, "sourceSnapshotSchedulePolicyId": "123",
        **changes,
    }


def operation(**changes):
    return {
        "kind": "compute#operation", "id": "9876543210987654321", "name": "operation-123",
        "clientOperationId": REQUEST, "operationType": "insert", "targetLink": TARGET,
        "targetId": "18446744073709551615", "status": "DONE", **changes,
    }


class Response(io.BytesIO):
    status = 200


class CloudTests(unittest.TestCase):
    def setUp(self):
        self.auth = patch.object(cloud.subprocess, "run", return_value=SimpleNamespace(
            returncode=0, stdout=(CANARY + "\n").encode(),
        )).start()
        self.addCleanup(patch.stopall)
        self.opener = Mock()
        self.make_opener = patch.object(cloud.urllib.request, "build_opener", return_value=self.opener).start()
        self.client = cloud.Cloud()

    def reply(self, value):
        self.opener.open.return_value = Response(json.dumps(value).encode())

    def test_request_fixed_origin_token_header_and_native_body(self):
        expected = operation()
        self.reply(expected)
        body = {"name": "unique-trial", "sourceSnapshot": snapshot()["selfLink"]}
        actual = self.client.request("POST", SCOPE + "/disks", body, {"requestId": REQUEST})
        self.assertEqual(actual, expected)
        req = self.opener.open.call_args.args[0]
        self.assertEqual(req.full_url, cloud.API + SCOPE + "/disks?requestId=" + REQUEST)
        self.assertEqual(req.get_header("Authorization"), "Bearer " + CANARY)
        self.assertEqual(json.loads(req.data), body)
        self.assertEqual(self.auth.call_args.args[0],
                         ["/usr/bin/gcloud", "auth", "print-access-token", "--quiet", "--verbosity=none"])
        self.assertEqual(self.auth.call_args.kwargs["stderr"], cloud.subprocess.DEVNULL)
        self.assertNotIn(CANARY, repr(self.auth.call_args))
        self.assertEqual(self.opener.open.call_count, 1)
        self.assertEqual(self.make_opener.call_args.args[0].proxies, {})
        self.assertIsInstance(self.make_opener.call_args.args[1], cloud.NoRedirect)

    def test_rejects_unsafe_paths_and_zero_request_before_auth(self):
        paths = ["https://example.invalid/private", "/" + SCOPE, SCOPE + "/../disks", SCOPE + "%2fdisks",
                 SCOPE + "/disks?access_token=secret", SCOPE + "/disks#fragment"]
        for value in paths:
            with self.subTest(path=value), self.assertRaises(Refusal):
                self.client.request("GET", value)
        with self.assertRaises(Refusal):
            self.client.request("POST", SCOPE + "/disks", {},
                                {"requestId": "00000000-0000-0000-0000-000000000000"})
        for method in ("POST", "DELETE"):
            with self.subTest(method=method), self.assertRaises(Refusal):
                self.client.request(method, SCOPE + "/disks/unique-trial")
        self.auth.assert_not_called()
        self.opener.open.assert_not_called()

    def test_http_errors_never_retry_or_echo_private_body(self):
        for status in (401, 403, 409, 429, 500, 503):
            with self.subTest(status=status):
                self.opener.open.reset_mock()
                self.opener.open.side_effect = urllib.error.HTTPError(
                    cloud.API + SCOPE + "/disks", status, CANARY, {}, io.BytesIO(CANARY.encode()),
                )
                with self.assertRaisesRegex(Refusal, "^snapshot.cloud.http_" + str(status) + "$"):
                    self.client.request("POST", SCOPE + "/disks", {}, {"requestId": REQUEST})
                self.assertEqual(self.opener.open.call_count, 1)

    def test_only_explicit_404_returns_none(self):
        def missing(*args, **kwargs):
            raise urllib.error.HTTPError(TARGET, 404, CANARY, {}, io.BytesIO(CANARY.encode()))
        self.opener.open.side_effect = missing
        self.assertIsNone(self.client.request("GET", SCOPE + "/disks/unique-trial", allow_missing=True))
        with self.assertRaisesRegex(Refusal, "^snapshot.cloud.http_404$"):
            self.client.request("GET", SCOPE + "/disks/unique-trial")

    def test_redirect_transport_and_auth_failures_do_not_leak_or_retry(self):
        with self.assertRaisesRegex(Refusal, "^snapshot.cloud.redirect$"):
            cloud.NoRedirect().redirect_request(None, None, 302, CANARY, {}, "https://example.invalid")
        self.opener.open.side_effect = urllib.error.URLError(CANARY)
        with self.assertRaisesRegex(Refusal, "^snapshot.cloud.response_unknown$"):
            self.client.request("POST", SCOPE + "/disks", {}, {"requestId": REQUEST})
        self.assertEqual(self.opener.open.call_count, 1)
        self.opener.open.reset_mock()
        self.auth.side_effect = cloud.subprocess.TimeoutExpired("gcloud", 30, output=CANARY.encode())
        with self.assertRaisesRegex(Refusal, "^snapshot.cloud.auth$"):
            self.client.request("GET", SCOPE + "/disks/unique-trial")
        self.opener.open.assert_not_called()

    def test_bounded_and_strict_json(self):
        for raw in (b"[1]", b'{"id":1,"id":2}', b'{"secret":NaN}', CANARY.encode(), b"x" * 65):
            with self.subTest(raw=raw):
                self.opener.open.return_value = Response(raw)
                with patch.object(cloud, "MAX_JSON_BYTES", 64), self.assertRaises(Refusal) as raised:
                    self.client.request("GET", SCOPE + "/disks/unique-trial")
                self.assertNotIn(CANARY, str(raised.exception))


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 21, 2, tzinfo=timezone.utc)

    def test_newest_fresh_ready_scheduled_snapshot_has_exact_source_incarnation(self):
        chosen = snapshot()
        rows = [
            snapshot("1", "2026-10-20T23:00:00Z"),
            snapshot("2", "2026-10-21T01:59:00Z", status="UPLOADING"),
            snapshot("3", "2026-10-21T01:59:00Z", autoCreated=False),
            snapshot("4", "2026-10-21T01:59:00Z", sourceDiskId="456"),
            snapshot("5", "2026-10-21T01:59:00Z", sourceSnapshotSchedulePolicy=POLICY + "-other"),
            snapshot("6", "2026-10-21T02:00:01Z"), chosen,
        ]
        self.assertIs(cloud.select_snapshot(rows, SOURCE, POLICY, self.now, 7200), chosen)
        self.assertIs(cloud.select_snapshot(list(reversed(rows)), SOURCE, POLICY, self.now, 7200), chosen)
        with self.assertRaisesRegex(Refusal, "snapshot.select.none_ready"):
            cloud.select_snapshot([chosen], SOURCE, POLICY, self.now, 3599)

    def test_snapshot_ties_ids_host_aliases_and_invalid_provenance(self):
        older, newer = snapshot(), snapshot("9223372036854775809")
        newer["sourceDisk"] = newer["sourceDisk"].replace(cloud.API, cloud.SELF_LINK_BASES[1])
        self.assertIs(cloud.select_snapshot([newer, older], SOURCE, POLICY, self.now, 3600), newer)
        for field, value in (("id", 123), ("id", "18446744073709551616"),
                             ("sourceSnapshotSchedulePolicyId", ""), ("creationTimestamp", "yesterday"),
                             ("selfLink", "https://example.invalid/snapshot")):
            with self.subTest(field=field), self.assertRaises(Refusal):
                cloud.select_snapshot([{**older, field: value}], SOURCE, POLICY, self.now, 3600)
        with self.assertRaisesRegex(Refusal, "snapshot.select.duplicate"):
            cloud.select_snapshot([older, {**older, "diskSizeGb": "999"}], SOURCE, POLICY, self.now, 3600)

    def test_native_operation_done_binding_and_nonfatal_warnings(self):
        op = operation(warnings=[{"code": "SYNTHETIC_WARNING", "message": CANARY}])
        self.assertIs(cloud.operation_receipt(op, REQUEST, "insert", TARGET, op["targetId"]), op)
        for field, value in (("status", "RUNNING"), ("error", {"errors": [{"message": CANARY}]}),
                             ("httpErrorStatusCode", 500), ("targetId", "42"),
                             ("targetLink", TARGET + "-other"), ("clientOperationId", "wrong"),
                             ("operationType", "delete")):
            with self.subTest(field=field), self.assertRaises(Refusal) as raised:
                cloud.operation_receipt({**op, field: value}, REQUEST, "insert", TARGET, op["targetId"])
            self.assertNotIn(CANARY, str(raised.exception))

    def test_lost_reply_operation_lookup_paginates_and_none_means_unknown(self):
        op = operation(status="RUNNING")
        client = Mock()
        client.request.side_effect = [None, {"nextPageToken": "second"}, {"items": [op]}]
        self.assertIs(cloud.inspect_operation(client, PROJECT, ZONE, REQUEST, "operation-123"), op)
        calls = client.request.call_args_list
        self.assertEqual(calls[0].kwargs, {"allow_missing": True})
        self.assertEqual(calls[1].kwargs["query"]["filter"], f'clientOperationId = "{REQUEST}"')
        self.assertEqual(calls[2].kwargs["query"]["pageToken"], "second")
        self.assertTrue(all(call.args[0] == "GET" for call in calls))
        client.request.side_effect = [{"items": []}]
        self.assertIsNone(cloud.inspect_operation(client, PROJECT, ZONE, REQUEST))

    def test_lookup_refuses_ambiguous_mismatched_or_looping_native_evidence(self):
        client = Mock()
        cases = [
            [{"items": [operation(), operation(id="123")]}],
            [{"items": [operation(clientOperationId="wrong")]}],
            [{"nextPageToken": "loop"}, {"nextPageToken": "loop"}],
        ]
        for responses in cases:
            with self.subTest(responses=responses), self.assertRaises(Refusal):
                client.request.side_effect = copy.deepcopy(responses)
                cloud.inspect_operation(client, PROJECT, ZONE, REQUEST)
        client.request.side_effect = [operation(clientOperationId="wrong")]
        with self.assertRaisesRegex(Refusal, "snapshot.operation.request_mismatch"):
            cloud.inspect_operation(client, PROJECT, ZONE, REQUEST, "operation-123")


if __name__ == "__main__":
    unittest.main()

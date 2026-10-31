"""Fixed public tag/tiny Git fixtures, never a full-source or native CI pass."""
import ast
import base64
from contextlib import nullcontext
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
PUBLIC_COMMIT_B64 = "dHJlZSA4ZTg3ZWEwNDFkODhmNzJiNzdkODM4MDZiOWFkMDVhYTRmMTc2ZDU5CnBhcmVudCA0ZTM4NDExNTYyMTBkMzBlZTJjNDVkMDY3NmY1YjU1MWI1NjNlZDBlCmF1dGhvciBEYWxsaW4gUm9tbmV5IDxkYWxsaW5yb21uZXlAZ21haWwuY29tPiAxNzkzMDQ1NzYzIC0wNzAwCmNvbW1pdHRlciBEYWxsaW4gUm9tbmV5IDxkYWxsaW5yb21uZXlAZ21haWwuY29tPiAxNzkzMDc0NDUzIC0wNzAwCmdwZ3NpZyAtLS0tLUJFR0lOIFBHUCBTSUdOQVRVUkUtLS0tLQogCiBpUUpQQkFBQkNBQTVGaUVFMzRYSkNML1ZZY0JBSURFYlR2djV6QUhaY1pFRkFtcmdKUlViRklBQUFBQUFCQUFPCiBiV0Z1ZFRJc01pNDFLekV1TVRJc01Dd3pBQW9KRUU3Nytjd0IyWEdSSFlZUC8xZXV1Nm0wS1lyT3RLb2Z6eG84CiBSV2h1RGFFWGpKRmI2M0hucVFIU1FHMGtqRFgycXBEZ1dqRUJJRHAyTmtqWXg5L3gybDBBejZwY09oekFRUDlJCiBxN0w3UGZwNHM4NlpZaElpYk1ZVnZra1lOMzBxeHJBRDl6RERYYm42TGkvUmF4cmNVbVBzZ3dWTXNmeGRDSzVzCiB0MTFOelViN1FRMFIyNENBajZLRUQybWZBdm5KbDl1NGhzYVBydkJwdjNITFBlSGJjd3lWNjFPeHVrV2V1Z2tjCiBDbWd3dmt4RWRKbW5GVGRPKzRTWHRETFFHREVKTVg0U0lidmtpVTFEMVR2b25VVUxMZy9PWFlNZDlWQVNIWDlSCiBSK2lxOFBYbGZhTFdCOXlibTdWL3J4SzlyeTZDN0w4K1V4ZjVXZEs0a0UybWVqaTk0TlNBZWdXZkpObU9CMjZGCiBYb2ptcXp1UDhWcVJkc1R2WGh5U2pWNmplVndaMitoRzhOYW93cVZIYkI1UmxQYStZTHQzZDlRMDVDT04rVGpECiBpRktqak03bkJubXFrd3djdFlGMk5CNGNobjVZWnFTNmp2eE5XVXJEaGpRanFZeXoybG5XK3plWVlCV3RBbWVjCiBkV0xqSTdKVjN4WUxxbVpYdTlRenJIei8yYXYyZ3ZSNjBXaXdhSWptaTgzbUpkZTQ0dFY1NzYzZDhyN0VhOVhVCiBEa1JJMGpiNlRLMDFyZnNDS2dFd0tNU2llSnZKNWRFYlYwQlMwRVNpb0FYemNDWkttOHdkVy9GazFNTGxrMUpxCiBiOEhBWjBLRENJZW14Yll1VE5ZbTdkWVlHRXE3NzJZMTJ2QnJCcDdNbDV4TG1XQnltOEgzK0JtZ29tTlViTC84CiB0LzlOZjM5WUdWNE1WZ3VuNHNWWDVDUU8KID0raGJuCiAtLS0tLUVORCBQR1AgU0lHTkFUVVJFLS0tLS0KCmRvY3MoY2hhbmdlbG9nKTogcHJlcGFyZSAyMDI2LjEwLjggbm90ZXMK"


class Refusal(ValueError):
    pass


def owner():
    tree = ast.parse((HERE / "source_validation_v108.py").read_text())
    functions = {"reuse_upstream_tag_v7", "fetch_closure", "code_binding", "commands"}
    nodes = [n for n in tree.body if
        isinstance(n, ast.FunctionDef) and n.name in functions or
        isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id.startswith("R7_TAG_")
                                         for t in n.targets)]
    def need(ok, code):
        if not ok:
            raise Refusal(code)
    def validate(request, pins):
        # The unchanged closed operational validator is separately maintained.
        # These tiny fixtures exercise only this new helper's boundary and Git ABI.
        need(request.get("sourceSha") == pins["sourceSha"] and
             request.get("sourceTree") == pins["sourceTree"], "unchanged.validator")
    scope = dict(Path=Path, hashlib=hashlib, os=os, subprocess=subprocess, tempfile=tempfile, need=need,
        _r7_need=need, validate_request_v7=validate, R7_STAGE_PINS={},
        R7_SCHEMA="openclaw.fork-source-validation-request.v7", R7_POLICY="re2js-security-followup-v1",
        R8_SCHEMA="openclaw.fork-source-validation-request.v8",
        V5_SCHEMA="openclaw.fork-source-validation-request.v5",
        V6_SCHEMA="openclaw.fork-source-validation-request.v6",
        V4_SCHEMA="openclaw.fork-source-validation-request.v4")
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(HERE / "source_validation_v108.py"), "exec"), scope)
    return types.SimpleNamespace(**scope), scope


class TagReuse(unittest.TestCase):
    def setUp(self):
        self.d, self.g = owner()
        self.temp = tempfile.TemporaryDirectory(prefix="v108-public-tag-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(strict=True)
        self.pipeline, self.source = self.root / "pipeline", self.root / "source"
        self.fixture = self.pipeline / self.d.R7_TAG_FIXTURE
        self.fixture.parent.mkdir(parents=True)
        self.fixture.write_bytes((HERE / self.d.R7_TAG_FIXTURE.removeprefix("scripts/fork-release/")).read_bytes())
        self.env = {"PATH": "/usr/bin:/bin", "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1",
                    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
        self.git("init", "--quiet", str(self.source), root=self.root)
        tree = self.git("hash-object", "-t", "tree", "-w", "--stdin", data=b"").strip()
        commit = (b"tree " + tree + b"\nauthor Synthetic <test@example.invalid> 1 +0000\n"
                  b"committer Synthetic <test@example.invalid> 1 +0000\n\nTiny test only\n")
        head = self.git("hash-object", "-t", "commit", "-w", "--stdin", data=commit).strip()
        # Detached scratch HEAD; no operational repository or project branch.
        self.git("update-ref", "--no-deref", "HEAD", head.decode())
        public_commit = base64.b64decode(PUBLIC_COMMIT_B64, validate=True)
        self.assertEqual(hashlib.sha1(b"commit " + str(len(public_commit)).encode() + b"\0" + public_commit).hexdigest(),
                         self.d.R7_TAG_COMMIT)
        self.assertEqual(self.git("hash-object", "-t", "commit", "-w", "--stdin", data=public_commit).strip().decode(),
                         self.d.R7_TAG_COMMIT)
        self.request = dict(schema=self.d.R7_SCHEMA, profilePolicy=self.d.R7_POLICY, stageRound=2,
                            sourceSha=head.decode(), sourceTree=tree.decode())
        self.g["R7_STAGE_PINS"] = {k: self.request[k] for k in ("sourceSha", "sourceTree")}
        self.inventory = {"upstream": dict(tag=self.d.R7_TAG_NAME, tagObject=self.d.R7_TAG_OBJECT,
                                          commit=self.d.R7_TAG_COMMIT)}
        self.context = dict(request=self.request, profile="types-tests", deadlineEpoch=1)
        self.calls = []
        self.g["phase_process"] = self.phase

    def git(self, *args, root=None, data=None):
        argv = ["/usr/bin/git", "--no-replace-objects", "-c", "protocol.allow=never",
                "-c", "core.hooksPath=/dev/null", "-c", "maintenance.auto=false", "-c", "gc.auto=0"]
        if root is not None:
            argv += ["-C", str(root)]
        elif hasattr(self, "source"):
            argv += ["-C", str(self.source)]
        child = subprocess.run([*argv, *args], input=data, env=self.env, capture_output=True, timeout=5)
        if child.returncode:
            raise subprocess.CalledProcessError(child.returncode, child.args, child.stdout, child.stderr)
        return child.stdout

    def inspect(self, root, *args):
        return self.git(*args, root=root).strip()

    def phase(self, argv, cwd, env, context, name, ordinal):
        self.calls.append((list(argv), name, ordinal))
        self.assertEqual(cwd, self.source)
        self.assertEqual(env, self.env)
        self.assertIs(context, self.context)
        child = subprocess.run(["/usr/bin/git", *argv[1:]], cwd=cwd, env=env,
                               capture_output=True, timeout=5)
        child.timed_out = False
        return child

    def run_reuse(self, inspect=None):
        return self.d.reuse_upstream_tag_v7(self.pipeline, self.source, self.request, self.inventory,
                                          inspect or self.inspect, self.env, self.context)

    def refuses(self, code):
        return self.assertRaisesRegex(Refusal, code.replace(".", r"\."))

    def test_actual_raw_identity_and_positive_tiny_tag_peel(self):
        raw = self.fixture.read_bytes()
        self.assertEqual(len(raw), 1028)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), self.d.R7_TAG_SHA256)
        before = (self.inspect(self.source, "rev-parse", "HEAD"), self.inspect(self.source, "rev-parse", "HEAD^{tree}"))
        self.run_reuse()
        self.assertEqual(self.inspect(self.source, "rev-parse", self.d.R7_TAG_REF), self.d.R7_TAG_OBJECT.encode())
        self.assertEqual(self.inspect(self.source, "rev-parse", self.d.R7_TAG_REF + "^{commit}"), self.d.R7_TAG_COMMIT.encode())
        self.assertEqual(before, (self.inspect(self.source, "rev-parse", "HEAD"), self.inspect(self.source, "rev-parse", "HEAD^{tree}")))
        self.assertEqual(self.inspect(self.source, "status", "--porcelain=v1", "--untracked-files=all"), b"")
        self.assertEqual([c[1:] for c in self.calls], [("source-tag-reuse", 1), ("source-tag-reuse", 2)])
        self.assertTrue(all("protocol.allow=never" in c[0] and "core.hooksPath=/dev/null" in c[0]
                            and "fetch" not in c[0] for c in self.calls))

    def test_rejects_other_contexts_before_writes(self):
        for key, value in [("schema", self.d.V6_SCHEMA), ("stageRound", 1), ("stageRound", "2"),
                           ("stageRound", True), ("profilePolicy", "other")]:
            with self.subTest(key=key, value=value):
                old = self.request[key]; self.request[key] = value
                with self.refuses("r7.tag_reuse_context"):
                    self.run_reuse()
                self.request[key] = old
        self.assertEqual(self.calls, [])

    def test_rejects_inventory_substitution(self):
        self.inventory["upstream"]["tagObject"] = "0" * 40
        with self.refuses("r7.tag_reuse_inventory"):
            self.run_reuse()
        self.assertEqual(self.calls, [])

    def test_absent_fixture_refuses_before_writes(self):
        self.fixture.unlink()
        with self.refuses("r7.tag_reuse_fixture_file"):
            self.run_reuse()
        self.assertEqual(self.calls, [])

    def test_corrupt_fixture_refuses_before_writes(self):
        raw = self.fixture.read_bytes(); self.fixture.write_bytes(raw[:-1] + b"x")
        with self.refuses("r7.tag_reuse_fixture_identity"):
            self.run_reuse()
        self.assertEqual(self.calls, [])

    def test_oversize_fixture_refuses_before_writes(self):
        with self.fixture.open("ab") as h:
            h.write(b"x")
        with self.refuses("r7.tag_reuse_fixture_file"):
            self.run_reuse()
        self.assertEqual(self.calls, [])

    def test_symlink_and_hardlink_fixture_refuse(self):
        target = self.root / "raw"; self.fixture.rename(target); self.fixture.symlink_to(target)
        with self.refuses("r7.tag_reuse_fixture_file"):
            self.run_reuse()
        self.fixture.unlink(); os.link(target, self.fixture)
        with self.refuses("r7.tag_reuse_fixture_file"):
            self.run_reuse()
        self.assertEqual(self.calls, [])

    def test_missing_base_commit_refuses_before_writes(self):
        path = self.source / ".git/objects" / self.d.R7_TAG_COMMIT[:2] / self.d.R7_TAG_COMMIT[2:]
        path.unlink()
        with self.refuses("r7.tag_reuse_base_object"):
            self.run_reuse()
        self.assertEqual(self.calls, [])

    def test_shallow_source_refuses_before_writes(self):
        def inspect(root, *args):
            return b"true" if args == ("rev-parse", "--is-shallow-repository") else self.inspect(root, *args)
        with self.refuses("r7.tag_reuse_base_object"):
            self.run_reuse(inspect)
        self.assertEqual(self.calls, [])

    def test_dirty_source_refuses_before_writes(self):
        (self.source / "unexpected").write_bytes(b"test")
        with self.refuses("r7.tag_reuse_source_identity"):
            self.run_reuse()
        self.assertEqual(self.calls, [])

    def test_conflicting_tag_ref_refuses_before_writes(self):
        self.git("update-ref", self.d.R7_TAG_REF, self.request["sourceSha"])
        with self.refuses("r7.tag_reuse_ref_conflict"):
            self.run_reuse()
        self.assertEqual(self.calls, [])

    def test_dangling_symbolic_tag_ref_refuses_before_writes(self):
        self.git("symbolic-ref", self.d.R7_TAG_REF, "refs/tags/missing")
        with self.refuses("r7.tag_reuse_ref_conflict"):
            self.run_reuse()
        self.assertEqual(self.calls, [])

    def test_existing_exact_tag_is_accepted_without_overwrite(self):
        self.git("hash-object", "-t", "tag", "-w", "--no-filters", "--", str(self.fixture))
        self.git("update-ref", self.d.R7_TAG_REF, self.d.R7_TAG_OBJECT)
        self.run_reuse()
        self.assertEqual(self.calls[-1][0][-1], self.d.R7_TAG_OBJECT)

    def test_nonzero_object_write_has_no_second_write_or_fallback(self):
        def fail(*args):
            self.calls.append(args)
            return types.SimpleNamespace(returncode=1, timed_out=False)
        self.g["phase_process"] = fail
        with self.refuses("r7.tag_reuse_write_failed"):
            self.run_reuse()
        self.assertEqual(len(self.calls), 1)

    def test_zero_exit_with_timeout_is_not_success(self):
        self.g["phase_process"] = lambda *a: types.SimpleNamespace(returncode=0, timed_out=True)
        with self.refuses("r7.tag_reuse_write_failed"):
            self.run_reuse()

    def test_conflict_at_atomic_ref_write_is_terminal(self):
        ordinary = self.phase
        def race(argv, *args):
            if "update-ref" in argv:
                self.git("update-ref", self.d.R7_TAG_REF, self.request["sourceSha"])
            return ordinary(argv, *args)
        self.g["phase_process"] = race
        with self.refuses("r7.tag_reuse_write_failed"):
            self.run_reuse()
        self.assertEqual(len(self.calls), 2)

    def test_nonstandard_ref_read_error_is_terminal(self):
        def inspect(root, *args):
            if args[0] == "symbolic-ref":
                raise subprocess.CalledProcessError(128, args)
            return self.inspect(root, *args)
        with self.refuses("r7.tag_reuse_ref_read"):
            self.run_reuse(inspect)
        self.assertEqual(self.calls, [])

    def test_reference_transaction_hook_cannot_run(self):
        hook = self.source / ".git/hooks/reference-transaction"
        hook.write_bytes(b"#!/bin/sh\nexit 93\n")
        hook.chmod(0o700)
        self.run_reuse()
        self.assertEqual(self.inspect(self.source, "rev-parse", self.d.R7_TAG_REF), self.d.R7_TAG_OBJECT.encode())

    def test_snapshot_uses_verified_bytes_and_changed_original_refuses(self):
        raw = self.fixture.read_bytes()
        changed = raw[:-1] + b"x"
        bad_oid = hashlib.sha1(b"tag " + str(len(changed)).encode() + b"\0" + changed).hexdigest()
        ordinary = self.phase
        snapshots = []
        def mutate(argv, *args):
            if "hash-object" in argv:
                snapshot = Path(argv[-1]); snapshots.append(snapshot)
                self.assertNotEqual(snapshot, self.fixture)
                self.assertEqual(snapshot.read_bytes(), raw)
                self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)
                self.assertEqual(snapshot.parent.stat().st_mode & 0o777, 0o700)
                self.fixture.write_bytes(changed)
            return ordinary(argv, *args)
        self.g["phase_process"] = mutate
        with self.refuses("r7.tag_reuse_final_binding"):
            self.run_reuse()
        self.assertEqual(self.git("cat-file", "tag", self.d.R7_TAG_OBJECT), raw)
        with self.assertRaises(subprocess.CalledProcessError):
            self.git("cat-file", "-e", bad_oid)
        self.assertTrue(snapshots and all(not p.exists() for p in snapshots))

    def test_coarse_equal_stat_cannot_hide_nanosecond_fixture_drift(self):
        original_stat = Path.stat
        ordinary = self.phase
        changed = [False]
        class CoarseEqualStat:
            def __init__(self, value):
                self.value = value
            def __getattr__(self, name):
                value = getattr(self.value, name)
                return value + 1 if name in ("st_mtime_ns", "st_ctime_ns") else value
            def __eq__(self, other):
                # Deterministic model of the stat_result sequence omission.
                return self.value == other
        def stat(path, *args, **kwargs):
            value = original_stat(path, *args, **kwargs)
            return CoarseEqualStat(value) if changed[0] and path == self.fixture else value
        def phase(argv, *args):
            result = ordinary(argv, *args)
            if "update-ref" in argv:
                changed[0] = True
            return result
        self.g["phase_process"] = phase
        with patch.object(Path, "stat", stat), self.refuses("r7.tag_reuse_final_binding"):
            self.run_reuse()
        self.assertEqual(len(self.calls), 2)


class Routing(unittest.TestCase):
    def setUp(self):
        self.d, self.g = owner()
        self.request = dict(schema=self.d.R7_SCHEMA, stageRound=2)
        self.actions = []
        source_sha, source_tree, tag, commit = "a" * 40, "b" * 40, "c" * 40, "d" * 40
        upstream = dict(tag="v2026.10.8", tagObject=tag, commit=commit)
        self.g.update(metadata=lambda p: (self.request, {}, "manifest"),
            source_identity_for=lambda r: (source_sha, source_tree),
            validate_event=lambda e, v: "e" * 40,
            profile_deadline=lambda *a: 9999999999, admission_deadline=lambda *a: 9999999999,
            closure_remaining=lambda d: 1, profile_signals=nullcontext,
            CANDIDATE="candidate", release=types.SimpleNamespace(SHA=None, matches=lambda *a: True),
            preflight=types.SimpleNamespace(inventory_at=lambda *a: ({"upstream": upstream}, "inventory"),
                                            history_commits=lambda *a: [source_sha]),
            local_closure_donor_uri=lambda *a: "file:///fixed-pipeline",
            source_preflight=lambda *a: self.actions.append("preflight"))
        self.g["reuse_upstream_tag_v7"] = lambda *a: self.actions.append("reuse")
        def phase(argv, *args):
            self.actions.append(argv)
            return types.SimpleNamespace(returncode=0, timed_out=False)
        self.g["phase_process"] = phase
        def read(argv, **kw):
            if argv[-1] == "--is-shallow-repository":
                return b"false\n"
            if argv[-1] == "FETCH_HEAD":
                return tag.encode()
            if argv[-2:] == ["-t", tag]:
                return b"tag\n"
            if argv[-1] == tag + "^{commit}":
                return commit.encode()
            return b"commit\n"
        self.read = read
        self.env = {"GITHUB_WORKSPACE": "/owned", "PATH": "/usr/bin:/bin", "SOURCE_PROFILE": "types-tests"}

    def run_closure(self):
        with patch.object(subprocess, "check_output", self.read):
            self.d.fetch_closure(Path("/owned/pipeline"), Path("/owned/source"), env=self.env, event={})

    def test_v7_round2_uses_donor_then_fixture_then_unchanged_preflight(self):
        self.run_closure()
        self.assertEqual(self.actions[0][-2:], ["file:///fixed-pipeline", "a" * 40])
        self.assertEqual(self.actions[1:], ["reuse", "preflight"])
        self.assertIn("protocol.allow=never", self.actions[0])

    def test_stage1_and_legacy_v6_keep_original_official_fetch(self):
        for schema, stage in [(self.d.R7_SCHEMA, 1), (self.d.V6_SCHEMA, 2), (self.d.V5_SCHEMA, 2)]:
            with self.subTest(schema=schema):
                self.request.update(schema=schema, stageRound=stage); self.actions.clear()
                self.run_closure()
                self.assertEqual(self.actions[1][-2:], ["https://github.com/openclaw/openclaw.git", "refs/tags/v2026.10.8"])
                self.assertEqual(self.actions[-1], "preflight")
                self.assertNotIn("reuse", self.actions)

    def test_refusal_never_calls_http_or_preflight(self):
        def refused(*args):
            raise Refusal("fixed fixture failure")
        self.g["reuse_upstream_tag_v7"] = refused
        with self.assertRaises(Refusal):
            self.run_closure()
        self.assertEqual(len(self.actions), 1)


class CodeBinding(unittest.TestCase):
    def setUp(self):
        self.d, self.g = owner()
        self.temp = tempfile.TemporaryDirectory(prefix="v108-tag-code-binding-")
        self.addCleanup(self.temp.cleanup)
        self.pipeline = Path(self.temp.name).resolve(strict=True)
        self.head, self.merge, self.base = "a" * 40, "b" * 40, "c" * 40
        self.paths = (".github/workflows/future-v108-source-validation.yml",
            "scripts/fork-release/source_validation_v108.py", "scripts/fork-release/preflight.py",
            "scripts/fork-release/release.py", "scripts/fork-release/native_tests.mjs", self.d.R7_TAG_FIXTURE)
        self.blobs = {}
        for p in self.paths:
            path = self.pipeline / p; path.parent.mkdir(parents=True, exist_ok=True)
            self.blobs[p] = b"public fixture\n"; path.write_bytes(self.blobs[p])
        self.g.update(source_identity_for=lambda r: ("d" * 40, "e" * 40),
            validate_event=lambda e, v: self.head, acquire_workflow_commit=lambda *a, **kw: None,
            WORKFLOW=self.paths[0], TARGET_BRANCH_TIP=self.base)
        self.env = {"GITHUB_WORKFLOW_SHA": self.merge}
        self.request = dict(schema=self.d.R7_SCHEMA, stageRound=2)
        def git(root, *args):
            if args == ("rev-parse", "HEAD"):
                return self.head.encode()
            if args == ("rev-parse", self.merge + "^1"):
                return self.base.encode()
            if args[0] == "show":
                return self.blobs[args[1].split(":", 1)[1]]
            raise AssertionError(args)
        self.git = git
        self.g["git"] = git

    def test_target_requires_reviewed_fixture_bytes(self):
        self.d.code_binding(self.pipeline, None, {}, self.env, request=self.request)
        (self.pipeline / self.d.R7_TAG_FIXTURE).write_bytes(b"changed")
        with self.assertRaisesRegex(Refusal, "reviewed workflow/code bytes"):
            self.d.code_binding(self.pipeline, None, {}, self.env, request=self.request)

    def test_merge_cannot_substitute_fixture(self):
        def git(root, *args):
            if args == ("show", self.merge + ":" + self.d.R7_TAG_FIXTURE):
                return b"changed synthetic merge"
            return self.git(root, *args)
        self.g["git"] = git
        with self.assertRaisesRegex(Refusal, "reviewed workflow/code bytes"):
            self.d.code_binding(self.pipeline, None, {}, self.env, request=self.request)

    def test_final_sparse_and_old_stage_do_not_read_unused_fixture(self):
        (self.pipeline / self.d.R7_TAG_FIXTURE).unlink()
        self.d.code_binding(self.pipeline, None, {}, self.env, minimal=True, request=self.request)
        self.request["stageRound"] = 1
        self.d.code_binding(self.pipeline, None, {}, self.env, request=self.request)


class TestRegistration(unittest.TestCase):
    def test_only_current_target_adds_owner_without_dropping_any_old_assertion(self):
        d, g = owner()
        g.update(profile_minutes_for=lambda r: {"pipeline-contracts": 45},
                 source_identity_for=lambda r: ("a" * 40, "b" * 40))
        def planned(schema, stage):
            return d.commands(Path("/pipeline"), Path("/source"), "pipeline-contracts", [],
                              dict(schema=schema, stageRound=stage))
        before = planned(d.R7_SCHEMA, 1)
        after = planned(d.R7_SCHEMA, 2)
        self.assertEqual(after[:-1], before)
        self.assertEqual(after[-1][-1], "test_targeted_tag_reuse_v108.py")
        self.assertTrue(all(row[-1] != "test_targeted_tag_reuse_v108.py" for row in planned(d.V6_SCHEMA, 2)))


if __name__ == "__main__":
    unittest.main()

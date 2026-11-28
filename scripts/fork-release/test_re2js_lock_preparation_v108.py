"""Trusted Python-only helper boundaries; no live registry, process or candidate."""
import contextlib
import copy
from datetime import datetime, timezone
import importlib.util
import io
import json
import marshal
import os
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("re2js_helper_under_test", HERE / "re2js_lock_prepare_v108.py")
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)
NOW = datetime(2026, 10, 29, 8, tzinfo=timezone.utc).timestamp()


def configuration():
    return {"pipelineParentSha": "a" * 40, "driverSha256": "b" * 64,
        "preflightSha256": "c" * 64, "releaseSha256": "d" * 64,
        "baselineSha256": H.BASELINE_SHA, "knownPriorRuns": {"1": "e" * 40},
        "changedPipelinePaths": sorted([H.WORKFLOW, H.HELPER, H.TEST,
            "scripts/fork-release/source_validation_v108.py"])}


def metadata():
    target = {"name": "re2js", "version": H.VERSION, "gitHead": H.GIT_HEAD,
        "engines": {"node": ">=20.0.0"}, "dist": {"integrity": H.INTEGRITY,
            "shasum": "7c16e45ba6842b7078c739a6d2046c07eae93e21",
            "tarball": "https://registry.npmjs.org/re2js/-/re2js-2.8.7.tgz"}}
    parent = {"name": "@openclaw/crabline", "version": "0.1.29",
        "dependencies": {"re2js": "2.8.6"}, "engines": {"node": ">=22"},
        "dist": {"integrity": H.PARENT_INTEGRITY,
            "tarball": "https://registry.npmjs.org/@openclaw/crabline/-/crabline-0.1.29.tgz"}}
    values = {"target": target, "parent": parent,
        "packument": {"versions": {H.VERSION: copy.deepcopy(target)}, "time": {H.VERSION: H.PUBLISHED}}}
    return {key: (value, H.encode(value)) for key, value in values.items()}


def mutate(documents, kind, fn):
    values = {key: copy.deepcopy(value) for key, (value, _) in documents.items()}
    fn(values[kind])
    return {key: (value, H.encode(value)) for key, value in values.items()}


def prep_pins():
    return {"sourceSha": "1" * 40, "sourceTree": "2" * 40, "packageSha256": H.PACKAGE_SHA,
        "sourceLockSha256": H.LOCK_SHA, **{key: "3" * 64 for key in
            ("workspaceSha256", "securityTestSha256", "ledgerSha256", "metadataProofSha256")}}


def run(rid="2", head="f" * 40):
    repo = {"full_name": H.REPOSITORY, "private": False}
    return {"id": int(rid), "head_sha": head, "run_attempt": 1, "repository": repo,
        "head_repository": repo, "event": "pull_request", "path": H.WORKFLOW,
        "head_branch": H.BRANCH, "display_title": H.TITLE, "status": "in_progress",
        "actor": {"login": "fr-meyer"}}


class HelperTests(unittest.TestCase):
    def refuse(self, fn, *args):
        with self.assertRaises((H.Refusal, ValueError, OSError, TypeError)):
            fn(*args)

    def test_unbound_main_refuses_before_any_operation_or_private_error_export(self):
        stdout = io.StringIO()
        old = os.umask(0o077)
        try:
            with patch.object(H, "CONFIG", None), patch.object(H.sys, "argv", ["helper", "admit"]), \
                patch.object(H, "exact_paths") as paths, patch.object(H, "public_api") as api, \
                contextlib.redirect_stdout(stdout):
                self.assertEqual(H.main(), 2)
                paths.assert_not_called(); api.assert_not_called()
        finally:
            os.umask(old)
        self.assertEqual(json.loads(stdout.getvalue())["code"], "config.unbound")

    def test_configuration_is_closed_and_does_not_choose_a_source(self):
        value = configuration()
        with patch.object(H, "CONFIG", value):
            self.assertIs(H.configuration(), value)
        for key, replacement in (("baselineSha256", "0" * 64), ("pipelineParentSha", "refs/heads/main"),
            ("knownPriorRuns", {}), ("changedPipelinePaths", [H.HELPER, "../private"])):
            changed = copy.deepcopy(value); changed[key] = replacement
            with self.subTest(key=key), patch.object(H, "CONFIG", changed):
                self.refuse(H.configuration)
        with patch.object(H, "CONFIG", {**value, "sourceSha": "0" * 40}):
            self.refuse(H.configuration)

    def test_utility_donor_exports_only_fixed_function_identities(self):
        for name in ("need", "digest", "encode", "parse", "regular", "private_write", "git", "public_lock_material"):
            self.assertIs(getattr(H, name), getattr(H._UTILITIES, name))
        self.assertIs(H.Refusal, H._UTILITIES.Refusal)
        self.assertEqual(H.digest((HERE / "npm_lock_prepare_v108.py").read_bytes()), H.DONOR_SHA)

    def test_missing_wrong_or_symlink_donor_refuses_before_module_execution(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(H, "__file__", str(Path(directory) / "helper.py")):
            donor = Path(directory) / "npm_lock_prepare_v108.py"
            with patch("builtins.compile") as compiler:
                self.refuse(H.utility_owner)
                donor.write_bytes(b"not reviewed")
                self.refuse(H.utility_owner)
                donor.unlink(); donor.symlink_to(HERE / "npm_lock_prepare_v108.py")
                self.refuse(H.utility_owner)
                compiler.assert_not_called()

    def test_registry_positive_and_outer_packument_changes_do_not_claim_authenticity(self):
        documents = metadata()
        value = H.metadata_checks(documents, NOW)
        self.assertEqual(value["targetVersion"], "2.8.7")
        self.assertEqual(value["parentDeclaredRe2js"], "2.8.6")
        self.assertGreater(value["ageMinutes"], 10080)
        self.assertEqual(value["targetManifestSha256"], H.digest(documents["target"][1]))
        changed = mutate(documents, "packument", lambda x: x.update({"unrelatedNewVersion": {}}))
        self.assertNotEqual(H.metadata_checks(changed, NOW)["packumentSha256"], value["packumentSha256"])

    def test_registry_rejects_metadata_disagreement_wrong_integrity_engine_or_dependencies(self):
        documents = metadata()
        cases = (("target", lambda x: x["dist"].update(integrity="sha512-wrong")),
            ("target", lambda x: x.update(engines={"node": ">=18"})),
            ("target", lambda x: x.update(dependencies={"new-runtime": "1.0.0"})),
            ("packument", lambda x: x["versions"].clear()),
            ("parent", lambda x: x["dependencies"].update(re2js="2.8.7")),
            ("parent", lambda x: x.update(engines={"node": ">=20"})))
        for kind, fn in cases:
            with self.subTest(kind=kind):
                self.refuse(H.metadata_checks, mutate(documents, kind, fn), NOW)

    def test_registry_refuses_unaged_future_clock_missing_or_nonfinite_data(self):
        documents = metadata()
        published = datetime.fromisoformat(H.PUBLISHED.replace("Z", "+00:00")).timestamp()
        for now in (published - 1, published + 10080 * 60 - 0.01, float("nan"), float("inf")):
            with self.subTest(now=now): self.refuse(H.metadata_checks, documents, now)
        self.refuse(H.metadata_checks, {key: value for key, value in documents.items() if key != "parent"}, NOW)
        changed = dict(documents); changed["target"] = (changed["target"][0], b"{}")
        self.refuse(H.metadata_checks, changed, NOW)
        self.refuse(H.parse, b'{"a":1,"a":2}')
        self.refuse(H.parse, b'{"a":NaN}')

    def test_fixed_registry_route_has_no_bearer_and_unknown_kind_does_not_open(self):
        with patch.object(H, "fetch_json", return_value=({}, b"{}")) as fetch:
            H.registry_request("target", NOW)
            request = fetch.call_args.args[0]
            self.assertEqual(request.full_url, H.REGISTRY_URLS["target"])
            self.assertIsNone(request.get_header("Authorization"))
            self.refuse(H.registry_request, "https://other.invalid", NOW)
            self.assertEqual(fetch.call_count, 1)

    def test_failed_or_capped_metadata_read_never_exports_body(self):
        secret = b"SYNTHETIC_PRIVATE_BODY"
        response = Mock(status=200)
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=None)
        response.read.return_value = secret
        opener = Mock(); opener.open.return_value = response
        stdout = io.StringIO()
        with patch.object(H.urllib.request, "build_opener", return_value=opener), \
            patch.object(H.time, "time", return_value=NOW), patch.object(H, "CAP", 4), \
            contextlib.redirect_stdout(stdout):
            self.refuse(H.registry_request, "target", NOW + 60)
        self.assertNotIn(secret.decode(), stdout.getvalue())
        self.assertFalse(json.loads(stdout.getvalue())["rawReturned"])

    def test_genuine_preparation_context_has_no_old_request_or_fake_source(self):
        pins = prep_pins()
        driver = SimpleNamespace(R7_PREPARATION_PINS=pins, validate_preparation_context_v7=Mock())
        actual, context = H.preparation(driver)
        self.assertIs(actual, pins)
        self.assertEqual(context, {"schema": H.CONTEXT_SCHEMA, "sourceSha": pins["sourceSha"], "sourceTree": pins["sourceTree"]})
        driver.validate_preparation_context_v7.assert_called_once_with(context, pins)
        driver.R7_PREPARATION_PINS = None
        self.refuse(H.preparation, driver)

    def test_actor_and_title_gate_and_first_attempt_are_positive(self):
        current = run()
        H.checked_run(current, "2", "f" * 40)
        for key, value in (("display_title", "old-title"), ("actor", {"login": "other"}),
            ("run_attempt", True), ("status", "completed"), ("head_sha", "0" * 40)):
            altered = copy.deepcopy(current); altered[key] = value
            with self.subTest(key=key): self.refuse(H.checked_run, altered, "2", "f" * 40)

    def test_complete_known_history_rejects_duplicate_missing_rerun_and_extra(self):
        prior = run("1", "e" * 40); prior["status"] = "completed"
        current = run()
        table = {"total_count": 2, "workflow_runs": [prior, current]}
        H.checked_history(table, "2", "f" * 40, configuration())
        for change in ("missing", "duplicate", "rerun", "extra"):
            value = copy.deepcopy(table)
            if change == "missing": value["workflow_runs"].pop()
            if change == "duplicate": value["workflow_runs"][0] = copy.deepcopy(current)
            if change == "rerun": value["workflow_runs"][0]["run_attempt"] = 2
            if change == "extra": value["workflow_runs"].append(run("3"))
            with self.subTest(change=change): self.refuse(H.checked_history, value, "2", "f" * 40, configuration())

    def test_only_single_positively_acquired_standard_job_is_admitted(self):
        job = {"name": "lock-preparation", "id": 3, "run_id": 2, "head_sha": "f" * 40,
            "run_attempt": 1, "status": "in_progress", "runner_id": 9,
            "runner_group_name": "GitHub Actions", "labels": ["ubuntu-24.04"]}
        self.assertEqual(H.checked_job({"total_count": 1, "jobs": [job]}, "2", "f" * 40), 3)
        for key, value in (("runner_id", None), ("labels", ["self-hosted"]), ("id", True), ("status", "skipped")):
            altered = dict(job, **{key: value})
            with self.subTest(key=key): self.refuse(H.checked_job, {"total_count": 1, "jobs": [altered]}, "2", "f" * 40)

    def test_clock_refuses_expired_or_nonfinite_before_any_output(self):
        env = {H.CLOCK: str(int(NOW))}
        self.assertEqual(H.clock_deadline(env, NOW), int(NOW) + 2640)
        for now in (NOW + 2640, NOW - 1, float("nan"), float("inf")):
            with self.subTest(now=now): self.refuse(H.clock_deadline, env, now)

    def test_admission_hash_mode_freshness_and_source_are_not_defaulted(self):
        pins = prep_pins(); deadline = int(NOW) + 2640
        value = {"schema": "openclaw.v108.re2js-lock-admission.v1",
            "sourceSha": pins["sourceSha"], "sourceTree": pins["sourceTree"], "pipelineHead": "f" * 40,
            "runId": "2", "runAttempt": 1, "jobId": 3, "checkedAtEpoch": int(NOW),
            "expiresAtEpoch": int(NOW) + 600, "deadlineEpoch": deadline, "startedEpoch": int(NOW)}
        with tempfile.TemporaryDirectory() as directory, patch.object(H.time, "time", return_value=NOW):
            temporary = Path(directory).resolve(); path = temporary / (H.PREFIX + "admission-2.json")
            raw = H.encode(value); H.private_write(path, raw)
            self.assertEqual(H.read_admission(temporary, "2", H.digest(raw), deadline, pins), value)
            self.refuse(H.read_admission, temporary, "2", "0" * 64, deadline, pins)
            path.chmod(0o644); self.refuse(H.read_admission, temporary, "2", H.digest(raw), deadline, pins)

    def test_private_atomic_and_artifact_boundaries_preserve_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); output = root / "out"; output.mkdir()
            H.private_write(output / "generation.json", b"{}")
            self.assertEqual((output / "generation.json").stat().st_mode & 0o777, 0o600)
            self.refuse(H.private_write, output / "generation.json", b"overwrite")
            env = {"GITHUB_OUTPUT": str(root / "github-output")}
            H.artifact_ready(env, output)
            (output / "not-allowed").write_bytes(b"x")
            self.refuse(H.artifact_ready, env, output)
            self.assertFalse(H.public_lock_material(b"authorization: SYNTHETIC"))
            self.assertFalse(H.public_lock_material(b"https://registry.invalid/pkg?cap=synthetic"))

    def test_unsuccessful_phase_including_timeout_valid_status_is_refused(self):
        for code, timed in ((1, False), (0, True), (None, False), (False, False)):
            self.refuse(H.successful_phase, SimpleNamespace(returncode=code, timed_out=timed))
        H.successful_phase(SimpleNamespace(returncode=0, timed_out=False))

    def test_actual_generation_function_emits_only_frozen_success_contract(self):
        pins = prep_pins(); registry = H.metadata_checks(metadata(), NOW)
        result = SimpleNamespace(returncode=0, timed_out=False, cleanup_settled=None)
        with patch.object(H.time, "time", return_value=NOW + 2), patch.object(H.time, "monotonic", return_value=15):
            value = H.generation_receipt(pins, "f" * 40, "2", b"resolver-produced", b"exact-diff",
                registry, H.utc_now(NOW), 10, result)
        fields = {"schema", "status", "sourceSha", "sourceTree", "baseSourceSha", "baseSourceTree",
            "pipelineHead", "runId", "runAttempt", "packageSha256", "sourceLockSha256", "lockSha256",
            "workspaceSha256", "securityTestSha256", "ledgerSha256", "metadataProofSha256", "re2jsVersion",
            "re2jsIntegrity", "parentName", "parentVersion", "parentDeclaredRe2js", "nodeVersion", "pnpmVersion",
            "registryChecks", "changedPaths", "gitDiffSha256", "allOtherTrackedEntriesUnchanged", "startedAt",
            "finishedAt", "commandSeconds", "exitCode", "timedOut", "cleanupSettled", "qualified", "imageBuilt",
            "productionAuthorized"}
        self.assertEqual(set(value), fields)
        self.assertEqual(value["schema"], H.SCHEMA); self.assertEqual(value["status"], "derived_only")
        self.assertEqual(value["sourceSha"], pins["sourceSha"])
        self.assertEqual(value["changedPaths"], ["pnpm-lock.yaml"])
        self.assertEqual(value["commandSeconds"], 5)
        for flag in ("qualified", "imageBuilt", "productionAuthorized"):
            self.assertIs(value[flag], False)

    def test_unsettled_writer_failure_preserves_explicit_metadata_without_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); output = root / "failure"
            state = {"source": root, "output": output, "rid": "2", "pins": prep_pins(),
                "phase": "lock_generation", "bound": True, "generated": True, "result": None}
            env = {"GITHUB_OUTPUT": str(root / "github-output")}
            with patch.object(H, "regular") as read, patch.object(H, "git") as git:
                H.preserve_failure(state, H.Refusal("process.nonzero_or_timeout"), env)
                read.assert_not_called(); git.assert_not_called()
            self.assertEqual({p.name for p in output.iterdir()}, {"generation.json"})
            value = json.loads((output / "generation.json").read_bytes())
            self.assertEqual(value["status"], "refused")
            self.assertEqual(value["missingFileReasons"], {"pnpm-lock.yaml": "writer_unsettled",
                "re2js-lock.diff": "writer_unsettled"})

    def test_source_hooks_are_refused_without_new_resolver_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory).resolve(); pins = prep_pins()
            for path, key in H.SOURCE_FILES.items():
                p = source / path; p.parent.mkdir(parents=True, exist_ok=True)
                raw = b"minimumReleaseAge: 10080\n" if path == "pnpm-workspace.yaml" else b"synthetic"
                p.write_bytes(raw); pins[key] = H.digest(raw)
            with patch.object(H, "git", return_value=b""):
                H.source_inputs(source, pins)
                hook = source / ".pnpmfile.cjs"; hook.write_bytes(b"must never execute")
                self.refuse(H.source_inputs, source, pins); hook.unlink()
                (source / ".npmrc").write_bytes(b"pnpmfile=./unexpected.cjs\n")
                self.refuse(H.source_inputs, source, pins)

    def test_manifest_agreement_distinguishes_boolean_and_number_in_both_places(self):
        documents = metadata()
        value = copy.deepcopy(documents["target"][0]); value["opaque"] = False
        raw = H.encode(value); altered = copy.deepcopy(value); altered["opaque"] = 0
        changed = dict(documents); changed["target"] = (altered, raw)
        self.refuse(H.metadata_checks, changed, NOW)
        values = {k: copy.deepcopy(v) for k, (v, _) in documents.items()}
        values["target"]["opaque"] = 0
        values["packument"]["versions"][H.VERSION]["opaque"] = False
        changed = {k: (v, H.encode(v)) for k, v in values.items()}
        self.refuse(H.metadata_checks, changed, NOW)

    def poison_cache(self, path):
        cache = Path(importlib.util.cache_from_source(str(path))); cache.parent.mkdir(exist_ok=True)
        st = path.stat()
        code = compile("POISONED_CACHE = True\n", str(path), "exec")
        cache.write_bytes(importlib.util.MAGIC_NUMBER + struct.pack("<III", 0, int(st.st_mtime), st.st_size) + marshal.dumps(code))

    def test_utility_loader_compiles_held_verified_source_not_poisoned_pyc(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(sys, "pycache_prefix", None):
            root = Path(directory).resolve(); donor = root / "npm_lock_prepare_v108.py"
            donor.write_bytes((HERE / donor.name).read_bytes()); self.poison_cache(donor)
            with patch.object(H, "__file__", str(root / "helper.py")):
                value = H.utility_owner()
            self.assertFalse(hasattr(value, "POISONED_CACHE")); self.assertTrue(callable(value.need))

    def test_driver_loader_compiles_all_three_verified_owners_and_restores_cache(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(sys, "pycache_prefix", None):
            pipeline = Path(directory).resolve(); owners = pipeline / "scripts/fork-release"; owners.mkdir(parents=True)
            sources = {"release": b"MARKER='verified-release'\n",
                "preflight": b"import release\nMARKER=release.MARKER+'-preflight'\n",
                "source_validation_v108": b"import release,preflight\nMARKER=release.MARKER+preflight.MARKER\n"}
            config = {}
            for name, key in (("release", "releaseSha256"), ("preflight", "preflightSha256"), ("source_validation_v108", "driverSha256")):
                path = owners / (name + ".py"); path.write_bytes(sources[name]); self.poison_cache(path)
                config[key] = H.digest(sources[name])
            sentinels = {name: SimpleNamespace(MARKER="unverified-cache") for name in sources}
            with patch.dict(sys.modules, sentinels):
                value = H.load_driver(pipeline, config)
                self.assertEqual(value.MARKER, "verified-releaseverified-release-preflight")
                self.assertTrue(all(sys.modules[name] is old for name, old in sentinels.items()))
            self.assertFalse(hasattr(value, "POISONED_CACHE"))

    def test_http_failure_diagnostics_identify_only_fixed_kind_ordinal_status(self):
        error = H.urllib.error.HTTPError("https://private.invalid/?SYNTHETIC_CAP", 403, "private", {}, io.BytesIO(b"SYNTHETIC_BODY"))
        opener = Mock(); opener.open.side_effect = error; output = io.StringIO()
        with patch.object(H.urllib.request, "build_opener", return_value=opener), \
            patch.object(H.time, "time", return_value=NOW), contextlib.redirect_stdout(output):
            self.refuse(H.public_api, "/repos/" + H.REPOSITORY + "/pulls/28", "SYNTHETIC_TOKEN", NOW + 60)
        value = json.loads(output.getvalue())
        self.assertEqual((value["kind"], value["ordinal"], value["httpStatus"]), ("pr28", 1, 403))
        self.assertEqual(value["refusalCode"], "api.http_refused")
        for private in ("SYNTHETIC_CAP", "SYNTHETIC_BODY", "SYNTHETIC_TOKEN"):
            self.assertNotIn(private, output.getvalue())

    def test_only_verified_canonical_refusal_whitelist_is_preserved(self):
        class CanonicalRefusal(ValueError): pass
        driver = SimpleNamespace(R7ContractRefusal=CanonicalRefusal, R7_RUNTIME_REFUSAL_CODES=frozenset({"r7.exact"}),
            runtime_refusal_code_v7=Mock(return_value="r7.exact"))
        error = CanonicalRefusal("SYNTHETIC_PRIVATE_ARGUMENT")
        self.assertEqual(H.safe_refusal(error, driver), "r7.exact")
        driver.runtime_refusal_code_v7.return_value = "SYNTHETIC_PRIVATE_ARGUMENT"
        self.assertEqual(H.safe_refusal(error, driver), "preparation.unavailable")
        self.assertEqual(H.safe_refusal(ValueError("SYNTHETIC_PRIVATE_ARGUMENT"), driver), "preparation.unavailable")


if __name__ == "__main__":
    unittest.main()

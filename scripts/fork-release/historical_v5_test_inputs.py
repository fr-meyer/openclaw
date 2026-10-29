"""Exact published P7 fixtures for historical V5 tests, never an operational CLI.

The current validator exclusively owns the current protocol. These tests retain
the published V5 Python contract and inputs under their original identities.
Missing objects or changed shared Python owners refuse; no fetch or fallback is
available. Only immutable authenticated bytes are cached between test cases.
"""
import builtins
import hashlib
import os
from pathlib import Path
import subprocess
import types


HERE = Path(__file__).resolve().parent
PIPELINE = HERE.parents[1]
P7 = "d213bb593b3e618d459dde6767bc93f716ac8493"
CANDIDATE = "scripts/fork-release/candidates/v2026.10.8-source-only/"
PINS = {
    "driver": ("scripts/fork-release/source_validation_v108.py", 215435,
        "ff04088cd2026aea3c06d1109b4741aa55b6919879acda2f3f75e93f26291cc5"),
    "release": ("scripts/fork-release/release.py", 65836,
        "6a183cbde1f2257b30440b34b781688e873ee2e2ed938a129e921d72ac667da3"),
    "preflight": ("scripts/fork-release/preflight.py", 21768,
        "89b6ba41fc89131f33754104fdd0d3ebc08c20f252288651bc7d95038639103a"),
    "workflow": (".github/workflows/future-v108-source-validation.yml", 6874,
        "902a0dace570b13ab0c540b653f6b283210fba7db32bb1a9b78e7a0f071818b1"),
    "source-request.json": (CANDIDATE + "source-request.json", 2002,
        "381c9752fc73f8fe094054b633b587e4e6f20494e98f0d47587518bfd88dcc03"),
    "manifest.json": (CANDIDATE + "manifest.json", 4722,
        "39436d06465c651f63ded013530f91aaf549932dd32390d31b809f8982f527f0"),
    "patch-inventory.json": (CANDIDATE + "patch-inventory.json", 116220,
        "5f9f2f96f3303487daccb5a59177b7ee7ffa6457a0d5bac98187683b353d8ec7"),
    "settled-usage.json": (CANDIDATE + "settled-usage.json", 779518,
        "b02f46b6c5404f33bf04a519190bc724843f901f3bd045ac47a82edaa845eb0d"),
}
_CACHE = {}


def _read_p7(path):
    """One fixed, read-only Git object lookup; all transports are disabled."""
    if path not in {row[0] for row in PINS.values()}:
        raise AssertionError("historical_v5.path_not_allowlisted")
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0",
               GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
    try:
        child = subprocess.run(
            ["/usr/bin/git", "--no-replace-objects", "-c", "protocol.allow=never", "-c",
             "core.hooksPath=/dev/null", "-c", "gc.auto=0", "-c", "maintenance.auto=false",
             "-C", str(PIPELINE), "show", P7 + ":" + path],
            env=env, capture_output=True, timeout=20)
    except subprocess.TimeoutExpired as error:
        raise AssertionError("historical_v5.git_timeout") from error
    if child.returncode != 0:
        # No stderr or process environment is exported by a fixture failure.
        raise AssertionError("historical_v5.git_read_failed")
    return child.stdout


def p7_input(name):
    if type(name) is not str or name not in PINS:
        raise AssertionError("historical_v5.input_not_allowlisted")
    if name not in _CACHE:
        path, size, digest = PINS[name]
        raw = _read_p7(path)
        if type(raw) is not bytes or len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise AssertionError("historical_v5.input_pin")
        _CACHE[name] = raw
    return _CACHE[name]


# Exact current release-owner compatibility, separate from immutable P7 PINS.
# The successor literal is bound only after that exact canonical owner is reviewed.
CURRENT_RELEASE_SUCCESSOR_SHA256 = "3bf47cc5a24e5c43ef3226e3e1fa9cf66c21a7e61bc5e698c71f411d86655d02"


def _check_current_shared_owners():
    for owner in ("release", "preflight"):
        path = HERE / (owner + ".py")
        if not path.is_file() or path.is_symlink():
            raise AssertionError("historical_v5.shared_owner_changed")
        current = path.read_bytes()
        original = p7_input(owner)
        successor = (owner == "release" and
            type(CURRENT_RELEASE_SUCCESSOR_SHA256) is str and
            hashlib.sha256(current).hexdigest() == CURRENT_RELEASE_SUCCESSOR_SHA256)
        if current != original and not successor:
            raise AssertionError("historical_v5.shared_owner_changed")


def _p7_namespace(name):
    """Fresh authenticated P7 dependencies; no process-global module mutation."""
    modules = {owner: types.ModuleType(name + "__" + owner)
               for owner in ("release", "preflight")}
    original_import = builtins.__import__

    def historical_import(module_name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and module_name in modules:
            return modules[module_name]
        return original_import(module_name, globals, locals, fromlist, level)

    def execute(module, owner, raw):
        module.__file__ = "<historical-p7:" + P7 + ":" + owner + ".py>"
        module.__dict__["__builtins__"] = dict(vars(builtins), __import__=historical_import)
        exec(compile(raw, module.__file__, "exec"), module.__dict__)
        return module

    # Both policy and Refusal identity stay historical. Current caller modules
    # retain their own class and globals; P7 callers catch driver.release.Refusal.
    for owner in ("release", "preflight"):
        execute(modules[owner], owner, p7_input(owner))
    return execute(types.ModuleType(name), "source_validation_v108", p7_input("driver"))


def load_p7_driver(name):
    if type(name) is not str or not name.startswith("historical_v5_") or not name.isidentifier():
        raise AssertionError("historical_v5.module_identity")
    _check_current_shared_owners()
    module = _p7_namespace(name)
    controls = {key: p7_input(key) for key in (
        "source-request.json", "manifest.json", "patch-inventory.json", "settled-usage.json")}
    return module, controls


# Fixed historical preparation-only workflow. These inputs never choose or
# validate a current operational request, reference, path, or CLI.
P8_PREPARATION = "e96941f0c8c05a45d7df32ca7e45758e12609be7"
P8_PREPARATION_WORKFLOW = (".github/workflows/future-v108-source-validation.yml", 4460,
    "c3c00a6e3d24ffd387b351fc3f44edab5078ab68a7aed1975b4449bedbb63ae5")
_P8_WORKFLOW_CACHE = None


def p8_preparation_workflow():
    """Return only the exact immutable P8 workflow; no alternate lookup exists."""
    global _P8_WORKFLOW_CACHE
    if _P8_WORKFLOW_CACHE is not None:
        return _P8_WORKFLOW_CACHE
    path, size, digest = P8_PREPARATION_WORKFLOW
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0",
               GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
    try:
        child = subprocess.run(
            ["/usr/bin/git", "--no-replace-objects", "-c", "protocol.allow=never", "-c",
             "core.hooksPath=/dev/null", "-c", "gc.auto=0", "-c", "maintenance.auto=false",
             "-C", str(PIPELINE), "show", P8_PREPARATION + ":" + path],
            env=env, capture_output=True, timeout=20)
    except subprocess.TimeoutExpired:
        raise AssertionError("historical_p8.git_timeout") from None
    if type(child.returncode) is not int or child.returncode != 0:
        raise AssertionError("historical_p8.git_read_failed")
    raw = child.stdout
    if type(raw) is not bytes or len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise AssertionError("historical_p8.workflow_pin")
    _P8_WORKFLOW_CACHE = raw
    return raw

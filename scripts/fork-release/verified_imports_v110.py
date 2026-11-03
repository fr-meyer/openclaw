"""Fixed local operator imports from an already verified in-memory code map.

Callers verify the complete pinned manifest before executing these bytes. This
helper performs no file reads, installs no search path/finder and starts nothing.
The returned builtins are used only by the captured entry and local modules.
"""
import builtins
from pathlib import PurePosixPath
import re
import sys
from types import ModuleType


def install_verified_imports(pipeline_root, captured_files):
    if (type(pipeline_root) is not str or not pipeline_root.startswith("/") or
            type(captured_files) is not dict or
            any(type(path) is not str or type(raw) is not bytes
                for path, raw in captured_files.items())):
        raise SystemExit("v110.closed_import_input")
    # A fixed filename in the verified map is the only local module namespace.
    # Nested directories/data remain data, never package-shaped import targets.
    modules = {}
    for path, raw in captured_files.items():
        relative = PurePosixPath(path)
        if str(relative.parent) == "scripts/fork-release" and relative.suffix == ".py":
            name = relative.stem
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None or name == "__init__":
                raise SystemExit("v110.closed_import_module_name")
            modules[name] = (pipeline_root + "/" + path, raw)
    if any(path == pipeline_root or path.startswith(pipeline_root + "/")
            for path in sys.path):
        raise SystemExit("v110.closed_import_search_path")
    original_import = builtins.__import__
    closed_builtins = dict(vars(builtins))
    loaded = {}

    def import_verified(name, globals=None, locals=None, fromlist=(), level=0):
        if (level != 0 or type(name) is not str or "/" in name or "\\" in name or
                ("." in name and name.split(".", 1)[0] in modules)):
            raise ImportError("v110.closed_import_package_target")
        if name not in modules:
            # Python -I's original paths contain no pipeline directory, so an
            # unlisted sibling cannot replace argparse or any other import.
            return original_import(name, globals, locals, fromlist, level)
        if name in loaded:
            return loaded[name]
        if name in sys.modules:
            raise ImportError("v110.closed_import_existing_module")
        filename, raw = modules[name]
        module = ModuleType(name)
        module.__file__ = filename
        module.__package__ = ""
        module.__dict__["__builtins__"] = closed_builtins
        loaded[name] = module
        sys.modules[name] = module
        try:
            exec(compile(raw, filename, "exec"), module.__dict__)
        except BaseException:
            del loaded[name]
            if sys.modules.get(name) is module:
                del sys.modules[name]
            raise
        return module

    closed_builtins["__import__"] = import_verified
    return closed_builtins

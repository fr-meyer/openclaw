"""Fixed-file, data-only custody. Importing this module performs no capture.

The trusted caller supplies an already bound checkout root and a fresh private
output directory. This module does not authenticate CI, Git HEAD or UI assets.
Rejected raw data stays private; only adjudicate() can create the five fixed
public payload files. No command execution or caller-selected source paths.
"""
import copy
import difflib
import functools
import hashlib
import json
import os
import re
import stat
from pathlib import Path

SOURCE_H = "edd010829dcb622d7dc60dc90f7097048cb78819"
MAX_FILE_BYTES = 64 * 1024
MAX_PUBLIC_BYTES = 2 * 1024 * 1024
PLUGIN_PATHS = {
    "workboard": "extensions/workboard/openclaw.plugin.json",
    "x": "extensions/x/openclaw.plugin.json",
}
ORIGINAL_SHA256 = {
    "workboard": "67f00a82f72f5d3c8e2cebf0155e5f736c8445a4bf66ea24140817f6225722c2",
    "x": "26fabfc6758e2f90a69e485c962387e26a50191aee2075072ab2d129a0d3e083",
}
ENTRY = re.compile(r"dist/control-ui/([a-f0-9]{64})/index\.js\Z", re.ASCII)


class Refusal(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _need(value, code):
    if not value:
        raise Refusal(code)


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _private_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
              and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600
              and info.st_size <= MAX_FILE_BYTES, "custody.private_file")
        raw = stream.read(MAX_FILE_BYTES + 1)
        _need(len(raw) <= MAX_FILE_BYTES, "custody.private_file")
        return raw


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            _need(key not in result, "manifest.duplicate_key")
            result[key] = value
        return result

    def constant(_):
        raise Refusal("manifest.non_json_number")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise Refusal("manifest.invalid_json") from None


def _encode(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _private_dir(out):
    out = Path(out)
    info = out.lstat()
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
          and stat.S_IMODE(info.st_mode) == 0o700, "custody.private_directory")
    return out


def _safe_io(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except OSError:
            pass
        # Outside the except block: no native exception/path context escapes.
        raise Refusal("custody.io_refused")
    return wrapped


def _open_named_path(root, relative):
    descriptors = []
    try:
        # Re-open every named component, including ancestors of the supplied
        # root. Trusted callers use a canonical, symlink-free checkout path.
        parts = Path(root).absolute().parts
        fd = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(fd)
        for part in (*parts[1:], *relative.split("/")[:-1]):
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            descriptors.append(fd)
        fd = os.open(relative.split("/")[-1],
                     os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        descriptors.append(fd)
        return descriptors
    except BaseException:
        for opened in reversed(descriptors):
            os.close(opened)
        raise


def _lineage(descriptors):
    return [(info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
            for info in map(os.fstat, descriptors)]


def _fixed_read(root, relative):
    """Read only one fixed path, rejecting symlinks/hardlinks/nonregular files."""
    descriptors = []
    try:
        descriptors = _open_named_path(root, relative)
        opened_lineage = _lineage(descriptors)
        leaf = descriptors[-1]
        before = os.fstat(leaf)
        _need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
              "custody.source_file_type")
        chunks, remaining = [], MAX_FILE_BYTES + 1
        while remaining:
            piece = os.read(leaf, remaining)
            if not piece:
                break
            chunks.append(piece)
            remaining -= len(piece)
        raw = b"".join(chunks)
        after = os.fstat(leaf)
        fields = lambda item: (item.st_dev, item.st_ino, item.st_size,
                               item.st_mtime_ns, item.st_ctime_ns, item.st_mode,
                               item.st_nlink, item.st_uid, item.st_gid)
        reopened = []
        try:
            reopened = _open_named_path(root, relative)
            path_stable = (opened_lineage == _lineage(reopened)
                           and fields(after) == fields(os.fstat(reopened[-1])))
        except OSError:
            path_stable = False
        finally:
            for fd in reversed(reopened):
                os.close(fd)
        return raw[:MAX_FILE_BYTES], {
            "bytes": min(len(raw), MAX_FILE_BYTES),
            "savedSha256": _digest(raw[:MAX_FILE_BYTES]),
            "sourceSize": before.st_size,
            "mode": stat.S_IMODE(before.st_mode),
            "complete": len(raw) <= MAX_FILE_BYTES and before.st_size <= MAX_FILE_BYTES,
            "leafStable": fields(before) == fields(after),
            "namedPathStable": path_stable,
            "stable": fields(before) == fields(after) and path_stable,
        }
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def _snapshot(stage, root, out):
    _need(stage in ("before", "after"), "custody.stage")
    records = {}
    for plugin, relative in PLUGIN_PATHS.items():
        try:
            raw, record = _fixed_read(root, relative)
        except (OSError, Refusal):
            records[plugin] = {"captured": False, "code": "custody.fixed_read_refused"}
            continue
        # Save raw prefix before hash/size/schema acceptance. It is never printed.
        _write(out / f"{stage}.{plugin}.raw.json", raw)
        records[plugin] = {"captured": True, **record}
    _write(out / f"{stage}.custody.json", _encode({"stage": stage, "files": records}))
    _need(all(r.get("captured") and r["complete"] and r["stable"]
              and r["mode"] == 0o644 for r in records.values()), "custody.capture_refused")


@_safe_io
def capture_before(source_root, private_output):
    """First call only: creates a private directory and captures exactly two files."""
    out = Path(private_output)
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    out = _private_dir(out)
    _snapshot("before", source_root, out)
    for plugin in PLUGIN_PATHS:
        _need(_digest(_private_read(out / f"before.{plugin}.raw.json"))
              == ORIGINAL_SHA256[plugin], "manifest.before_pin")
    return {"status": "before_captured", "sourceH": SOURCE_H}


@_safe_io
def capture_after(source_root, private_output, observed_changed_paths):
    """After the owned CI command; preserves bounded bytes before adjudication."""
    out = _private_dir(private_output)
    _private_read(out / "before.custody.json")
    _need(type(observed_changed_paths) is list and 1 <= len(observed_changed_paths) <= 2
          and all(type(path) is str for path in observed_changed_paths)
          and len(set(observed_changed_paths)) == len(observed_changed_paths)
          and set(observed_changed_paths) <= set(PLUGIN_PATHS.values()),
          "custody.changed_paths_not_fixed_manifests")
    _write(out / "change-selection.json", _encode({"paths": sorted(observed_changed_paths)}))
    _snapshot("after", source_root, out)
    return {"status": "after_captured_unadjudicated"}


def validate_pair(before, after, plugin):
    """Pure data validator. A hash-looking path is not asset authentication."""
    _need(plugin in PLUGIN_PATHS, "manifest.plugin")
    _need(len(before) <= MAX_FILE_BYTES and len(after) <= MAX_FILE_BYTES, "manifest.size")
    _need(_digest(before) == ORIGINAL_SHA256[plugin], "manifest.before_pin")
    original, result = _json(before), _json(after)
    _need(type(original) is dict and type(result) is dict, "manifest.object")
    control = result.get("controlUi")
    _need(type(control) is dict and set(control) in ({"entry"}, {"entry", "styles"}),
          "manifest.control_shape")
    entry = control.get("entry")
    match = ENTRY.fullmatch(entry) if type(entry) is str else None
    _need(match is not None, "manifest.entry")
    if "styles" in control:
        _need(type(control["styles"]) is list and control["styles"] == [
            f"dist/control-ui/{match.group(1)}/index.css"], "manifest.styles")
    # Rebuild from fixed public original, not from untrusted outside fields.
    expected = copy.deepcopy(original)
    expected["controlUi"] = control
    _need(after == _encode(expected), "manifest.outside_or_serialization_changed")
    return {"status": "pointer_shape_only", "changed": before != after,
            "assetContentAuthenticated": False, "qualified": False}


@_safe_io
def adjudicate(private_output):
    """Produce only fixed allowlisted payload after both pairs are accepted."""
    out = _private_dir(private_output)
    payload, files = {}, {}
    for stage in ("before", "after"):
        record = _json(_private_read(out / f"{stage}.custody.json"))
        _need(type(record) is dict and record.get("stage") == stage,
              "custody.metadata")
        for plugin in PLUGIN_PATHS:
            info = record.get("files", {}).get(plugin)
            _need(type(info) is dict and info.get("captured") is True
                  and info.get("complete") is True and info.get("stable") is True
                  and info.get("mode") == 0o644, "custody.metadata")
            raw = _private_read(out / f"{stage}.{plugin}.raw.json")
            _need(len(raw) == info.get("bytes") and _digest(raw) == info.get("savedSha256"),
                  "custody.snapshot_pin")
            _need(type(info.get("sourceSize")) is int and len(raw) == info["sourceSize"],
                  "custody.snapshot_size")
            files[stage, plugin] = raw
    results = {}
    for plugin, path in PLUGIN_PATHS.items():
        before, after = files["before", plugin], files["after", plugin]
        results[plugin] = validate_pair(before, after, plugin)
        payload[f"{plugin}.after.json"] = after
        payload[f"{plugin}.diff"] = "".join(difflib.unified_diff(
            before.decode().splitlines(keepends=True), after.decode().splitlines(keepends=True),
            fromfile=path + "@" + SOURCE_H, tofile=path + "@observed"
        )).encode()
    selection = _json(_private_read(out / "change-selection.json"))
    changed = sorted(PLUGIN_PATHS[plugin] for plugin, result in results.items() if result["changed"])
    _need(type(selection) is dict and set(selection) == {"paths"}
          and changed == selection["paths"] and bool(changed), "custody.change_selection_mismatch")
    receipt = {"schema": "openclaw.plugin-manifest-capture.v1", "sourceH": SOURCE_H,
               "status": "fixed_manifest_data_validated_not_authenticated",
               "assetContentAuthenticated": False, "qualified": False,
               "producerObservedCheck": "not_collected_by_this_validator",
               "beforeSha256": ORIGINAL_SHA256,
               "afterSha256": {plugin: _digest(files["after", plugin]) for plugin in PLUGIN_PATHS},
               "controlUiSha256": {plugin: _digest(_encode(_json(files["after", plugin])["controlUi"]))
                                   for plugin in PLUGIN_PATHS},
               "results": results,
               "files": {name: {"bytes": len(raw), "sha256": _digest(raw)}
                         for name, raw in payload.items()}}
    payload["manifest-capture-receipt.json"] = _encode(receipt)
    _need(len(payload) == 5 and sum(map(len, payload.values())) <= MAX_PUBLIC_BYTES,
          "custody.payload_limit")
    public = out / "validated-payload"
    public.mkdir(mode=0o700, exist_ok=False)
    for name, raw in payload.items():
        _write(public / name, raw)
    return receipt

#!/usr/bin/env python3
"""Inspect ELF program/dynamic headers as data. Never use ldd or load a library."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import posixpath
import struct


def elf(data):
    if data[:6] != b"\x7fELF\x02\x01" or len(data) < 64:
        raise ValueError("expected ELF64 little-endian")
    if struct.unpack_from("<H", data, 18)[0] != 62:
        raise ValueError("expected x86-64 ELF")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    if size != 56 or count > 1024 or offset + size * count > len(data):
        raise ValueError("invalid program-header table")
    headers = [struct.unpack_from("<IIQQQQQQ", data, offset + i * size) for i in range(count)]
    def payload(h):
        start, length = h[2], h[5]
        if start + length > len(data):
            raise ValueError("truncated segment")
        return data[start:start + length]
    interp = None
    dynamic = []
    for h in headers:
        if h[0] == 3:
            raw = payload(h)
            if len(raw) > 4096 or not raw.endswith(b"\0"):
                raise ValueError("invalid interpreter")
            interp = raw[:-1].decode("ascii")
        if h[0] == 2:
            raw = payload(h)
            if len(raw) % 16 or len(raw) > 1024 * 1024:
                raise ValueError("invalid dynamic section")
            for i in range(0, len(raw), 16):
                tag, value = struct.unpack_from("<qQ", raw, i)
                if tag == 0:
                    break
                dynamic.append((tag, value))
    if not dynamic:
        return {"interpreter": interp, "needed": [], "rpath": [], "runpath": []}
    tables = [v for t, v in dynamic if t == 5]
    lengths = [v for t, v in dynamic if t == 10]
    if len(tables) != 1 or len(lengths) != 1 or lengths[0] > 16 * 1024 * 1024:
        raise ValueError("invalid dynamic string table")
    table = tables[0]
    mapping = [h for h in headers if h[0] == 1 and h[3] <= table and table + lengths[0] <= h[3] + h[5]]
    if len(mapping) != 1:
        raise ValueError("unmapped dynamic strings")
    h = mapping[0]
    start = h[2] + table - h[3]
    strings = data[start:start + lengths[0]]
    def string(i):
        if i >= len(strings) or b"\0" not in strings[i:]:
            raise ValueError("invalid dynamic string offset")
        return strings[i:].split(b"\0", 1)[0].decode("ascii")
    return {"interpreter": interp, "needed": [string(v) for t, v in dynamic if t == 1],
            "rpath": [string(v) for t, v in dynamic if t == 15],
            "runpath": [string(v) for t, v in dynamic if t == 29]}


def inspect(inventory, stores):
    raw = inventory.read_bytes()
    if hashlib.sha256(raw).hexdigest() != "e7c50cfcb33072e780dbae849147d3fbc33b2bcb41b7067ae9f13a05d9116719":
        raise ValueError("inventory changed")
    rows = {r["path"]: r for r in json.loads(gzip.decompress(raw))["entries"]}
    def resolve(p):
        for _ in range(40):
            parts = p.strip("/").split("/")
            for i in range(len(parts)):
                name = "/" + "/".join(parts[:i + 1])
                row = rows.get(name)
                if not row:
                    raise ValueError("absent:" + name)
                if row["type"] == "symlink":
                    p = posixpath.normpath(posixpath.join(posixpath.dirname(name), row["target"], *parts[i + 1:]))
                    break
            else:
                if rows[p]["type"] != "file":
                    raise ValueError("non-file:" + p)
                return p
        raise ValueError("link loop")
    queue = ["/usr/local/bin/node"] + [p for p in rows if p.endswith(".node") and ("fs-safe-linux-x64-gnu@0.21.1/" in p or "koffi-linux-x64@3.3.1/" in p)]
    result, failures = [], []
    seen = set()
    while queue:
        name = resolve(queue.pop(0))
        if name in seen:
            continue
        seen.add(name)
        row = rows[name]
        p = next((root / row["sha256"] for root in stores if (root / row["sha256"]).is_file()), None)
        if p is None:
            failures.append({"path": name, "error": "native content not captured"})
            continue
        data = p.read_bytes()
        if len(data) != row["bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
            raise ValueError("captured native content changed")
        info = elf(data)
        joined = []
        if info["interpreter"]:
            queue.append(info["interpreter"])
        for dep in info["needed"]:
            candidates = []
            for directory in ["/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu", "/usr/local/lib", "/usr/lib", "/lib"]:
                try:
                    target = resolve(directory + "/" + dep)
                    if target not in candidates:
                        candidates.append(target)
                except ValueError:
                    pass
            joined.append({"soname": dep, "candidates": candidates})
            if len(candidates) != 1:
                failures.append({"path": name, "dependency": dep, "error": "nonunique standard-path identity"})
            else:
                queue.append(candidates[0])
        result.append({**row, **info, "dependencyCandidates": joined})
    return {"schema": "openclaw-v98-static-elf-dependencies/v1", "entries": result,
            "unresolved": failures, "dynamicLoaderExecuted": False,
            "fullRuntimeClosureClaimed": False,
            "limit": "Static SONAME/standard-path content joins only; not loader cache, runtime dlopen, constructor or confinement proof."}


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--inventory", type=Path, required=True)
    p.add_argument("--objects", type=Path, action="append", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    result = inspect(a.inventory, a.objects)
    with a.output.open("x") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    print(json.dumps({"entries": len(result["entries"]), "unresolved": len(result["unresolved"])}))

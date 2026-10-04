#!/usr/bin/env python3
"""Read admitted image bytes into flat digest objects. Never extract or run an image.

The authenticated producer inventory supplies requested names and hashes.
Earlier layer versions can supply identical content, so a separate final-catalog
join is required before interpreting these bytes as final path bindings.
No symlink, tar pathname, mode or directory is reproduced on the host.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

IMAGE = "0a3418e393313dbe7e20f4ef140fea81e3a7e6d8a24f9ee1bf5e0bd87d86ffcf"
INVENTORY = "e7c50cfcb33072e780dbae849147d3fbc33b2bcb41b7067ae9f13a05d9116719"
VALIDATION = "1fb4f68a10dc0769f519cdb4d63256ffab0311c58db195b5bcd92dc11c1517f4"
LIMIT = 1024 * 1024 ** 2


def digest(p):
    h = hashlib.sha256()
    with p.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def selected(row):
    p = row["path"]
    return row["type"] == "file" and (
        p.startswith("/app/") and p.endswith((".mjs", ".js", ".cjs", ".json"))
        or "fs-safe" in p and p.endswith(".node")
        or p == "/usr/local/bin/node"
        or p.startswith(("/usr/lib/x86_64-linux-gnu/", "/lib/x86_64-linux-gnu/"))
        and (".so" in p or p.endswith("ld-linux-x86-64.so.2"))
    )


def read(artifact, out, only=None):
    for name, expected in [("image.tar.gz", IMAGE),
                           ("image-filesystem-manifest.json.gz", INVENTORY),
                           ("validation.json", VALIDATION)]:
        p = artifact / name
        if p.is_symlink() or digest(p) != expected:
            raise ValueError("admitted input changed: " + name)
    with gzip.open(artifact / "image-filesystem-manifest.json.gz") as f:
        inventory = json.load(f)
    rows = {r["path"].lstrip("/"): r for r in inventory["entries"]
            if r["type"] == "file" and (r["path"] in only if only is not None else selected(r))}
    if only is not None and set(only) != {r["path"] for r in rows.values()}:
        raise ValueError("requested path is not an admitted regular file")
    if any(r["bytes"] > 128 * 1024 ** 2 for r in rows.values()):
        raise ValueError("selected file over budget")
    if sum(r["bytes"] for r in rows.values()) > LIMIT:
        raise ValueError("selected bytes over budget")
    out.mkdir(mode=0o700)
    objects = out / "objects"
    objects.mkdir(mode=0o700)
    needed = {r["sha256"] for r in rows.values()}
    found = set()
    measured = 0
    with gzip.open(artifact / "image.tar.gz", "rb") as outer:
        with tarfile.open(fileobj=outer, mode="r|") as saved:
            for layer in saved:
                # Saved OCI layers may be gzip blobs with digest-only names.
                if not layer.isfile() or layer.size < 1024:
                    continue
                f = saved.extractfile(layer)
                prefix = f.read(2)
                class Prefix(io.RawIOBase):
                    def __init__(self):
                        self.prefix = prefix
                    def readable(self):
                        return True
                    def readinto(self, b):
                        value = self.prefix[:len(b)]
                        self.prefix = self.prefix[len(value):]
                        if len(value) < len(b):
                            value += f.read(len(b) - len(value))
                        b[:len(value)] = value
                        return len(value)
                combined = io.BufferedReader(Prefix())
                stream = gzip.GzipFile(fileobj=combined) if prefix == b"\x1f\x8b" else combined
                # Only metadata/config members fail this tar-format test; their
                # identity and all layer digests were already independently joined.
                try:
                    contents = tarfile.open(fileobj=stream, mode="r|")
                except tarfile.ReadError:
                    continue
                with contents:
                    for member in contents:
                        name = member.name.removeprefix("./").rstrip("/")
                        row = rows.get(name)
                        if not row or not member.isfile() or member.size != row["bytes"]:
                            continue
                        if row["sha256"] in found:
                            continue
                        data = contents.extractfile(member).read(member.size + 1)
                        h = hashlib.sha256(data).hexdigest()
                        if h != row["sha256"]:
                            continue
                        measured += len(data)
                        if measured > LIMIT:
                            raise ValueError("object storage over budget")
                        p = objects / h
                        with p.open("xb") as dest:
                            dest.write(data)
                        p.chmod(0o400)
                        found.add(h)
    missing = needed - found
    receipt = {"schema": "openclaw-v98-static-byte-capture/v1",
               "imageArchiveSha256": IMAGE, "inventorySha256": INVENTORY,
               "validationSha256": VALIDATION,
               "sourceCommit": "bc8b82b2cbbbb81f5abe6093e1bb3af4f1f70cdf",
               "objects": len(found), "bytes": measured,
               "selectedEntries": len(rows), "missingHashes": sorted(missing),
               "imageExecuted": False, "tarPathsExtracted": False}
    (out / "capture.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if missing:
        raise ValueError("selected content missing")
    print(json.dumps(receipt))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--artifact", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--only-paths", type=Path)
    a = p.parse_args()
    read(a.artifact, a.output, json.loads(a.only_paths.read_text()) if a.only_paths else None)

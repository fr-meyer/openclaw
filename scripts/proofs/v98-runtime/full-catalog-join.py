#!/usr/bin/env python3
"""Join every saved-layer final path to the producer inventory, without extraction.

Reuses the independently reviewed, local-only 9de validator algorithm by exact
file digest. It executes trusted Python proof tooling, never image code.
"""
import argparse
import hashlib
import json
from pathlib import Path

VALIDATOR = "3f60f4f04eac0361a7b4f6d49e77f0cf2e25661a3d4b804d8e30aa95c14783d4"
IMAGE = "0a3418e393313dbe7e20f4ef140fea81e3a7e6d8a24f9ee1bf5e0bd87d86ffcf"
INVENTORY = "e7c50cfcb33072e780dbae849147d3fbc33b2bcb41b7067ae9f13a05d9116719"
CONFIG = "sha256:1b2669dcea79d48e6c9f1e86a81495746e62f6d4b9a7837eaccca5ce0a266c39"


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def join(artifact, validator):
    for path, expected in [(validator, VALIDATOR), (artifact / "image.tar.gz", IMAGE),
                           (artifact / "image-filesystem-manifest.json.gz", INVENTORY)]:
        if path.is_symlink() or digest(path) != expected:
            raise ValueError("pinned proof input changed")
    namespace = {"__file__": str(validator.resolve()), "__name__": "v98_reviewed_consumer"}
    exec(compile(validator.read_bytes(), str(validator), "exec"), namespace)
    collector = namespace["load_collector"]()
    expected = namespace["read_manifest"](artifact / "image-filesystem-manifest.json.gz", collector)
    actual, _, layers = namespace["saved_identity_files"](artifact / "image.tar.gz", CONFIG, collector)
    differences = [{"path": "/" + name, "producer": expected.get(name), "savedFinal": actual.get(name)}
                   for name in sorted(expected.keys() | actual.keys()) if expected.get(name) != actual.get(name)]
    important = [r for r in differences if r["path"].startswith(("/app/", "/usr/lib/", "/usr/local/", "/lib/", "/lib64/"))
                 or r["path"] in ("/app", "/usr/lib", "/usr/local", "/lib", "/lib64")]
    return {"schema": "openclaw-v98-independent-final-catalog-join/v1",
            "status": "STATIC_RUNTIME_CATALOG_MATCHED" if not important else "BLOCKED_RUNTIME_CATALOG_DIFFERENCE",
            "validatorSha256": VALIDATOR, "imageSha256": IMAGE, "inventorySha256": INVENTORY,
            "imageConfigId": CONFIG, "layers": layers, "savedEntries": len(actual),
            "producerEntries": len(expected), "equalEntries": sum(expected.get(n) == r for n, r in actual.items()),
            "differences": differences, "runtimeCatalogDifferences": important,
            "runtimeExecuted": False, "filesystemReconstructed": False,
            "completeImportWorkerClosureClaimed": False,
            "scope": "All final-layer identities compared; Docker-export differences retained explicitly. This is static catalog identity, not import resolution or runtime admission."}


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--artifact", required=True, type=Path)
    p.add_argument("--validator", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    result = join(a.artifact, a.validator)
    with a.output.open("x") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    print(json.dumps({"status": result["status"], "differences": len(result["differences"])}))
    raise SystemExit(bool(result["runtimeCatalogDifferences"]))

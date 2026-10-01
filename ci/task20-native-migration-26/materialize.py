"""Fetch the exact bounded source/package inputs. Never run package scripts."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import resource
import subprocess
import tarfile
import time
import urllib.request

HERE = Path(__file__).resolve().parent
MANIFEST = json.loads((HERE / "manifest.json").read_text())


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def inside(root, relative):
    p = PurePosixPath(relative)
    if p.is_absolute() or ".." in p.parts or not p.parts:
        raise RuntimeError("unsafe input path")
    return root.joinpath(*p.parts)


def download(url, path, budget, algorithm, expected):
    if not url.startswith(("https://registry.npmjs.org/", "https://codeload.github.com/openclaw/openclaw/")):
        raise RuntimeError("unapproved artifact origin")
    h = hashlib.new(algorithm)
    count = 0
    with urllib.request.urlopen(url, timeout=30) as response, path.open("xb") as out:
        if not response.geturl().startswith(("https://registry.npmjs.org/", "https://codeload.github.com/openclaw/openclaw/")):
            raise RuntimeError("unapproved artifact redirect")
        for block in iter(lambda: response.read(1024 * 1024), b""):
            count += len(block)
            if count > budget:
                raise RuntimeError("artifact transfer budget exceeded")
            h.update(block)
            out.write(block)
    if h.digest() != expected:
        raise RuntimeError("artifact digest mismatch")
    return count


def extract(archive, root, expected_prefix, expansion_budget, inventory=None):
    """Validate all members first; install links after files, never through links."""
    with tarfile.open(archive, "r:gz") as tar:
        members = []
        destinations = set()
        links = set()
        size = 0
        link_bytes = 0
        for member in tar:
            p = PurePosixPath(member.name)
            if p.is_absolute() or ".." in p.parts or not p.parts or p.parts[0] != expected_prefix:
                raise RuntimeError("unsafe archive member")
            relative = str(PurePosixPath(*p.parts[1:]))
            if relative == ".":
                if not member.isdir():
                    raise RuntimeError("invalid archive root")
                continue
            if relative in destinations:
                raise RuntimeError("duplicate archive member")
            destinations.add(relative)
            if member.isreg():
                size += member.size
            elif member.issym():
                link_bytes += len(member.linkname.encode("utf8"))
                target = (inside(root, relative).parent / member.linkname).resolve()
                if not target.is_relative_to(root):
                    raise RuntimeError("archive link escapes root")
                links.add(relative)
            elif not member.isdir():
                raise RuntimeError("unsupported archive object")
            if size + link_bytes > expansion_budget:
                raise RuntimeError("archive expansion budget exceeded")
            members.append((relative, member))
        for relative, member in members:
            if any(str(parent) in links for parent in PurePosixPath(relative).parents):
                raise RuntimeError("archive member below link")
            destination = inside(root, relative)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if member.isdir():
                destination.mkdir(exist_ok=True)
            elif member.isreg():
                with tar.extractfile(member) as src, destination.open("xb") as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
                destination.chmod(0o555 if member.mode & 0o111 else 0o444)
        for relative, member in members:
            if member.issym():
                inside(root, relative).symlink_to(member.linkname)
    if inventory is not None:
        inventory.update({"regularBytes": size, "symlinkTargetBytes": link_bytes,
                          "symlinkCount": len(links), "trackedBlobBytes": size + link_bytes})
    return size


def materialize(work, progress=None):
    if progress is None:
        progress = {}
    progress["phase"] = "SCRATCH_ADMISSION"
    if work.exists():
        raise RuntimeError("scratch must be new")
    if shutil.disk_usage(work.parent).free < MANIFEST["budgets"]["scratchBytes"] + 1024**3:
        raise RuntimeError("insufficient scratch reserve")
    work.mkdir(mode=0o755)
    budget = MANIFEST["budgets"]
    receipts = {"sourceCommit": MANIFEST["nativeCommit"], "sourceTree": MANIFEST["nativeTree"],
                "packages": [], "scriptsExecuted": False, "databaseOpened": False}
    started = time.monotonic()
    source = work / "source"
    source.mkdir()
    archive = work / "source.tgz"
    progress["phase"] = "SOURCE_DOWNLOAD"
    receipts["sourceTransferBytes"] = download(
        MANIFEST["sourceUrl"], archive, budget["sourceTransferBytes"], "sha256",
        bytes.fromhex(MANIFEST["sourceArchiveSha256"]))
    progress.update({"sourceTransferBytes": receipts["sourceTransferBytes"], "sourceDigestVerified": True,
                     "phase": "SOURCE_EXTRACT"})
    receipts["sourceInventory"] = {}
    receipts["sourceExpandedBytes"] = extract(
        archive, source, "openclaw-" + MANIFEST["nativeCommit"], budget["sourceExpansionBytes"],
        inventory=receipts["sourceInventory"])
    progress.update({"sourceInventory": receipts["sourceInventory"], "phase": "SOURCE_IDENTITY"})
    archive.unlink()
    if receipts["sourceExpandedBytes"] != MANIFEST["sourceRegularBytes"]:
        raise RuntimeError("source size differs from archived pinned source")
    if receipts["sourceInventory"] != MANIFEST["sourceInventory"]:
        raise RuntimeError("source tracked-blob/link inventory differs from archived pinned source")
    for relative, expected in MANIFEST["sourceOwnerHashes"].items():
        if sha(inside(source, relative)) != expected:
            raise RuntimeError("physical source owner mismatch: " + relative)

    transfer = expansion = 0
    for row in MANIFEST["roots"]:
        progress.update({"phase": "PACKAGE_DOWNLOAD", "lastPackage": row["snapshot"],
                         "packagesCompleted": len(receipts["packages"]), "packageTransferBytes": transfer})
        progress.pop("lastPackageCompressedBytes", None)
        progress.pop("lastPackageIntegrityVerified", None)
        if time.monotonic() - started > 300:
            raise RuntimeError("materialization wall budget exceeded")
        root = inside(work, row["path"])
        root.mkdir(parents=True)
        archive = work / "package.tgz"
        algorithm, encoded = row["integrity"].split("-", 1)
        if algorithm != "sha512":
            raise RuntimeError("unexpected lock integrity algorithm")
        compressed = download(row["url"], archive, budget["dependencyTransferBytes"] - transfer,
                              algorithm, base64.b64decode(encoded, validate=True))
        if compressed != row["compressedBytes"]:
            raise RuntimeError("registry artifact size changed")
        progress.update({"phase": "PACKAGE_EXTRACT", "lastPackageCompressedBytes": compressed,
                         "lastPackageIntegrityVerified": True})
        expanded = extract(archive, root, row["archivePrefix"], budget["dependencyExpansionBytes"] - expansion)
        archive.unlink()
        transfer += compressed
        expansion += expanded
        package = json.loads((root / "package.json").read_text())
        if (package["name"], package["version"]) != (row["name"], row["version"]):
            raise RuntimeError("package identity mismatch")
        receipts["packages"].append({"snapshot": row["snapshot"], "integrity": row["integrity"],
                                      "compressedBytes": compressed, "expandedBytes": expanded})

    proxy = next(x for x in MANIFEST["roots"] if x["name"] == "@openclaw/proxyline")
    progress.update({"phase": "LOCK_PATCH_AND_CLOSURE_BINDING", "packagesCompleted": len(receipts["packages"]),
                     "packageTransferBytes": transfer})
    proxy_root = inside(work, proxy["path"])
    patch = source / MANIFEST["proxylinePatch"]["sourcePath"]
    if sha(patch) != MANIFEST["proxylinePatch"]["physicalSha256"]:
        raise RuntimeError("native lock patch identity changed")
    subprocess.run(["git", "apply", "--check", str(patch)], cwd=proxy_root, check=True, timeout=10)
    # Only the lock-owned patch is applied to this new package copy; no lifecycle script.
    for path in proxy_root.rglob("*"):
        if path.is_file():
            path.chmod(0o755 if path.stat().st_mode & 0o111 else 0o644)
    subprocess.run(["git", "apply", str(patch)], cwd=proxy_root, check=True, timeout=10)
    for row in MANIFEST["proxylinePatchedFiles"]:
        if sha(inside(proxy_root, row["path"])) != row["sha256"]:
            raise RuntimeError("patched package physical custody mismatch")

    for row in MANIFEST["links"]:
        path = inside(work, row["path"])
        target = inside(work, row["target"])
        if path.exists() or path.is_symlink() or not target.exists():
            raise RuntimeError("dependency link identity collision")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(os.path.relpath(target, path.parent), target_is_directory=True)
    (work / "extra-anchor/anchor.mjs").write_text("export {};\n")
    control = work / "control"
    control.mkdir()
    (control / "sealed-empty").mkdir(mode=0o555)
    (control / "expanded-closure-linux.json").write_text(json.dumps({"directRootLinks": MANIFEST["directRootLinks"]}))
    shutil.copytree(HERE / "fixture-source", work / "fixture-source")
    for row in MANIFEST["fixtureFiles"]:
        path = inside(work, row["path"])
        if sha(path) != row["sha256"] or path.stat().st_size != row["bytes"]:
            raise RuntimeError("reviewed fixture identity changed")
    receipts["dependencyTransferBytes"] = transfer
    receipts["dependencyExpandedBytes"] = expansion
    receipts["wallSeconds"] = time.monotonic() - started
    (control / "materialization-receipt.json").write_text(json.dumps(receipts, indent=2) + "\n")
    for path in work.rglob("*"):
        if path.is_symlink():
            if not path.resolve().is_relative_to(work):
                raise RuntimeError("final link escapes closure")
        elif path.is_file():
            path.chmod(0o555 if path.stat().st_mode & 0o111 else 0o444)
        elif path.is_dir():
            path.chmod(0o555)
    work.chmod(0o555)
    progress["phase"] = "EXACT_PINNED_INPUTS_MATERIALIZED"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2))
    progress = {}
    try:
        materialize(args.work.resolve(), progress=progress)
        receipt = {"status": "EXACT_PINNED_INPUTS_MATERIALIZED", "databaseOpened": False,
                   "scriptsExecuted": False, "nativeSourceExecuted": False, "progress": progress}
    except Exception as error:
        receipt = {"status": "MATERIALIZATION_REFUSED", "databaseOpened": False,
                   "scriptsExecuted": False, "nativeSourceExecuted": False,
                   "error": type(error).__name__ + ": " + str(error), "progress": progress}
    args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")
    if receipt["status"] != "EXACT_PINNED_INPUTS_MATERIALIZED":
        raise SystemExit(1)

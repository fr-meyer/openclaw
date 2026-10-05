#!/usr/bin/env python3
"""Prepare exact image read paths without starting or importing image code.

The pinned, independent saved-layer comparison is the content authority. The
AST graph is deliberately conservative and is not a complete runtime resolver.
Only regular target files become Landlock read rules; namespace bindings do not
grant directory reads. Proof inputs and runner files are added by the bundle
owner after it verifies their separate hashes.
"""
import argparse
import gzip
import hashlib
import json
import os
import posixpath
import re
import stat
from pathlib import Path, PurePosixPath

SOURCE_COMMIT = "bc8b82b2cbbbb81f5abe6093e1bb3af4f1f70cdf"
SOURCE_TREE = "ba825f670dc5ba943f7893cb267225d1f68d3110"
IMAGE_SHA256 = "0a3418e393313dbe7e20f4ef140fea81e3a7e6d8a24f9ee1bf5e0bd87d86ffcf"
IMAGE_CONFIG = "sha256:1b2669dcea79d48e6c9f1e86a81495746e62f6d4b9a7837eaccca5ce0a266c39"
PINNED_INPUTS = {
    "graph": ("openclaw-v98-doctor-worker-import-graph-final-20261004.json", "7eaaa86bab0597f69d9208bc77140fff605a9dfb922a283738d5a0cd847b9589"),
    "inventory": ("openclaw-v98-artifact-build-37192724704-validated-scalable/image-filesystem-manifest.json.gz", "e7c50cfcb33072e780dbae849147d3fbc33b2bcb41b7067ae9f13a05d9116719"),
    "catalog": ("openclaw-v98-independent-final-catalog-join-20261004.json", "61fdb2ab3746f01126f518bc4d57e86311501ce9b29a6e1dc8bba2a41bb52328"),
    "classification": ("openclaw-v98-independent-final-catalog-classification-20261004.json", "0a051c803837686a67627abf6e417dbcc5c7893c62c76882abf9fe6417c8f290"),
    "elf": ("openclaw-v98-elf-dependency-analysis-20261004.json", "1de4df7cfd908935ee5703df95ebd75d1a39ed04e96867969e7e1c2e9a0e1555"),
}
GNU_FS_SAFE = "/app/node_modules/.pnpm/@openclaw+fs-safe-linux-x64-gnu@0.21.1/node_modules/@openclaw/fs-safe-linux-x64-gnu/fs-safe-native.node"
GNU_KOFFI = "/app/node_modules/.pnpm/@koromix+koffi-linux-x64@3.3.1/node_modules/@koromix/koffi-linux-x64/linux_x64/koffi.node"
NODE = "/usr/local/bin/node"
SYSTEM_FILES = (
    NODE,
    "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    "/usr/lib/x86_64-linux-gnu/libdl.so.2",
    "/usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.30",
    "/usr/lib/x86_64-linux-gnu/libm.so.6",
    "/usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
    "/usr/lib/x86_64-linux-gnu/libpthread.so.0",
    "/usr/lib/x86_64-linux-gnu/libc.so.6",
    "/etc/ld.so.cache",
    "/etc/ssl/openssl.cnf",
)
APP_METADATA = ("/app/package.json", "/app/dist/build-info.json",
                "/app/dist/.buildstamp", "/app/dist/.runtime-postbuildstamp")
FROZEN_INPUTS = {
    "/proof/inputs/fixture.mjs": "6ca0b85238594eb4294514ec08e0b60770953b37ed783f83e7f2920088144dd2",
    "/proof/inputs/predecessor-state.sql": "32a9ec60e38f1511e6f5fcd532f4c631d680d537a8325601f5bdf8221cf20fa3",
    "/proof/inputs/predecessor-workboard.ts": "aa15bf48dbe292993a47c7286d5f7e12fe2ffbd74442c92b37ad98018bd2e810",
    "/proof/inputs/predecessor-publisher-controller.mjs": "c3d63b3c567541f72fb33c6982b41d4d5e4efa7fdd2d43ba5d7d14e624ebdbfc",
}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def canonical_path(path):
    if (not isinstance(path, str) or not path.startswith("/") or path == "/"
            or len(path.encode("utf-8")) > 4095
            or any(ord(c) < 32 or ord(c) == 127 for c in path)
            or posixpath.normpath(path) != path or path.startswith("//")):
        raise ValueError("read path is not an exact canonical absolute filename")
    return path


def regular_identity(entry):
    canonical_path(entry.get("path"))
    if (entry.get("type") != "file" or type(entry.get("bytes")) is not int
            or entry["bytes"] < 0 or not isinstance(entry.get("sha256"), str)
            or not SHA256.fullmatch(entry["sha256"])
            or not isinstance(entry.get("mode"), str)
            or not re.fullmatch(r"0o[0-7]{3,4}", entry["mode"])):
        raise ValueError("read rule needs a regular file identity")
    return {k: entry[k] for k in ("path", "mode", "type", "bytes", "sha256")}


def catalog_entries(inventory):
    if inventory.get("schema") != "openclaw-image-filesystem-inventory/v1":
        raise ValueError("wrong inventory schema")
    entries = {}
    for entry in inventory["entries"]:
        path = canonical_path(entry.get("path"))
        if path in entries:
            raise ValueError("duplicate inventory path")
        kind = entry.get("type")
        if kind == "file":
            regular_identity(entry)
        elif kind in ("symlink", "hardlink"):
            target = entry.get("target")
            if (not isinstance(target, str) or not target or len(target.encode("utf-8")) > 4095
                    or any(ord(c) < 32 or ord(c) == 127 for c in target)):
                raise ValueError("invalid symlink target")
        elif kind not in ("directory", "character-device", "block-device", "fifo"):
            raise ValueError("unsupported inventory entry")
        entries[path] = entry
    return entries


def resolve_catalog_path(path, entries):
    """Resolve image aliases using image metadata, never host realpath()."""
    canonical_path(path)
    pending = path.split("/")[1:]
    resolved = []
    aliases = []
    links = 0
    while pending:
        component = pending.pop(0)
        if component in ("", "."):
            continue
        if component == "..":
            if not resolved:
                raise ValueError("image alias escapes root")
            resolved.pop()
            continue
        current = "/" + "/".join(resolved + [component])
        entry = entries.get(current)
        if entry is None:
            raise ValueError("image path component absent: " + current)
        if entry["type"] == "symlink":
            links += 1
            if links > 40:
                raise ValueError("image alias loop or excessive chain")
            aliases.append({k: entry[k] for k in ("path", "mode", "type", "target")})
            target = entry["target"]
            if target.startswith("/"):
                resolved = []
            pending = target.split("/") + pending
        else:
            if pending and entry["type"] != "directory":
                raise ValueError("non-directory image ancestor")
            resolved.append(component)
    final = "/" + "/".join(resolved)
    canonical_path(final)
    return final, aliases


def bind_selected_paths(selected, entries, differences):
    difference_paths = {r["path"] for r in differences}
    bound = {}
    aliases = {}
    for path, reasons in selected.items():
        final, chain = resolve_catalog_path(path, entries)
        row = regular_identity(entries[final])
        if any(p in difference_paths for p in [path, final] + [e["path"] for e in chain]):
            raise ValueError("selected path differs from saved-layer catalog")
        if final not in bound:
            bound[final] = {**row, "reasons": []}
        bound[final]["reasons"] = sorted(set(bound[final]["reasons"]) | set(reasons))
        for e in chain:
            aliases[e["path"]] = e
    return bound, aliases


def classify_selector(row):
    source = row["from"]
    specifier = row.get("specifier")
    expression = row.get("expression")
    if source.endswith("/koffi/src/koffi/src/static.cjs") and specifier and specifier.startswith("@koromix/koffi-"):
        platform = specifier[len("@koromix/koffi-"):]
        if platform == "linux-x64":
            raise ValueError("required Koffi target cannot be classified foreign")
        return "LINUX_X64_UNREACHABLE", "The pinned loader selects pkg=linux-x64; this require is guarded by a different exact pkg value."
    if specifier in ("bun:ffi", "bun:sqlite"):
        return "NODE_RUNTIME_UNREACHABLE", "Bun-only SQLite branch; the admitted executable is the pinned GNU Node ELF, never Bun."
    if expression == "require(candidate)" and source in (
            "/app/dist/version-BMuSsYfE.mjs", "/app/dist/infra/sqlite-readonly-location.worker.js",
            "/app/dist/state/openclaw-state-read.worker.js"):
        return "BOUNDED_JSON_PROBES", "Literal version/package/build-info candidate arrays; only present pinned /app/package.json and /app/dist/build-info.json are admitted. Missing/outside candidates stay denied."
    if specifier == "../../package.json" and source == "/app/dist/git-commit-Brz49B6u.mjs":
        return "ABSENT_OPTIONAL_JSON_PROBE", "Resolves to absent /package.json in this exact image; best-effort catch, no root-level read grant."
    if expression == "require(nativePackageForTarget(target))" and source.endswith("/@openclaw/fs-safe/dist/native.js"):
        return "PINNED_GNU_NATIVE_TARGET", "linux/x64 and the pinned Node GNU interpreter select fs-safe-linux-x64-gnu 0.21.1; no alternate platform binary is admitted."
    if expression == "require(name)" and source.endswith("/tslog/esm/env/sourceMap.node.js"):
        return "BUILTIN_ONLY", "The sole caller passes node:fs. Optional computed source-map file reads remain forbidden unless independently selected."
    if source.endswith("/@koromix/koffi-linux-x64/index.js") and expression == "require(BINARIES[libc])":
        return "PINNED_GNU_NATIVE_TARGET", "ELF interpreter detection selects glibc/linux_x64/koffi.node 3.3.1; musl target is denied."
    if source.endswith("/@koromix/koffi-linux-x64/index.js") and expression == "require(filename)":
        return "CONDITIONAL_FALLBACK_DENIED", "The loader fallback iterates GNU and musl. Only the pinned GNU target is readable; GNU load failure never admits musl."
    return "UNKNOWN_FORBIDDEN", "No read grant. The attempt must establish the actual flow under the unchanged allowlist or fail; this is not complete closure proof."


def derive_binding(graph, inventory, catalog, classification, elf):
    if (graph.get("schema") != "openclaw-v98-static-import-graph/v1"
            or graph.get("completeClosureClaimed") is not False
            or graph.get("imageJavaScriptExecuted") is not False):
        raise ValueError("graph has an unsupported closure/execution claim")
    if (catalog.get("schema") != "openclaw-v98-independent-final-catalog-join/v1"
            or catalog.get("imageSha256") != IMAGE_SHA256
            or catalog.get("imageConfigId") != IMAGE_CONFIG
            or catalog.get("inventorySha256") != PINNED_INPUTS["inventory"][1]
            or catalog.get("runtimeExecuted") is not False
            or classification.get("rawReceiptSha256") != PINNED_INPUTS["catalog"][1]
            or classification.get("waiverOrExecutionAdmission") is not False):
        raise ValueError("final saved-layer comparison binding changed")
    entries = catalog_entries(inventory)
    selected = {}

    def add(path, reason):
        canonical_path(path)
        selected.setdefault(path, set()).add(reason)

    for key in ("files", "metadata"):
        seen = set()
        for row in graph[key]:
            identity = regular_identity(row)
            path = identity["path"]
            if path in seen or entries.get(path) != identity:
                raise ValueError("graph row does not match pinned inventory")
            seen.add(path)
            add(path, "conservative-static-graph" if key == "files" else "selected-package-exports")
    for path in APP_METADATA:
        add(path, "compiled-version-and-build-identity")
    for path in (GNU_FS_SAFE, GNU_KOFFI):
        add(path, "selected-linux-x64-gnu-native-addon")
    for path in SYSTEM_FILES:
        add(path, "named-node-and-gnu-loader-runtime")
    elf_rows = {row["path"]: row for row in elf["entries"]}
    elf_files = tuple(path for path in SYSTEM_FILES
                      if path not in ("/etc/ld.so.cache", "/etc/ssl/openssl.cnf"))
    for path in (GNU_FS_SAFE, GNU_KOFFI) + elf_files:
        if path not in elf_rows or regular_identity(elf_rows[path]) != regular_identity(entries[path]):
            raise ValueError("ELF identity does not match final catalog")
    if elf_rows[NODE].get("interpreter") != "/lib64/ld-linux-x86-64.so.2":
        raise ValueError("Node interpreter changed")
    # Node reads package scope metadata above selected module files, including
    # nested type=module scopes absent from the graph's exports lookups.
    for path in tuple(selected):
        for parent in PurePosixPath(path).parents:
            metadata = str(parent).rstrip("/") + "/package.json"
            if metadata in entries:
                add(metadata, "selected-file-ancestor-package-scope")
    bound, aliases = bind_selected_paths(selected, entries, catalog["differences"])
    selected_ancestors = {str(p) for path in bound for p in PurePosixPath(path).parents if str(p) != "/"}
    # Bind image namespace aliases resolving to selected targets/ancestors, but
    # grant reads only to canonical regular files. Broken unrelated workspace
    # links and aliases to unselected packages do not enter the binding.
    differences = {r["path"] for r in catalog["differences"]}
    for path, entry in entries.items():
        if entry["type"] != "symlink":
            continue
        try:
            final, chain = resolve_catalog_path(path, entries)
        except ValueError:
            continue
        if final in bound or final in selected_ancestors:
            if any(e["path"] in differences for e in chain):
                raise ValueError("selected namespace alias differs from saved layer")
            for e in chain:
                aliases[e["path"]] = e
    namespace = {p: entries[p] for p in selected_ancestors if p in entries}
    namespace.update(aliases)
    for row in namespace.values():
        if row["type"] not in ("directory", "symlink") or row["path"] in differences:
            raise ValueError("selected namespace does not match final layer")
    selectors = []
    for row in graph["unresolved"]:
        if row["from"] not in bound:
            raise ValueError("unresolved selector source is not a bound module")
        kind, explanation = classify_selector(row)
        selectors.append({**row, "sourceSha256": bound[row["from"]]["sha256"],
                          "classification": kind, "explanation": explanation})
    return {
        "schema": "openclaw-v98-exact-runtime-read-binding/v1",
        "status": "STATIC_READ_POLICY_PREPARED; RUNTIME_NOT_ADMITTED",
        "sourceCommit": SOURCE_COMMIT, "sourceTree": SOURCE_TREE,
        "imageSha256": IMAGE_SHA256, "imageConfigId": IMAGE_CONFIG,
        "inputs": {k: {"sha256": v[1]} for k, v in PINNED_INPUTS.items()},
        "platform": {"os": "linux", "architecture": "amd64", "libc": "gnu"},
        "imageEntries": [bound[p] for p in sorted(bound)],
        "namespaceEntries": [namespace[p] for p in sorted(namespace)],
        "unresolvedSelectors": selectors,
        "frozenInputHashes": FROZEN_INPUTS,
        "readPolicy": {
            "parentAndHelperImageReadScopesEqual": True,
            "regularFileRulesOnly": True,
            "directoryReadRules": False,
            "symlinksGrantOnlyFinalTargetInode": True,
            "proofFilesAddedAfterSeparateBundleHashVerification": True,
            "scratchAndSpecialFileRulesOwnedByNativeExecutor": True,
            "unknownComputedReads": "DENY; NO_AUTOMATIC_ALLOWLIST_EXPANSION",
            "muslNativeFallback": "DENY",
        },
        "completeImportClosureClaimed": False,
        "runtimeExecuted": False,
        "limitations": "Conservative image graph plus named GNU dependencies and scope metadata; actual import, Worker, loader-cache, fsync and six-phase behavior require the separately approved native confined attempt.",
    }


def read_pinned_inputs(root):
    result = {}
    for key, (name, expected) in PINNED_INPUTS.items():
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("proof input is not a regular file")
        data = path.read_bytes()
        if sha256_bytes(data) != expected:
            raise ValueError("pinned proof input changed: " + key)
        result[key] = json.loads(gzip.decompress(data) if key == "inventory" else data)
    return result


def image_read_paths(binding):
    if (binding.get("schema") != "openclaw-v98-exact-runtime-read-binding/v1"
            or binding.get("sourceCommit") != SOURCE_COMMIT
            or binding.get("sourceTree") != SOURCE_TREE
            or binding.get("imageSha256") != IMAGE_SHA256
            or binding.get("imageConfigId") != IMAGE_CONFIG
            or binding.get("completeImportClosureClaimed") is not False
            or binding.get("runtimeExecuted") is not False):
        raise ValueError("read binding source/image or scope changed")
    paths = [regular_identity(e)["path"] for e in binding["imageEntries"]]
    if paths != sorted(set(paths)):
        raise ValueError("read rules must be sorted unique regular filenames")
    for path in paths:
        if not path.startswith("/app/") and path not in SYSTEM_FILES:
            raise ValueError("image read rule outside selected app or named GNU runtime")
    return paths


def read_list_bytes(paths):
    if paths != sorted(set(paths)):
        raise ValueError("read list must be sorted and unique")
    for path in paths:
        canonical_path(path)
    return ("\n".join(paths) + "\n").encode("utf-8")


def write_prepared_policy(output, binding):
    output.mkdir(parents=True, exist_ok=False)
    payload = (json.dumps(binding, indent=2, sort_keys=True) + "\n").encode("utf-8")
    (output / "runtime-read-binding.json").write_bytes(payload)
    paths = read_list_bytes(image_read_paths(binding))
    for name in ("parent-read-paths.txt", "helper-read-paths.txt"):
        (output / name).write_bytes(paths)
    return {"bindingSha256": sha256_bytes(payload), "imageRegularFiles": len(binding["imageEntries"]),
            "namespaceBindings": len(binding["namespaceEntries"]), "unresolvedSelectors": len(binding["unresolvedSelectors"]),
            "parentReadListSha256": sha256_bytes(paths), "helperReadListSha256": sha256_bytes(paths),
            "runtimeExecuted": False}


def open_relative_nofollow(root_fd, path, directory=False):
    canonical_path(path)
    components = path.split("/")[1:]
    current_fd = os.dup(root_fd)
    try:
        for component in components[:-1]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        # Reject a FIFO/device after open without blocking on a FIFO attacker.
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        if directory:
            flags |= os.O_DIRECTORY
        return os.open(components[-1], flags, dir_fd=current_fd)
    finally:
        os.close(current_fd)


def verify_regular_files(root, identities):
    """Verify canonical files under an already read-only trusted image tree.

    The caller owns the read-only mount and binds this code/binding before use.
    Descriptor traversal rejects host symlink redirection and special files.
    This operation only reads bytes; it never imports modules or loads ELF.
    """
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        seen = set()
        for raw in identities:
            row = regular_identity(raw)
            if row["path"] in seen:
                raise ValueError("duplicate verification path")
            seen.add(row["path"])
            fd = open_relative_nofollow(root_fd, row["path"])
            try:
                before = os.fstat(fd)
                if (not stat.S_ISREG(before.st_mode) or before.st_size != row["bytes"]
                        or stat.S_IMODE(before.st_mode) != int(row["mode"], 8)):
                    raise ValueError("mounted file type/size/mode mismatch: " + row["path"])
                digest = hashlib.sha256()
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                after = os.fstat(fd)
                fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
                if (any(getattr(before, key) != getattr(after, key) for key in fields)
                        or digest.hexdigest() != row["sha256"]):
                    raise ValueError("mounted file bytes changed: " + row["path"])
            finally:
                os.close(fd)
    finally:
        os.close(root_fd)


def verify_namespace(root, identities):
    """Bind directory metadata and symlink text without granting their reads."""
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        seen = set()
        for row in identities:
            path = canonical_path(row.get("path"))
            if path in seen or row.get("type") not in ("directory", "symlink"):
                raise ValueError("invalid or duplicate namespace binding")
            seen.add(path)
            parent = posixpath.dirname(path)
            parent_fd = os.dup(root_fd) if parent == "/" else open_relative_nofollow(root_fd, parent, directory=True)
            try:
                name = posixpath.basename(path)
                info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if stat.S_IMODE(info.st_mode) != int(row["mode"], 8):
                    raise ValueError("mounted namespace mode changed: " + path)
                if row["type"] == "directory":
                    if not stat.S_ISDIR(info.st_mode):
                        raise ValueError("mounted namespace directory changed: " + path)
                elif not stat.S_ISLNK(info.st_mode) or os.readlink(name, dir_fd=parent_fd) != row["target"]:
                    raise ValueError("mounted namespace alias changed: " + path)
            finally:
                os.close(parent_fd)
    finally:
        os.close(root_fd)


def read_bound_policy(path, expected_sha256):
    """The caller supplies the binding hash from the final reviewed packet."""
    if not isinstance(expected_sha256, str) or not SHA256.fullmatch(expected_sha256):
        raise ValueError("exact reviewed binding digest is required")
    if path.is_symlink() or not path.is_file():
        raise ValueError("binding is not a regular file")
    data = path.read_bytes()
    if sha256_bytes(data) != expected_sha256:
        raise ValueError("reviewed read binding changed")
    binding = json.loads(data)
    image_read_paths(binding)
    return binding


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    inputs = read_pinned_inputs(args.evidence_root)
    binding = derive_binding(**inputs)
    print(json.dumps(write_prepared_policy(args.output_dir, binding), sort_keys=True))


if __name__ == "__main__":
    main()

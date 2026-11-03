"""Fixed 10.10 lock admission; imports perform no I/O or package execution.

The existing pnpm writer-dialect reader remains the parser owner. This gate
checks the reviewed source inputs, selected security edges, patch registration
and positive age/integrity for every bootstrap and project registry tuple.
It does not approve the remaining lock diff, replace advisory audits, or grant
execution authority. Registry access exists only when an admitted caller invokes
PublicRegistry; tests inject synthetic packuments.
"""
import base64
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import posixpath
import re
import time
import urllib.error
import urllib.parse
import urllib.request

import lockfile_policy_v109 as writer


CAP = 2 * 1024 * 1024
MAX_PATCH_BYTES = 4 * 1024 * 1024  # Source input, not a permitted artifact upload.
MAX_PACKAGES = 4000
MINIMUM_AGE_MINUTES = 10080
NOT_BEFORE = "2026-11-04T09:59:50Z"
EXPIRES_AT = "2026-11-06T03:14:21Z"
BOOTSTRAP_SHA256 = "321c8f68b09bab3486375b53714510d110b6648a77565cbcd85a8aba27a4f113"
PNPM_SPEC = "pnpm@12.15.0+sha512.b3951d6d6ff4a9f13dc7cf56cd28d2b8eb37dbcc9c68e52e1e1191873ea9f82a017287ab50baadc5ccc494f036c67c0e47eb13608c2fa36f47711b61ea128e61"
FIXED_SOURCE_HASHES = {
    "package.json": "81cf7c38037ceba6791afeb736f74f099ffce29107e1801ccab20194ec78e741",
    "pnpm-workspace.yaml": "8b475a29d068c2d1aa1d89694230594bb434ce57b1025bf0151da26261c51838",
    "extensions/file-transfer/package.json": "f2113a06a866871b56f98433c12beeb9bebaf1ea4ad72ba4f606636f55ee0c38",
    "ui/package.json": "d4c65c630944af4335f6bb3e629ed983b1c29ba2059596600ab7bae8336a8bbb",
}
PATCHES = {
    "@a2ui/lit@0.12.0": ("patches/@a2ui__lit@0.12.0.patch", "1cc07844aae2cd1a6ebe80bdb5feb1aedf89f84f0c74bcd170cc4d34046b6fcd"),
    "@a2ui/web_core@0.12.0": ("patches/@a2ui__web_core@0.12.0.patch", "37c06a8d997b50dc9127c55c23176f0b722455d7a0fa223bcdea3013b738f583"),
    "@discord/embedded-app-sdk@2.5.0": ("patches/@discord__embedded-app-sdk@2.5.0.patch", "571102cd0329706f1c9edf2dd5cd7f50bfcb8c4336809c961e0c12f43760ab87"),
    "zod@4.6.6": ("patches/zod@4.6.6.patch", "9fe4b383c96309498941cafec0f003951e8c68447c668202dc6f122cc4029be2"),
    "baileys@7.0.0-rc14": ("patches/baileys@7.0.0-rc14.patch", "c3c4601486630c689ffd1a0e7a34f4b8cf8e7231e41c312ad33afdf4487d8ded"),
    "matrix-js-sdk@42.4.0": ("patches/matrix-js-sdk@42.4.0.patch", "a64300f73fb497ef3039c5886dce44c9bd1256afc291717854ee5f36c1a7d078"),
    "@novnc/novnc@1.7.0": ("patches/@novnc__novnc@1.7.0.patch", "bfde0e1bda172da3525f9f5014d85ad28073325b74f09609084598a65d2f412d"),
    "vitest@5.0.5": ("patches/vitest@5.0.5.patch", "c7225d77fb8a242bd88070b9787737119caea3ba29fdccb38419b9fe4c196e92"),
    "@awesome.me/webawesome@3.13.0": ("patches/@awesome.me__webawesome@3.13.0.patch", "9b35bfc2e23b45e47ac3e6a669b8bf7df0c4ca89423e8a78d6fb921faa686208"),
    "ghostty-web@0.4.0": ("patches/ghostty-web@0.4.0.patch", "d4c6598b6840564dac4a469f3aa9b8df24fe6eab48a6744302707017e095a524"),
    "chrome-devtools-mcp@1.10.1": ("patches/chrome-devtools-mcp@1.10.1.patch", "d31d6e7e187ea9fd4dad87ed3ad08073c77ffcfddd52bc4761b39a2dfce0ac1e"),
}
FIXED_GLOBAL_VERSIONS = {"fast-uri": "4.2.3", "follow-redirects": "1.16.2",
                         "minimatch": "11.0.1", "qs": "6.16.1"}
FIXED_EDGES = {
    "@azure/identity@4.13.3": {"@azure/msal-node": "7.1.1"},
    "@microsoft/teams.apps@2.1.0": {"@azure/msal-node": "7.1.1"},
    "@azure/msal-node@7.1.1": {"@azure/msal-common": "16.14.3"},
    "@openclaw/crabline@0.1.29": {"re2js": "2.8.7"},
    "express@5.2.1": {"body-parser": "2.4.0"},
    "body-parser@2.4.0": {"qs": "6.16.1"},
    "mailauth@7.1.1": {"nodemailer": "10.1.4", "joi": "18.3.1"},
    "mailparser@3.9.36": {"nodemailer": "10.1.4"},
    "cacache@21.0.1": {"glob": "14.0.2"},
    "@a2ui/lit@0.12.0": {"zod": "4.6.6"},
    "@a2ui/web_core@0.12.0": {"zod": "4.6.6"},
    "@discord/embedded-app-sdk@2.5.0": {"zod": "4.6.6"},
    "make-fetch-happen@16.0.1": {"http-cache-semantics": "4.3.0"},
}
NAME = re.compile(r"(?:@[a-z0-9][a-z0-9_.~-]*/)?[a-z0-9][a-z0-9_.~-]*\Z")
VERSION = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\Z")
UTC = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z\Z")
SRI = re.compile(r"sha512-([A-Za-z0-9+/]+={0,2})\Z")


class LockRefusal(ValueError):
    def __init__(self, code, evidence=None):
        super().__init__(code)
        self.code = code
        # Only caller-selected public package names/statuses, never response text.
        self.evidence = {} if evidence is None else evidence


def need(value, code, evidence=None):
    if not value:
        raise LockRefusal(code, evidence)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def strict_json(raw, cap=CAP):
    need(type(raw) is bytes and 0 < len(raw) <= cap, "v110.metadata_bounded")
    def pairs(rows):
        out = {}
        for key, value in rows:
            need(key not in out, "v110.metadata_duplicate_key")
            out[key] = value
        return out
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: need(False, "v110.metadata_constant"))
    except LockRefusal:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise LockRefusal("v110.metadata_json")


def utc(value):
    need(type(value) is str and UTC.fullmatch(value), "v110.registry_timestamp")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise LockRefusal("v110.registry_timestamp")


def whole_utc(value):
    # A whole-second eligibility boundary is rounded up, never down.
    if value.microsecond:
        value = value.replace(microsecond=0) + timedelta(seconds=1)
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def identity(key):
    need(type(key) is str and len(key) <= 8192, "v110.registry_key")
    plain = key.split("(", 1)[0]
    name, separator, version = plain.rpartition("@")
    need(separator and NAME.fullmatch(name) and VERSION.fullmatch(version),
         "v110.registry_package_identity")
    # Keys cannot smuggle an arbitrary URI, path, quote or newline as a package.
    need(not any(part in name for part in ("..", "//")), "v110.registry_package_identity")
    return name, version


def scalar(value):
    need(type(value) is str and value and not any(c in value for c in "\r\n\t"),
         "v110.writer_scalar")
    if value.startswith("'"):
        need(value.endswith("'") and "'" not in value[1:-1], "v110.writer_scalar")
        return value[1:-1]
    if value.startswith('"'):
        result = strict_json(value.encode())
        need(type(result) is str, "v110.writer_scalar")
        return result
    need(not value.startswith(("&", "*", "!", "[", "{")), "v110.writer_scalar")
    return value


def flat_section(doc, name):
    out = {}
    for line in writer.section(doc, name).splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"  (.+?): (.+)", line)
        need(match is not None, "v110.writer_flat_section")
        key, value = scalar(match.group(1)), scalar(match.group(2))
        need(key not in out, "v110.writer_duplicate_flat_key")
        out[key] = value
    return out


def workspace_manifest(path):
    return path in ("package.json", "ui/package.json", "tools/solid-lint/package.json") or bool(
        re.fullmatch(r"(?:packages|extensions|examples)/[^/]+/package\.json", path))


def validate_source_inputs(source_inputs, now):
    checked = utc(now)
    need(utc(NOT_BEFORE) <= checked < utc(EXPIRES_AT), "v110.package_use_clock")
    need(type(source_inputs) is dict, "v110.source_inputs")
    for path, expected in FIXED_SOURCE_HASHES.items():
        raw = source_inputs.get(path)
        need(type(raw) is bytes and 0 < len(raw) <= CAP and digest(raw) == expected,
             "v110.reviewed_source_input", {"path": path})
    for path, expected in PATCHES.values():
        raw = source_inputs.get(path)
        need(type(raw) is bytes and 0 < len(raw) <= MAX_PATCH_BYTES and digest(raw) == expected,
             "v110.reviewed_patch_bytes", {"path": path})
    manifests = {}
    for path, raw in source_inputs.items():
        if workspace_manifest(path):
            manifest = strict_json(raw)
            need(type(manifest) is dict and type(manifest.get("name")) is str,
                 "v110.source_manifest")
            manifests["." if path == "package.json" else path[:-len("/package.json")]] = manifest
    need(manifests["."].get("version") == "2026.10.10" and
         manifests["."].get("packageManager") == PNPM_SPEC, "v110.source_toolchain")
    return manifests


def importer_requirements(chunk):
    groups, current_group, current_name = {}, None, None
    for line in chunk.splitlines()[1:]:
        if not line.strip():
            continue
        group = re.fullmatch(r"    ([A-Za-z]+):(?: \{\})?", line)
        item = re.fullmatch(r"      (.+):", line)
        field = re.fullmatch(r"        (specifier|version): (.+)", line)
        if group:
            current_group = group.group(1)
            need(current_group in ("dependencies", "devDependencies", "optionalDependencies") and
                 current_group not in groups, "v110.importer_group")
            groups[current_group], current_name = {}, None
        elif item:
            need(current_group is not None, "v110.importer_shape")
            current_name = scalar(item.group(1))
            need(current_name not in groups[current_group], "v110.importer_duplicate_dependency")
            groups[current_group][current_name] = {}
        elif field:
            need(current_name is not None, "v110.importer_shape")
            name, value = field.group(1), scalar(field.group(2))
            fields = groups[current_group][current_name]
            need(name not in fields, "v110.importer_duplicate_field")
            fields[name] = value
        else:
            need(False, "v110.importer_shape")
    for deps in groups.values():
        need(all(set(fields) == {"specifier", "version"} for fields in deps.values()),
             "v110.importer_explicit_resolution")
    return groups


def check_importers(doc, manifests, overrides, packages):
    importers = writer.entries(doc, "importers")
    need(set(importers) == set(manifests), "v110.complete_workspace_importers")
    for path, chunk in importers.items():
        groups, manifest = importer_requirements(chunk), manifests[path]
        for group in ("dependencies", "devDependencies", "optionalDependencies"):
            wanted = manifest.get(group, {})
            need(type(wanted) is dict and all(type(k) is str and type(v) is str for k, v in wanted.items()),
                 "v110.manifest_dependency_shape")
            observed = groups.get(group, {})
            # Optional peer auto-install may add a declared peer at its normal
            # pnpm owner, but cannot introduce an undeclared package.
            peers = manifest.get("peerDependencies", {})
            need(type(peers) is dict, "v110.manifest_peer_shape")
            need(set(wanted) <= set(observed) and set(observed) <= set(wanted) | set(peers),
                 "v110.importer_dependency_membership", {"importer": path, "group": group})
            for name, fields in observed.items():
                spec = wanted.get(name, peers.get(name))
                allowed = {spec}
                if name in overrides:
                    allowed.add(overrides[name])
                if name == "zod" and re.fullmatch(r"4\.[0-9]+\.[0-9]+", spec or "") and tuple(map(int, spec.split("."))) < (4, 6, 6):
                    allowed.add("4.6.6")
                need(fields["specifier"] in allowed, "v110.importer_specifier", {"importer": path, "dependency": name})
                resolved = fields["version"]
                if resolved.startswith("link:"):
                    target = posixpath.normpath(posixpath.join("" if path == "." else path, resolved[5:]))
                    need(target in manifests and manifests[target].get("name") == name,
                         "v110.workspace_link_target")
                    need(type(spec) is str and spec.startswith(("workspace:", "link:", "file:")),
                         "v110.workspace_link_specifier")
                else:
                    child = identity(name + "@" + resolved) if resolved[:1].isdigit() else identity(
                        resolved.removeprefix("npm:"))
                    need(child[0] + "@" + child[1] in packages, "v110.importer_registry_membership")
                    effective = fields["specifier"]
                    if VERSION.fullmatch(effective):
                        need(child == (name, effective), "v110.importer_exact_version")
                    elif effective.startswith("npm:"):
                        need(child == identity(effective[4:]), "v110.importer_exact_alias")
    return len(importers)


def parsed_lock(raw):
    try:
        bootstrap, project = writer.documents(raw)
        tables = [{name: writer.entries(doc, name) for name in ("packages", "snapshots")}
                  for doc in (bootstrap, project)]
    except writer.LockRefusal as error:
        raise LockRefusal("v110." + str(error).removeprefix("v9."))
    return bootstrap, project, tables


def selected_packages(tables):
    selected = {}
    for table in tables:
        identities = {identity(key) for key in table["packages"]}
        need({identity(key) for key in table["snapshots"]} == identities,
             "v110.package_snapshot_membership")
        for key, chunk in table["packages"].items():
            name, version = identity(key)
            need(key == name + "@" + version, "v110.package_key_plain")
            matches = re.findall(r"^    resolution: \{integrity: (sha512-[A-Za-z0-9+/=]+)\}$", chunk, re.M)
            need(len(matches) == 1, "v110.registry_integrity_resolution", {"name": name, "version": version})
            integrity = matches[0]
            try:
                match = SRI.fullmatch(integrity)
                need(match is not None and len(base64.b64decode(match.group(1), validate=True)) == 64,
                     "v110.registry_integrity_encoding")
            except ValueError:
                raise LockRefusal("v110.registry_integrity_encoding")
            previous = selected.get((name, version))
            need(previous is None or previous == integrity, "v110.conflicting_registry_integrity")
            selected[name, version] = integrity
    need(0 < len(selected) <= MAX_PACKAGES, "v110.selected_package_count")
    return selected


def snapshot_edges(chunk):
    edges, group, seen = {}, None, set()
    for line in chunk.splitlines()[1:]:
        header = re.fullmatch(r"    ([A-Za-z][A-Za-z0-9]*):(.*)", line)
        if header:
            name, tail = header.group(1), header.group(2)
            need(name not in seen, "v110.snapshot_duplicate_field")
            seen.add(name)
            if name in ("dependencies", "optionalDependencies"):
                need(tail in ("", " {}"), "v110.snapshot_edge_shape")
                group = name if tail == "" else None
            else:
                group = None
            continue
        if group not in ("dependencies", "optionalDependencies") or not line.strip():
            continue
        edge = re.fullmatch(r"      (.+?): (.+)", line)
        need(edge is not None, "v110.snapshot_edge_shape")
        name, raw = scalar(edge.group(1)), scalar(edge.group(2))
        need(name not in edges, "v110.snapshot_duplicate_edge")
        if raw.startswith("npm:"):
            child = identity(raw[4:])
        elif raw[:1].isdigit():
            child = identity(name + "@" + raw)
        else:
            child = identity(raw)
        edges[name] = child
    return edges


def validate_msal_closure(node_versions, common_versions, consumers):
    required = {"@azure/msal-node@7.1.1": "16.14.3"}
    with_browser = {**required, "@azure/msal-browser@5.24.0": "16.14.2"}
    need(type(consumers) is dict and consumers in (required, with_browser),
         "v110.reviewed_msal_common_consumers")
    need(node_versions == {"7.1.1"} and common_versions == set(consumers.values()),
         "v110.closed_msal_selected_versions")
    return consumers


def msal_common_consumers(table):
    """Positively bind the only reviewed Common consumers, including aliases."""
    versions, consumers = defaultdict(set), {}
    for key in table["packages"]:
        name, version = identity(key)
        versions[name].add(version)
    for key, chunk in table["snapshots"].items():
        name, version = identity(key)
        parent = name + "@" + version
        for edge_name, (child_name, child_version) in snapshot_edges(chunk).items():
            if child_name != "@azure/msal-common":
                continue
            need(parent in table["packages"] and edge_name == child_name,
                 "v110.reviewed_msal_common_consumers")
            need(parent not in consumers or consumers[parent] == child_version,
                 "v110.reviewed_msal_common_consumers")
            consumers[parent] = child_version
    return validate_msal_closure(versions["@azure/msal-node"],
                                 versions["@azure/msal-common"], consumers)


def verify_security(doc, table):
    registered = flat_section(doc, "patchedDependencies")
    need(registered == {key: value[1] for key, value in PATCHES.items()}, "v110.exact_patch_registration")
    versions = defaultdict(set)
    for key in table["packages"]:
        name, version = identity(key)
        versions[name].add(version)
    for name, wanted in FIXED_GLOBAL_VERSIONS.items():
        need(versions[name] == {wanted}, "v110.fixed_global_security_version", {"name": name})
    need(versions["zod"] and all(re.fullmatch(r"4\.\d+\.\d+", v) and
         tuple(map(int, v.split("."))) >= (4, 6, 6) for v in versions["zod"]), "v110.no_legacy_zod_resolution")
    need("4.6.6" in versions["zod"], "v110.root_zod_patch_selected")
    for version in versions["undici"]:
        numeric = re.fullmatch(r"8\.(\d+)\.(\d+)", version)
        need(numeric is not None and (int(numeric[1]), int(numeric[2])) >= (12, 2),
             "v110.no_vulnerable_undici8")
    parents = defaultdict(list)
    for key, chunk in table["snapshots"].items():
        name, version = identity(key)
        plain = name + "@" + version
        if plain in PATCHES:
            need("(patch_hash=" + PATCHES[plain][1] + ")" in key,
                 "v110.exact_patch_snapshot", {"package": plain})
        edges = snapshot_edges(chunk)
        need(all(child_name + "@" + child_version in table["packages"]
                 for child_name, child_version in edges.values()), "v110.closed_snapshot_edges")
        parents[plain].append(edges)
        if plain == "@a2ui/web_core@0.12.0":
            need("zod-to-json-schema" not in edges, "v110.retired_converter_edge")
    for parent, expected in FIXED_EDGES.items():
        need(parents[parent], "v110.required_security_parent", {"parent": parent})
        for edges in parents[parent]:
            for name, version in expected.items():
                need(edges.get(name) == (name, version), "v110.exact_security_parent_edge",
                     {"parent": parent, "dependency": name})
    msal_common_consumers(table)
    return {name: sorted(versions[name]) for name in sorted(set(FIXED_GLOBAL_VERSIONS) |
            {"zod", "undici", "npm", "vitest", "@azure/msal-node", "@azure/msal-common"})}


def verify_age_and_integrity(selected, registry_lookup, now):
    checked = utc(now)
    need(callable(registry_lookup), "v110.registry_lookup_required")
    need(type(selected) is dict and 0 < len(selected) <= MAX_PACKAGES,
         "v110.selected_package_count")
    by_name = defaultdict(list)
    for key, integrity in selected.items():
        need(type(key) is tuple and len(key) == 2 and all(type(v) is str for v in key),
             "v110.registry_package_identity")
        name, version = key
        need(identity(name + "@" + version) == key and type(integrity) is str and SRI.fullmatch(integrity),
             "v110.registry_package_identity")
        by_name[name].append((version, integrity))
    rows = []
    for name in sorted(by_name):
        try:
            raw = registry_lookup(name)
        except LockRefusal:
            raise
        except Exception:
            raise LockRefusal("v110.registry_lookup_failed", {"name": name}) from None
        meta = strict_json(raw, PublicRegistry.MAX_BODY)
        need(type(meta) is dict and meta.get("name") == name and
             type(meta.get("versions")) is dict and type(meta.get("time")) is dict,
             "v110.registry_packument_identity", {"name": name})
        for version, integrity in sorted(by_name[name]):
            version_meta = meta["versions"].get(version)
            need(type(version_meta) is dict and version_meta.get("name") == name and
                 version_meta.get("version") == version and type(version_meta.get("dist")) is dict,
                 "v110.registry_selected_version", {"name": name, "version": version})
            need(version_meta["dist"].get("integrity") == integrity,
                 "v110.registry_selected_integrity", {"name": name, "version": version})
            published_raw = meta["time"].get(version)
            published = utc(published_raw)
            need(published <= checked, "v110.registry_future_publication", {"name": name, "version": version})
            eligible = published + timedelta(minutes=MINIMUM_AGE_MINUTES)
            need(eligible <= checked, "v110.minimum_release_age", {"name": name, "version": version,
                 "eligibleAt": whole_utc(eligible)})
            rows.append({"name": name, "version": version, "integrity": integrity,
                         "publishedAt": published_raw, "eligibleAt": whole_utc(eligible)})
    need(len(rows) == len(selected), "v110.complete_closure_age_coverage")
    latest = max(rows, key=lambda row: utc(row["publishedAt"]))
    return {"schema": "openclaw.v110.complete-closure-age.v1", "observedAt": now,
            "minimumReleaseAgeMinutes": MINIMUM_AGE_MINUTES, "strict": True,
            "selectedTupleCount": len(selected), "checkedTupleCount": len(rows),
            "registryPackageCount": len(by_name), "unknownTupleCount": 0,
            "allSelectedExclusionsAlsoChecked": True, "tuplesSha256": digest(canonical(rows)),
            "maximumPublishedAt": latest["publishedAt"], "maximumEligibleAt": latest["eligibleAt"],
            "rawRegistryMetadataRetainedInArtifact": False}


def verify_bootstrap_age(before, registry_lookup, now):
    bootstrap, _, tables = parsed_lock(before)
    need(digest(bootstrap.encode()) == BOOTSTRAP_SHA256, "v110.reviewed_pnpm_bootstrap")
    return verify_age_and_integrity(selected_packages(tables[:1]), registry_lookup, now)


def verify_generated_lock(before, generated, source_inputs, registry_lookup, now):
    manifests = validate_source_inputs(source_inputs, now)
    old_bootstrap, _, _ = parsed_lock(before)
    bootstrap, doc, tables = parsed_lock(generated)
    need(old_bootstrap == bootstrap and digest(bootstrap.encode()) == BOOTSTRAP_SHA256,
         "v110.pnpm_bootstrap_unchanged")
    workspace = source_inputs["pnpm-workspace.yaml"].decode()
    expected_overrides = flat_section(workspace, "overrides")
    need(flat_section(doc, "overrides") == expected_overrides, "v110.source_overrides_preserved")
    importer_count = check_importers(doc, manifests, expected_overrides, tables[1]["packages"])
    selected = selected_packages(tables)
    critical = verify_security(doc, tables[1])
    age = verify_age_and_integrity(selected, registry_lookup, now)
    return {"schema": "openclaw.v110.generated-lock-security.v1", "beforeLockSha256": digest(before),
            "generatedLockSha256": digest(generated), "workspaceImporters": importer_count,
            "criticalVersionSets": critical, "msalCommonConsumers": msal_common_consumers(tables[1]),
            "patchesSha256": digest(canonical(
                {name: sha for name, (_, sha) in PATCHES.items()})), "closureAge": age,
            "allSelectedRegistryIntegritiesMatched": True, "nativeAdvisoryAuditsStillRequired": True,
            "exactGeneratedDiffReviewRequiredBeforeCommit": True,
            "unrelatedGeneratedDiffAutomaticallyApproved": False, "qualified": False,
            "imageBuilt": False, "productionAuthorized": False}


def validate_generated_summary(summary, before_sha256, generated_sha256, finished_at):
    """Validate the same owner's compact output before authentic artifact use.

    This validates shape and consistency, not producer authenticity. The source
    contract separately authenticates the actual hosted run, artifact and hashes.
    """
    need(type(summary) is dict and set(summary) == {"schema", "beforeLockSha256",
         "generatedLockSha256", "workspaceImporters", "criticalVersionSets", "msalCommonConsumers", "patchesSha256",
         "closureAge", "allSelectedRegistryIntegritiesMatched", "nativeAdvisoryAuditsStillRequired",
         "exactGeneratedDiffReviewRequiredBeforeCommit", "unrelatedGeneratedDiffAutomaticallyApproved",
         "qualified", "imageBuilt", "productionAuthorized"}, "v110.security_summary_shape")
    hashes = (before_sha256, generated_sha256, summary["patchesSha256"])
    need(all(type(v) is str and re.fullmatch(r"[0-9a-f]{64}", v) for v in hashes),
         "v110.security_summary_hash")
    need(summary["schema"] == "openclaw.v110.generated-lock-security.v1" and
         summary["beforeLockSha256"] == before_sha256 and
         summary["generatedLockSha256"] == generated_sha256 and
         summary["patchesSha256"] == digest(canonical({name: sha for name, (_, sha) in PATCHES.items()})),
         "v110.security_summary_identity")
    need(type(summary["workspaceImporters"]) is int and 0 < summary["workspaceImporters"] <= 1000,
         "v110.security_summary_importers")
    for name in ("allSelectedRegistryIntegritiesMatched", "nativeAdvisoryAuditsStillRequired",
                 "exactGeneratedDiffReviewRequiredBeforeCommit"):
        need(summary[name] is True, "v110.security_summary_required_flag")
    for name in ("unrelatedGeneratedDiffAutomaticallyApproved", "qualified", "imageBuilt", "productionAuthorized"):
        need(summary[name] is False, "v110.security_summary_unqualified")
    critical = summary["criticalVersionSets"]
    expected_names = set(FIXED_GLOBAL_VERSIONS) | {"zod", "undici", "npm", "vitest",
                                                 "@azure/msal-node", "@azure/msal-common"}
    need(type(critical) is dict and set(critical) == expected_names, "v110.security_summary_critical")
    for name, values in critical.items():
        need(type(values) is list and values and len(values) <= MAX_PACKAGES and
             all(type(v) is str and VERSION.fullmatch(v) for v in values) and values == sorted(set(values)),
             "v110.security_summary_versions")
    for name, version in FIXED_GLOBAL_VERSIONS.items():
        need(critical[name] == [version], "v110.security_summary_fixed_version")
    need("4.6.6" in critical["zod"] and all(re.fullmatch(r"4\.\d+\.\d+", v) and
         tuple(map(int, v.split("."))) >= (4, 6, 6) for v in critical["zod"]),
         "v110.security_summary_zod")
    need("8.12.2" in critical["undici"] and all(re.fullmatch(r"8\.\d+\.\d+", v) and
         tuple(map(int, v.split("."))) >= (8, 12, 2) for v in critical["undici"]),
         "v110.security_summary_undici")
    need("12.2.1" in critical["npm"] and "5.0.5" in critical["vitest"],
         "v110.security_summary_selected_versions")
    validate_msal_closure(set(critical["@azure/msal-node"]), set(critical["@azure/msal-common"]),
                          summary["msalCommonConsumers"])
    age = summary["closureAge"]
    need(type(age) is dict and set(age) == {"schema", "observedAt", "minimumReleaseAgeMinutes",
         "strict", "selectedTupleCount", "checkedTupleCount", "registryPackageCount",
         "unknownTupleCount", "allSelectedExclusionsAlsoChecked", "tuplesSha256",
         "maximumPublishedAt", "maximumEligibleAt", "rawRegistryMetadataRetainedInArtifact"},
         "v110.age_summary_shape")
    need(age["schema"] == "openclaw.v110.complete-closure-age.v1" and
         type(age["minimumReleaseAgeMinutes"]) is int and age["minimumReleaseAgeMinutes"] == 10080 and
         age["strict"] is True and age["allSelectedExclusionsAlsoChecked"] is True and
         age["rawRegistryMetadataRetainedInArtifact"] is False and
         type(age["unknownTupleCount"]) is int and age["unknownTupleCount"] == 0,
         "v110.age_summary_flags")
    selected, checked, names = (age[k] for k in ("selectedTupleCount", "checkedTupleCount", "registryPackageCount"))
    need(all(type(v) is int for v in (selected, checked, names)) and
         0 < selected == checked <= MAX_PACKAGES and 0 < names <= selected,
         "v110.age_summary_complete")
    need(type(age["tuplesSha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", age["tuplesSha256"]),
         "v110.age_summary_digest")
    observed, finished = utc(age["observedAt"]), utc(finished_at)
    published, eligible = utc(age["maximumPublishedAt"]), utc(age["maximumEligibleAt"])
    need(utc(NOT_BEFORE) <= observed <= finished < utc(EXPIRES_AT) and
         published <= observed and eligible <= observed and
         whole_utc(published + timedelta(minutes=MINIMUM_AGE_MINUTES)) == age["maximumEligibleAt"],
         "v110.age_summary_clock")
    return summary


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PublicRegistry:
    """Bounded public packument transport. Construction does not make a request."""
    MAX_BODY = 32 * 1024 * 1024
    MAX_TOTAL = 2 * 1024 * 1024 * 1024

    def __init__(self, deadline_epoch, *, opener=None, clock=time.time):
        need(type(deadline_epoch) in (int, float) and math.isfinite(deadline_epoch),
             "v110.registry_deadline")
        self.deadline, self.clock, self.requests, self.total = deadline_epoch, clock, set(), 0
        self.opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def __call__(self, name):
        need(type(name) is str and NAME.fullmatch(name) and ".." not in name and "//" not in name,
             "v110.registry_name")
        need(name not in self.requests and len(self.requests) < MAX_PACKAGES, "v110.registry_request_count")
        remaining = self.deadline - self.clock()
        need(remaining > 0, "v110.registry_deadline")
        self.requests.add(name)
        url = "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="")
        request = urllib.request.Request(url, headers={"Accept": "application/json",
            "Accept-Encoding": "identity", "Cache-Control": "max-age=0, no-cache",
            "User-Agent": "OpenClaw-fixed-source-age-check/10.10"})
        try:
            with self.opener.open(request, timeout=min(15, remaining)) as response:
                need(response.status == 200 and response.geturl() == url, "v110.registry_route")
                need(response.headers.get_content_type() == "application/json" and
                     response.headers.get("Content-Encoding", "identity") == "identity",
                     "v110.registry_response_type")
                raw = bytearray()
                while True:
                    need(self.clock() < self.deadline, "v110.registry_deadline")
                    chunk = response.read(min(65536, self.MAX_BODY + 1 - len(raw)))
                    if not chunk:
                        break
                    raw.extend(chunk)
                    self.total += len(chunk)
                    need(len(raw) <= self.MAX_BODY and self.total <= self.MAX_TOTAL,
                         "v110.registry_response_cap")
                need(raw, "v110.registry_response_empty")
                return bytes(raw)
        except urllib.error.HTTPError as error:
            raise LockRefusal("v110.registry_http_refused", {"name": name, "status": error.code}) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise LockRefusal("v110.registry_transport_failed", {"name": name}) from None

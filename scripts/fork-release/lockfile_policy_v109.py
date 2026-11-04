"""Fixed pnpm12 lock admission for the reviewed 10.9 graph, not a YAML resolver.

The maintained package-patch checker still owns installed patch registration.
This early gate protects the carried Zod4 graph before a generated lock can be
committed: it must never silently admit new/unpatched Zod3 or edit the workspace.
All remaining generated changes are retained for independent exact-diff review.
"""
import hashlib
import re
import json
from datetime import datetime, timezone
import bounded_run_contract_v109 as authority


CAP = 2 * 1024 * 1024
CRITICAL = ("body-parser", "qs", "re2js", "zod", "undici", "npm", "vitest", "fast-uri", "nodemailer")
ZOD_HASH = "9fe4b383c96309498941cafec0f003951e8c68447c668202dc6f122cc4029be2"


class LockRefusal(ValueError):
    pass


def need(value, code):
    if not value:
        raise LockRefusal(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def documents(raw):
    need(type(raw) is bytes and 0 < len(raw) <= CAP and b"\r" not in raw and b"\t" not in raw,
         "v9.lock_bounded_writer_dialect")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise LockRefusal("v9.lock_utf8")
    parts = text.split("---\n")
    need(len(parts) == 3 and parts[0] == "" and
        all(p.startswith("lockfileVersion: '9.0'\n") for p in parts[1:]), "v9.two_pnpm_documents")
    return parts[1], parts[2]


def section(text, name):
    names = re.findall(r"^([A-Za-z][A-Za-z0-9]*):", text, re.M)
    need(len(names) == len(set(names)) and name in names, "v9.unique_lock_sections")
    marker = "\n" + name + ":\n"
    need(text.count(marker) == 1, "v9.explicit_lock_section")
    tail = text.split(marker, 1)[1]
    following = re.search(r"\n[A-Za-z][A-Za-z0-9]*:", tail)
    return tail[:following.start()] if following else tail


def entries(text, name):
    body = section(text, name)
    result, current, chunk = {}, None, []
    for line in body.splitlines():
        if line.startswith("  ") and not line.startswith("   "):
            need(line.endswith(":") or line.endswith(": {}"), "v9.lock_entry_shape")
            if current is not None:
                result[current] = "\n".join(chunk)
            key = line[2:-1] if line.endswith(":") else line[2:-4]
            if key.startswith(("'", '"')):
                need(len(key) >= 2 and key[-1] == key[0] and key[0] not in key[1:-1],
                     "v9.lock_entry_quote")
                key = key[1:-1]
            need(key and key not in result and key != current, "v9.unique_lock_entries")
            current, chunk = key, [line]
        elif line and not line.startswith("    "):
            need(False, "v9.lock_entry_indentation")
        elif current is not None:
            chunk.append(line)
    if current is not None:
        result[current] = "\n".join(chunk)
    need(bool(result), "v9.positive_lock_entries")
    return result


def versions(table, package):
    prefix = package + "@"
    result = set()
    for key in table:
        if key.startswith(prefix):
            version = key[len(prefix):].split("(", 1)[0]
            need(re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", version), "v9.explicit_resolved_version")
            result.add(version)
    need(bool(result), "v9.positive_critical_package")
    return result


def common_edges(snapshots):
    """Exact direct Common consumers in the fixed pnpm writer dialect."""
    result = {}
    for parent, entry in snapshots.items():
        lines = entry.splitlines()[1:]
        mentions = [line for line in lines if "@azure/msal-common" in line]
        values = re.findall(r"^      '@azure/msal-common': ([^\n]+)$", entry, re.M)
        need(len(mentions) == len(values) and len(values) <= 1, "v9.explicit_msal_common_edges")
        if values:
            need(values[0] in ("16.14.2", "16.14.3"), "v9.selected_msal_common_16_14_3")
            result[parent] = values[0]
    return result


def verify_common_consumers(old, new):
    old_edges, new_edges = common_edges(old["snapshots"]), common_edges(new["snapshots"])
    node_versions = versions(old["snapshots"], "@azure/msal-node")
    need(node_versions in ({"7.1.0"}, {"7.1.1"}), "v9.selected_msal_7_1_1")
    old_node = "@azure/msal-node@" + next(iter(node_versions))
    old_child = "16.14.2" if node_versions == {"7.1.0"} else "16.14.3"
    need(old_edges.get(old_node) == old_child, "v9.exact_msal_parent_child_edge")
    carried = {parent: child for parent, child in old_edges.items() if parent != old_node}
    need(carried in ({}, {"@azure/msal-browser@5.24.0": "16.14.2"}),
         "v9.carried_msal_common_consumers")
    expected = {**carried, "@azure/msal-node@7.1.1": "16.14.3"}
    need(new_edges == expected, "v9.exact_msal_parent_child_edge")
    for parent in carried:
        need(new["snapshots"].get(parent) == old["snapshots"][parent],
             "v9.carried_msal_consumer_unchanged")
        package = parent.split("(", 1)[0]
        need(package in old["packages"] and new["packages"].get(package) == old["packages"][package],
             "v9.carried_msal_consumer_unchanged")
    for table in ("packages", "snapshots"):
        need(versions(old[table], "@azure/msal-common") == set(old_edges.values()) and
            versions(new[table], "@azure/msal-common") == set(expected.values()),
             "v9.selected_msal_common_16_14_3")
        for child in set(carried.values()):
            key = "@azure/msal-common@" + child
            need(key in old[table] and new[table].get(key) == old[table][key],
                 "v9.carried_msal_common_unchanged")
    return carried


def verify_lock_security(before, generated, expected_msal_integrity, expected_common_integrity, *, h3=None):
    old_bootstrap, old_doc = documents(before)
    new_bootstrap, new_doc = documents(generated)
    need(old_bootstrap == new_bootstrap, "v9.pnpm_bootstrap_document_unchanged")
    old = {name: entries(old_doc, name) for name in ("packages", "snapshots")}
    new = {name: entries(new_doc, name) for name in ("packages", "snapshots")}
    catalogs = {}
    for name in ("packages", "snapshots"):
        before_versions = {p: versions(old[name], p) for p in CRITICAL}
        after_versions = {p: versions(new[name], p) for p in CRITICAL}
        need(before_versions["zod"] == after_versions["zod"] == {"4.6.6"}, "v9.no_unpatched_zod3_resolution")
        need(all(before_versions[p] == after_versions[p] for p in CRITICAL),
             "v9.carried_security_versions_preserved")
        need(versions(old[name], "@azure/msal-node") in ({"7.1.0"}, {"7.1.1"}) and
            versions(new[name], "@azure/msal-node") == {"7.1.1"}, "v9.selected_msal_7_1_1")
        catalogs[name] = {p: sorted(v) for p, v in after_versions.items()}
    carried_common = verify_common_consumers(old, new)
    need("zod@4.6.6(patch_hash=" + ZOD_HASH + ")" in new["snapshots"] and
        len([key for key in new["snapshots"] if key.startswith("zod@")]) == 1,
        "v9.zod4_patch_snapshot_preserved")
    for package, integrity in (("@azure/msal-node@7.1.1", expected_msal_integrity),
                               ("@azure/msal-common@16.14.3", expected_common_integrity)):
        need(type(integrity) is str and re.fullmatch(r"sha512-[A-Za-z0-9+/]{86}==", integrity),
             "v9.msal_registry_integrity")
        observed = re.findall(r"^    resolution: \{integrity: (sha512-[A-Za-z0-9+/=]+)\}$",
                              new["packages"].get(package, ""), re.M)
        need(observed == [integrity], "v9.msal_lock_integrity_matches_registry")
    edge = re.findall(r"^      '@azure/msal-common': ([^\n]+)$",
                      new["snapshots"]["@azure/msal-node@7.1.1"], re.M)
    need(edge == ["16.14.3"], "v9.exact_msal_parent_child_edge")
    result = {"schema": "openclaw.v109.generated-lock-security.v1", "beforeLockSha256": digest(before),
        "generatedLockSha256": digest(generated), "criticalVersionSets": catalogs,
        "zod4PatchHash": ZOD_HASH, "newUnpatchedZod3Absent": True,
        "selectedMsalNodeVersion": "7.1.1", "selectedMsalNodeIntegrity": expected_msal_integrity,
        "selectedMsalCommonVersion": "16.14.3", "selectedMsalCommonIntegrity": expected_common_integrity,
        "carriedMsalCommonConsumers": carried_common, "unexpectedMsalCommonConsumerAbsent": True,
        "unrelatedGeneratedDiffAutomaticallyApproved": False,
        "exactGeneratedDiffReviewRequiredBeforeCommit": True}
    if h3 is not None:
        result["sourceSuccessor"] = verify_h3_lock_delta(before, generated, old, new, h3)
    return result


H3_TARGETS = {"follow-redirects": ("1.16.1", "1.16.2"), "joi": ("18.2.9", "18.3.1"),
    "minimatch": ("10.2.6", "11.0.1"), "glob": ("13.0.6", "14.0.2")}
H3_FIXED_SELECTORS = {"follow-redirects": "1.16.2", "mailauth@7.1.0>joi": "18.3.1",
    "minimatch": "11.0.1", "cacache@21.0.1>glob": "14.0.2"}


def strict_json(raw):
    need(type(raw) is bytes and 0 < len(raw) <= CAP, "v9.h3_metadata_bounded")
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, "v9.h3_metadata_duplicate")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
            parse_constant=lambda _: need(False, "v9.h3_metadata_constant"))
    except (ValueError, UnicodeError):
        raise LockRefusal("v9.h3_metadata_json")


def validate_h3_source_inputs(h3):
    need(type(h3) is dict and set(h3) == {"amendmentSha256", "sourceGeneration", "checkedAt",
        "packageBytes", "workspaceBytes", "fileTransferPackageBytes", "excludedAgeProofBytes", "excludedAgeProofSha256", "targetMetadataProofBytes", "targetMetadataProofSha256"} and
        h3["amendmentSha256"] == authority.H3_AMENDMENT_SHA256 and type(h3["sourceGeneration"]) is int and
        1 <= h3["sourceGeneration"] <= 3 and type(h3["checkedAt"]) is str, "v9.h3_lock_authority")
    try:
        checked = datetime.strptime(h3["checkedAt"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise LockRefusal("v9.h3_lock_clock")
    need(checked.strftime("%Y-%m-%dT%H:%M:%SZ") == h3["checkedAt"] and
        authority.utc(authority.H3_NOT_BEFORE) <= checked < authority.utc(authority.H3_EXPIRES_AT), "v9.h3_lock_package_use_floor")
    for key in ("packageBytes", "workspaceBytes", "fileTransferPackageBytes"):
        need(type(h3[key]) is bytes and 0 < len(h3[key]) <= CAP, "v9.h3_positive_source_bytes")
    root, transfer = strict_json(h3["packageBytes"]), strict_json(h3["fileTransferPackageBytes"])
    need(root.get("dependencies", {}).get("minimatch") == transfer.get("dependencies", {}).get("minimatch") == "11.0.1", "v9.h3_direct_minimatch_pins")
    workspace = h3["workspaceBytes"].decode("utf-8")
    need(re.findall(r"^minimumReleaseAge: (.+)$", workspace, re.M) == ["10080"] and
        re.findall(r"^minimumReleaseAgeStrict: (.+)$", workspace, re.M) == ["true"], "v9.h3_minimum_age_policy")
    tail = workspace.split("minimumReleaseAgeExclude:\n")
    need(len(tail) == 2, "v9.h3_explicit_age_exclusions")
    block = re.split(r"^[A-Za-z][A-Za-z0-9]*:", tail[1], maxsplit=1, flags=re.M)[0]
    excluded = []
    for line in block.splitlines():
        if not line.strip() or line.lstrip().startswith("#"): continue
        match = re.fullmatch(r'  - "([^"\n]+)"', line)
        need(match is not None, "v9.h3_age_exclusion_writer_dialect")
        excluded.append(match.group(1))
    proof_rows = strict_json(h3["excludedAgeProofBytes"])["tuples"]
    expected_exclusions = {"@openai/codex", "@openai/codex-*"} | {
        row["name"] + "@" + row["version"] for row in proof_rows if row["name"].startswith("@openclaw/fs-safe")}
    need(len(excluded) == len(set(excluded)) and set(excluded) == expected_exclusions,
        "v9.h3_no_new_minimum_age_exception")
    for selector, expected in H3_FIXED_SELECTORS.items():
        quoted = re.escape(selector)
        found = re.findall(r"^  [\"']?" + quoted + r"[\"']?: ([^\n]+)$", workspace, re.M)
        need(found == [expected], "v9.h3_exact_parent_selectors")
    for forbidden in ("joi", "glob", "mailauth@7.0.0>joi", "cacache@21.0.0>glob"):
        need(not re.search(r"^  [\"']?" + re.escape(forbidden) + r"[\"']?:", workspace, re.M), "v9.h3_no_broad_parent_override")
    verify_h3_target_metadata(h3, checked)
    return checked


def snapshot_edges(table):
    graph = {}
    for key, chunk in table.items():
        edges = []
        for line in chunk.splitlines()[1:]:
            match = re.fullmatch(r"      ('[^']+'|[^: ]+): (.+)", line)
            if not match: continue
            name, version = match.groups(); name = name.strip("'")
            selected = version.strip("'")
            candidate = selected if selected in table else name + "@" + selected
            if candidate in table: edges.append(candidate)
            elif not version.startswith(("link:", "file:", "workspace:")):
                # This is a complete selected graph, not a guessed dependency.
                need(False, "v9.h3_snapshot_edge_unresolved")
        graph[key] = edges
    return graph


def affected_closure(table):
    graph = snapshot_edges(table)
    found = {key for key in table if any(key.startswith(name + "@") for name in H3_TARGETS)}
    pending = list(found)
    while pending:
        for child in graph[pending.pop()]:
            if child not in found: found.add(child); pending.append(child)
    return found


def replace_h3_edges(chunk, parent):
    lines = []
    for line in chunk.split("\n"):
        for name, (old, new) in H3_TARGETS.items():
            allowed = name in ("follow-redirects", "minimatch") or (name == "joi" and parent == "mailauth@7.1.0") or (name == "glob" and parent == "cacache@21.0.1")
            if allowed:
                line = re.sub(r"^(      ['\"]?" + re.escape(name) + r"['\"]?: )" + re.escape(old) + r"(\([^\n]*\))?$", lambda m: m.group(1) + new + (m.group(2) or ""), line)
        lines.append(line)
    return "\n".join(lines)



def retains_reviewed_h3_warning(key, before, generated):
    # Registry metadata added this authentic warning without changing package bytes.
    # Preserve it; this exception admits no dependency upgrade or security waiver.
    # https://github.com/aws/aws-sdk-js-v3/issues/8393
    if key != "@smithy/core@3.35.1" or "\n    deprecated:" in before:
        return False
    resolution = "    resolution: {integrity: sha512-i4YPS4B6ts7bjn7UwLnGjiZdprOvHvgGobFZsYK3GIY3E5hIqtj0rReU69BcTpGp+fvtraSNXeG1l+jtJvF55w==}\n"
    warning = "    deprecated: Deprecated due to a bug in custom logger data redaction. See https://github.com/aws/aws-sdk-js-v3/issues/8393."
    lines = generated.split("\n")
    return (before.count(resolution) == 1 and lines.count(warning) == 1 and
        [line for line in lines if line != warning] == before.split("\n"))


def verify_h3_lock_delta(before, generated, old, new, h3):
    checked = validate_h3_source_inputs(h3)
    target_metadata = verify_h3_target_metadata(h3, checked)
    for name, (old_version, new_version) in H3_TARGETS.items():
        for table in ("packages", "snapshots"):
            need(versions(old[table], name) in ({old_version}, {new_version}) and
                versions(new[table], name) == {new_version}, "v9.h3_selected_security_versions")
    for name, row in target_metadata.items():
        found = re.findall(r"^    resolution: \{integrity: (sha512-[A-Za-z0-9+/=]+)\}$",
            new["packages"].get(name + "@" + row["version"], ""), re.M)
        need(found == [row["integrity"]], "v9.h3_target_native_metadata_integrity")
    old_affected, new_affected = affected_closure(old["snapshots"]), affected_closure(new["snapshots"])
    for table in ("packages", "snapshots"):
        affected_old = {key.split("(", 1)[0] for key in old_affected} if table == "packages" else old_affected
        affected_new = {key.split("(", 1)[0] for key in new_affected} if table == "packages" else new_affected
        need(set(old[table]) - affected_old == set(new[table]) - affected_new, "v9.h3_no_unrelated_graph_add_remove")
        for key in set(old[table]) - affected_old:
            expected = replace_h3_edges(old[table][key], key) if table == "snapshots" else old[table][key]
            need(new[table][key] == expected or
                (table == "packages" and retains_reviewed_h3_warning(key, expected, new[table][key])),
                "v9.h3_unrelated_package_unchanged")
    old_doc, new_doc = documents(before)[1], documents(generated)[1]
    old_importers, new_importers = entries(old_doc, "importers"), entries(new_doc, "importers")
    need(set(old_importers) == set(new_importers), "v9.h3_importer_roots_unchanged")
    for importer in old_importers:
        expected = old_importers[importer]
        if importer in (".", "extensions/file-transfer"):
            expected = re.sub(r"(minimatch:\n        specifier: )10\.2\.6(\n        version: )10\.2\.6", r"\g<1>11.0.1\g<2>11.0.1", expected)
        need(new_importers[importer] == expected, "v9.h3_unrelated_importer_unchanged")
    # All other document sections remain exact except the four approved overrides.
    old_names = re.findall(r"^([A-Za-z][A-Za-z0-9]*):", old_doc, re.M)
    new_names = re.findall(r"^([A-Za-z][A-Za-z0-9]*):", new_doc, re.M)
    need(old_names == new_names, "v9.h3_lock_section_set")
    for name in old_names:
        if name in ("lockfileVersion", "packages", "snapshots", "importers"): continue
        if name == "packageExtensionsChecksum":
            pattern = r"^packageExtensionsChecksum: sha256-[A-Za-z0-9+/]{43}=\n(?:\n)*(?=^[A-Za-z][A-Za-z0-9]*:|\Z)"
            prior_scalar, actual_scalar = re.findall(pattern, old_doc, re.M), re.findall(pattern, new_doc, re.M)
            need(len(prior_scalar) == 1 and actual_scalar == prior_scalar,
                "v9.h3_package_extensions_checksum_unchanged")
            continue
        prior, actual = section(old_doc, name), section(new_doc, name)
        if name == "overrides":
            for selector, version in H3_FIXED_SELECTORS.items():
                previous = H3_TARGETS["joi" if ">joi" in selector else "glob" if ">glob" in selector else selector][0]
                old_pattern = r"(^  ['\"]?" + re.escape(selector) + r"['\"]?: )" + re.escape(previous) + r"$"
                prior = re.sub(old_pattern, lambda m: m.group(1) + version, prior, flags=re.M)
                if selector not in ("follow-redirects", "minimatch") and not re.search(r"^  ['\"]?" + re.escape(selector) + r"['\"]?:", prior, re.M):
                    prior += "\n  '" + selector + "': " + version
            # Ordering belongs to pnpm's fixed writer; compare exact unique key values.
            def override_map(value):
                result = {}
                for line in value.splitlines():
                    if not line: continue
                    m = re.fullmatch(r"  ('[^']+'|undici@>=8\.0\.0 <8\.12\.2|zod@>=4\.0\.0 <4\.6\.6|[^: ]+): (.+)", line)
                    need(m is not None, "v9.h3_override_writer_dialect")
                    key, val = m.groups(); key = key.strip("'"); need(key not in result, "v9.h3_override_unique"); result[key] = val
                return result
            need(override_map(prior) == override_map(actual), "v9.h3_exact_lock_overrides")
        else: need(prior == actual, "v9.h3_unrelated_lock_section")
    excluded = verify_h3_excluded_ages(new["packages"], h3, checked)
    return {"schema": "openclaw.v109.h3-lock-security.v1", "amendmentSha256": h3["amendmentSha256"],
        "materialSourceGeneration": h3["sourceGeneration"], "exactSelectedVersions": {k: v[1] for k,v in H3_TARGETS.items()},
        "parentSelectors": H3_FIXED_SELECTORS, "unrelatedSelectedGraphPreserved": True,
        "excludedAgeProofSha256": h3["excludedAgeProofSha256"], "excludedSelectedTupleCount": excluded,
        "nativeMinimumReleaseAgeStillRequiredForRemainingClosure": True}


H3_EXCLUDED_AGE_PROOF_SHA256 = "373061e725f14fbe9df627f06f69023836f47621630dad006c700da7582e7a05"


def verify_h3_excluded_ages(packages, h3, checked):
    raw = h3["excludedAgeProofBytes"]
    need(h3["excludedAgeProofSha256"] == H3_EXCLUDED_AGE_PROOF_SHA256 and
        digest(raw) == H3_EXCLUDED_AGE_PROOF_SHA256, "v9.h3_excluded_age_proof_binding")
    proof = strict_json(raw)
    need(type(proof) is dict and proof.get("schema") == "openclaw.v109.selected-excluded-package-ages.v1" and
        proof.get("sourceApplicationSha") == "0d0b3dbcbb571509df403e98d7e9be69a8f46f4f" and
        proof.get("minimumReleaseAgeMinutes") == 10080 and type(proof.get("minimumReleaseAgeMinutes")) is int and
        proof.get("tupleCount") == 18 and type(proof.get("tuples")) is list and len(proof["tuples"]) == 18 and
        proof.get("fullResolvedH3ClosureProven") is False and proof.get("metadataClaimsOnlyPackageBodiesAuthenticated") is False and
        proof.get("newAgeExceptionOrPackagePin") is False and proof.get("eligibleAtIsConservativeWholeSecondCeiling") is True,
        "v9.h3_excluded_age_proof_scope")
    rows = {}
    for row in proof["tuples"]:
        need(type(row) is dict and set(row) == {"name", "version", "integrity", "publishedAt", "eligibleAt",
            "sourceRoute", "sourceResponseSha256", "sourceSummarySha256"} and
            all(type(row[k]) is str for k in row) and re.fullmatch(r"sha512-[A-Za-z0-9+/]{86}==", row["integrity"]) and
            all(re.fullmatch(r"[0-9a-f]{64}", row[k]) for k in ("sourceResponseSha256", "sourceSummarySha256")) and
            row["sourceRoute"].startswith("https://registry.npmjs.org/"), "v9.h3_excluded_positive_metadata")
        key = row["name"] + "@" + row["version"]
        need(key not in rows, "v9.h3_excluded_unique_tuple")
        try:
            published = datetime.fromisoformat(row["publishedAt"].replace("Z", "+00:00"))
            eligible = authority.utc(row["eligibleAt"])
        except ValueError:
            raise LockRefusal("v9.h3_excluded_metadata_time")
        need(published.tzinfo is not None and 10080*60 <= (eligible-published).total_seconds() < 10080*60+1,
            "v9.h3_excluded_conservative_age")
        rows[key] = row
    selected = set()
    for key, chunk in packages.items():
        name_version = key.split("(", 1)[0]
        # Native unchanged exclusions cover all Codex tuples and exactly fs-safe0.26.0.
        excluded = name_version.startswith("@openai/codex@") or name_version.startswith("@openai/codex-") or (
            name_version.startswith("@openclaw/fs-safe") and name_version.rsplit("@", 1)[-1] == "0.26.0")
        if not excluded: continue
        need(name_version in rows, "v9.h3_unknown_selected_excluded_tuple")
        row = rows[name_version]
        found = re.findall(r"^    resolution: \{integrity: (sha512-[A-Za-z0-9+/=]+)\}$", chunk, re.M)
        need(found == [row["integrity"]] and checked >= authority.utc(row["eligibleAt"]), "v9.h3_selected_excluded_integrity_or_age")
        selected.add(name_version)
    need(selected == set(rows), "v9.h3_selected_excluded_closure_changed")
    return len(selected)


def verify_h3_before_package_use(lock_raw, h3):
    """Positive fixed excluded-tuple evidence complements unchanged native age policy."""
    checked = validate_h3_source_inputs(h3)
    selected = entries(documents(lock_raw)[1], "packages")
    count = verify_h3_excluded_ages(selected, h3, checked)
    return {"excludedSelectedTupleCount": count, "proofSha256": H3_EXCLUDED_AGE_PROOF_SHA256,
        "minimumReleaseAgeMinutes": 10080, "fullResolvedClosureProven": False,
        "nativeMinimumReleaseAgeStrictRequired": True}


H3_TARGET_METADATA_PROOF_SHA256 = "d2eef1b346c05bd69f133e47b28f2f8767f797e407a7210410e3c0f4df7930ed"


def verify_h3_target_metadata(h3, checked):
    raw = h3["targetMetadataProofBytes"]
    need(h3["targetMetadataProofSha256"] == H3_TARGET_METADATA_PROOF_SHA256 and digest(raw) == H3_TARGET_METADATA_PROOF_SHA256,
        "v9.h3_target_metadata_proof_binding")
    proof = strict_json(raw)
    need(type(proof) is dict and proof.get("schema") == "openclaw.v109.target-package-metadata.v1" and
        proof.get("tupleCount") == 4 and type(proof.get("tuples")) is list and len(proof["tuples"]) == 4 and
        proof.get("minimumReleaseAgeMinutes") == 10080 and type(proof.get("minimumReleaseAgeMinutes")) is int and
        proof.get("metadataOnly") is True and proof.get("fullResolvedH3ClosureProven") is False and
        proof.get("packageBodiesAuthenticated") is False and proof.get("newPinOrAgeExceptionBeyondApprovedFour") is False and
        proof.get("eligibleAtIsConservativeWholeSecondCeiling") is True, "v9.h3_target_metadata_scope")
    result = {}
    for row in proof["tuples"]:
        need(type(row) is dict and set(row) == {"name", "version", "integrity", "publishedAt", "eligibleAt", "dependencies", "engines",
            "sourceRoute", "sourceResponseSha256", "sourceProjectionSha256", "sourceSummarySha256"} and
            row["name"] in H3_TARGETS and row["name"] not in result and row["version"] == H3_TARGETS[row["name"]][1] and
            type(row["integrity"]) is str and re.fullmatch(r"sha512-[A-Za-z0-9+/]{86}==", row["integrity"]) and
            type(row["dependencies"]) is dict and type(row["engines"]) is dict and
            all(type(k) is str and type(v) is str for mapping in (row["dependencies"], row["engines"]) for k,v in mapping.items()) and
            all(type(row[k]) is str and re.fullmatch(r"[0-9a-f]{64}", row[k]) for k in ("sourceResponseSha256", "sourceProjectionSha256", "sourceSummarySha256")) and
            row["sourceRoute"] == "https://registry.npmjs.org/" + row["name"], "v9.h3_target_metadata_positive_tuple")
        try: published = datetime.fromisoformat(row["publishedAt"].replace("Z", "+00:00"));eligible = authority.utc(row["eligibleAt"])
        except (ValueError, AttributeError): raise LockRefusal("v9.h3_target_metadata_time")
        need(published.tzinfo is not None and 10080*60 <= (eligible-published).total_seconds() < 10080*60+1 and
            checked >= eligible, "v9.h3_target_metadata_age")
        result[row["name"]] = row
    need(set(result) == set(H3_TARGETS), "v9.h3_target_metadata_complete")
    return result

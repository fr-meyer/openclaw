"""Fixed pnpm12 lock admission for the reviewed 10.9 graph, not a YAML resolver.

The maintained package-patch checker still owns installed patch registration.
This early gate protects the carried Zod4 graph before a generated lock can be
committed: it must never silently admit new/unpatched Zod3 or edit the workspace.
All remaining generated changes are retained for independent exact-diff review.
"""
import hashlib
import re


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


def verify_lock_security(before, generated, expected_msal_integrity, expected_common_integrity):
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
    return {"schema": "openclaw.v109.generated-lock-security.v1", "beforeLockSha256": digest(before),
        "generatedLockSha256": digest(generated), "criticalVersionSets": catalogs,
        "zod4PatchHash": ZOD_HASH, "newUnpatchedZod3Absent": True,
        "selectedMsalNodeVersion": "7.1.1", "selectedMsalNodeIntegrity": expected_msal_integrity,
        "selectedMsalCommonVersion": "16.14.3", "selectedMsalCommonIntegrity": expected_common_integrity,
        "carriedMsalCommonConsumers": carried_common, "unexpectedMsalCommonConsumerAbsent": True,
        "unrelatedGeneratedDiffAutomaticallyApproved": False,
        "exactGeneratedDiffReviewRequiredBeforeCommit": True}

"""Synthetic closed H2 composition; no real diagnostic after bytes or H2."""
from copy import deepcopy
from contextlib import ExitStack
from pathlib import Path
import unittest
from unittest.mock import patch

import test_h_fixture_correction_contract_v109 as old

m = old.m


def pair(path):
    plugin = m.GENERATED_MANIFEST_ORIGINS[path]["plugin"]
    before = (Path(__file__).parent / "public-originals" / (plugin + ".json")).read_bytes()
    value = m.parse(before)
    value["controlUi"] = {"entry": "dist/control-ui/" + "a" * 64 + "/index.js"}
    if plugin == "workboard":
        value["controlUi"]["styles"] = ["dist/control-ui/" + "a" * 64 + "/index.css"]
    return before, (m.manifest_capture._encode(value))


def ledger():
    value = m.parse(old.ledger_vector())
    value["sourcePaths"].sort(key=lambda row: row["path"])
    return m.encode(value)


def graph(paths):
    data = old.model()
    b, files, read, trees, gate, entries, content, parents, overrides = data
    g, h, h2 = b["preparation"]["sourceSha"], m.FIXTURE_CORRECTION_PARENT, b["correction"]["source"]["sourceSha"]
    initial = m.parse(content[g][m.LEDGER]); initial["sourcePaths"].sort(key=lambda row: row["path"])
    content[g][m.LEDGER] = m.encode(initial)
    b["preparation"]["fileSha256"][m.LEDGER] = m.digest(content[g][m.LEDGER])
    receipt = m.parse(files["generation.json"]); receipt["ledgerSha256"] = m.digest(content[g][m.LEDGER])
    files["generation.json"] = m.encode(receipt)
    generation = b["validation"]["generation"]; generation["receiptSha256"] = m.digest(files["generation.json"])
    content[h][m.LEDGER] = m.expected_derived_ledger(content[g][m.LEDGER], old.blob(content[h]["pnpm-lock.yaml"]), generation)
    b["validation"]["source"]["fileSha256"][m.LEDGER] = m.digest(content[h][m.LEDGER])
    selected = {path: pair(path) for path in paths}
    for path in m.GENERATED_MANIFEST_ORIGINS:
        before, after = pair(path)
        for sha in (g, h, h2): content[sha][path] = after if sha == h2 and path in paths else before
    content[h2][m.LEDGER] = m.expected_fixture_correction_ledger(content[h][m.LEDGER], m.FIXTURE_CORRECTION_AFTER_BLOB, selected)
    for sha, source in content.items():
        entries[sha] = {path: ("100644", "blob", old.blob(raw)) for path, raw in source.items()}
    b["validation"]["unchangedTreeSha256"] = m.tree_digest(entries[g], ("pnpm-lock.yaml", m.LEDGER))
    c = b["correction"]; c["generation"] = deepcopy(generation)
    c["changedPaths"] = sorted((m.LEDGER, m.FIXTURE_CORRECTION_PATH, *paths))
    c["contentSha256"] = {path: m.digest(content[h2][path]) for path in c["changedPaths"]}
    c["source"]["fileSha256"][m.LEDGER] = m.digest(content[h2][m.LEDGER])
    c["unchangedTreeSha256"] = m.tree_digest(entries[h], c["changedPaths"])
    b["ciRunGrant"]["nextExecution"]["source"] = deepcopy(c["source"])
    overrides.update(FIXTURE_CORRECTION_SOURCE_PIN_SHA256=m.digest(m.canonical(b["validation"]["source"])),
        FIXTURE_CORRECTION_GENERATION_SHA256=m.digest(m.canonical(generation)))
    return data


def proof(data):
    b, files, read, trees, gate, entries, content, parents, overrides = data
    with ExitStack() as stack:
        for key, value in overrides.items(): stack.enter_context(patch.object(m, key, value))
        return m.verify_derived_source(read, b, "correction", files["generation.json"], read_tree=trees, verify_lock=gate)


class GeneratedManifestCorrectionTests(unittest.TestCase):
    def test_empty_selection_preserves_original_helper_bytes(self):
        self.assertEqual(m.expected_fixture_correction_ledger(old.ledger_vector(), m.FIXTURE_CORRECTION_AFTER_BLOB),
            m.expected_fixture_correction_ledger(old.ledger_vector(), m.FIXTURE_CORRECTION_AFTER_BLOB, {}))

    def test_each_changed_subset_has_exact_nonnull_origin_rows(self):
        keys = sorted(m.GENERATED_MANIFEST_ORIGINS)
        for subset in (keys[:1], keys[1:], keys):
            pairs = {path: pair(path) for path in subset}
            before = m.parse(ledger()); after = m.parse(m.expected_fixture_correction_ledger(ledger(), m.FIXTURE_CORRECTION_AFTER_BLOB, pairs))
            expected = m.parse(m.expected_fixture_correction_ledger(ledger(), m.FIXTURE_CORRECTION_AFTER_BLOB))
            generated = m.generated_manifest_results(pairs)
            for path in subset:
                origin = {"mode": "100644", "blob": m.GENERATED_MANIFEST_ORIGINS[path]["blob"]}
                expected["sourcePaths"].append({"path": path, "base108": origin, "fork108": origin,
                    "upstream109": origin, "result": {"mode": "100644", "blob": generated[path]["blob"]},
                    "disposition": "MERGED_SOURCE_REVIEWED"})
            expected["sourcePaths"].sort(key=lambda row: row["path"])
            self.assertEqual(after, expected)
            self.assertEqual(after["lockDerivation"], before["lockDerivation"])
            self.assertIs(type(after["lockDerivation"]["runId"]), int)

    def test_new_inventory_origins_are_h_not_invented_old_fork(self):
        pairs = {path: pair(path) for path in m.GENERATED_MANIFEST_ORIGINS}
        rows = m.generated_manifest_inventory_rows(pairs)
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(row["sourceCommit"], m.FIXTURE_CORRECTION_PARENT)
            self.assertEqual(row["sourceTree"], m.GENERATED_MANIFEST_PARENT_TREE)
            self.assertEqual(row["sourceBlob"], row["upstreamBlob"])
            self.assertEqual(row["candidateBlob"], old.blob(pairs[row["path"]][1]))

    def test_unknown_unchanged_malformed_or_nonpublic_bytes_refuse(self):
        path = next(iter(m.GENERATED_MANIFEST_ORIGINS)); before, after = pair(path)
        for pairs in ({"extensions/other/openclaw.plugin.json": (before, after)}, {path: (before, before)},
            {path: (b"{}", after)}, {path: (before, after + b" ")}, {path: [before]},
            {path: (before, b"x" * 65537)}, {path: (before, after.decode())}):
            with self.subTest(pairs=list(pairs)), self.assertRaises(m.Refusal): m.generated_manifest_results(pairs)

    def test_non_control_ui_mutations_duplicate_keys_and_bad_pointer_refuse(self):
        path = next(iter(m.GENERATED_MANIFEST_ORIGINS)); before, after = pair(path)
        for kind in ("outside", "entry", "styles", "duplicate"):
            value = m.parse(after)
            if kind == "outside": value["newField"] = True
            elif kind == "entry": value["controlUi"]["entry"] = "https://example.invalid/a.js"
            elif kind == "styles": value["controlUi"]["styles"] = ["outside.css"]
            raw = b'{"id":1,"id":2}' if kind == "duplicate" else m.manifest_capture._encode(value)
            with self.subTest(kind=kind), self.assertRaises(m.Refusal): m.generated_manifest_results({path: (before, raw)})

    def test_existing_manifest_rows_or_unsorted_origin_ledger_refuse(self):
        path = next(iter(m.GENERATED_MANIFEST_ORIGINS)); pairs = {path: pair(path)}
        for kind in ("existing", "unsorted"):
            value = m.parse(ledger())
            if kind == "existing": value["sourcePaths"].append({"path": path})
            else: value["sourcePaths"].reverse()
            with self.subTest(kind=kind), self.assertRaises(m.Refusal):
                m.expected_fixture_correction_ledger(m.encode(value), m.FIXTURE_CORRECTION_AFTER_BLOB, pairs)

    def test_full_synthetic_each_subset_preserves_generation_and_remaining_tree(self):
        keys = sorted(m.GENERATED_MANIFEST_ORIGINS)
        for subset in ([], keys[:1], keys[1:], keys):
            data = graph(subset); result = proof(data)
            self.assertTrue(result["sourceCorrectionVerified"])
            self.assertTrue(result["freshSourceCoverageRequired"])
            self.assertEqual(result["generatedSourceSha"], m.FIXTURE_CORRECTION_PARENT)
            self.assertEqual(result["changedPaths"], data[0]["correction"]["changedPaths"])
            if subset:
                self.assertTrue(result["combinedFixtureManifestCorrectionVerified"])
                self.assertFalse(result["fixtureOnlyCorrectionVerified"])
                self.assertFalse(result["generatedManifestArtifactOriginAuthenticated"])
                self.assertFalse(result["assetContentAuthenticated"])

    def test_extra_path_wrong_parent_generation_dependency_or_mode_refuse(self):
        path = next(iter(m.GENERATED_MANIFEST_ORIGINS))
        for kind in ("extra", "parent", "generation", "package.json", "pnpm-workspace.yaml", "pnpm-lock.yaml", "mode"):
            data = graph([path]); b, files, read, trees, gate, entries, content, parents, overrides = data
            h2 = b["correction"]["source"]["sourceSha"]
            if kind == "extra": entries[h2]["runtime.ts"] = ("100644", "blob", "a" * 40)
            elif kind == "parent": parents[h2] = [b["preparation"]["sourceSha"]]
            elif kind == "generation": b["correction"]["generation"]["runId"] = "41043479026"
            elif kind == "mode": entries[h2][path] = ("100755", "blob", entries[h2][path][2])
            else: b["correction"]["source"]["fileSha256"][kind] = "a" * 64
            with self.subTest(kind=kind), self.assertRaises(m.Refusal): proof(data)

    def test_unrelated_ledger_or_invented_origin_refuses_even_after_hash_rebind(self):
        path = next(iter(m.GENERATED_MANIFEST_ORIGINS))
        for kind in ("origin", "count", "lockDerivation", "oldRow", "disposition"):
            data = graph([path]); b, files, read, trees, gate, entries, content, parents, overrides = data
            h2 = b["correction"]["source"]["sourceSha"]; value = m.parse(content[h2][m.LEDGER])
            row = next(row for row in value["sourcePaths"] if row["path"] == path)
            if kind == "origin": row["base108"] = None
            elif kind == "count": value["forkDeltaPathCount"] = 251
            elif kind == "lockDerivation": value["lockDerivation"]["runId"] += 1
            elif kind == "oldRow": value["sourcePaths"][-1]["result"] = None
            else: row["disposition"] = "CARRIED_EXACT"
            raw = m.encode(value); content[h2][m.LEDGER] = raw; entries[h2][m.LEDGER] = ("100644", "blob", old.blob(raw))
            b["correction"]["contentSha256"][m.LEDGER] = m.digest(raw)
            b["correction"]["source"]["fileSha256"][m.LEDGER] = m.digest(raw)
            b["ciRunGrant"]["nextExecution"]["source"] = deepcopy(b["correction"]["source"])
            with self.subTest(kind=kind), self.assertRaises(m.Refusal): proof(data)


if __name__ == "__main__": unittest.main()

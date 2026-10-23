// Guard the actual production graph and package-patch bindings; no live registry or database reads.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import YAML from "yaml";
import {
  parseSnapshotKey,
  pnpmLockfileDocuments,
} from "../../scripts/lib/pnpm-lockfile-documents.mjs";
import {
  collectProdResolvedPackagesFromLockfile,
  createBulkAdvisoryPayload,
  filterFindingsBySeverity,
} from "../../scripts/pre-commit/pnpm-audit-prod.mjs";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const A2UI_VERSION = "0.11.0";
const ZOD_VERSION = "4.6.6";
const PATCHED_OWNERS = {
  "zod@4.6.6": "patches/zod@4.6.6.patch",
  [`@a2ui/lit@${A2UI_VERSION}`]: `patches/@a2ui__lit@${A2UI_VERSION}.patch`,
  [`@a2ui/web_core@${A2UI_VERSION}`]: `patches/@a2ui__web_core@${A2UI_VERSION}.patch`,
  "@discord/embedded-app-sdk@2.5.0": "patches/@discord__embedded-app-sdk@2.5.0.patch",
};
const read = (file: string) => readFileSync(path.join(ROOT, file), "utf8");

function assertNoLegacyZod(lockSource: string) {
  const payload = createBulkAdvisoryPayload(collectProdResolvedPackagesFromLockfile(lockSource));
  assert.deepEqual(
    payload.zod,
    [ZOD_VERSION],
    "production graph must contain only the reviewed fixed Zod package",
  );
  return payload;
}

function syntheticLock(edge: string, section = "dependencies") {
  return `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      zod: {version: 4.6.6(patch_hash=fixed)}
  extensions/fixture:
    ${section}:
      carrier: {version: 1.0.0}
snapshots:
  zod@4.6.6(patch_hash=fixed): {}
  carrier@1.0.0:
    optionalDependencies:
      ${edge}
  zod@3.25.76(patch_hash=not-a-version-fix): {}
`;
}

describe("reviewed legacy Zod closure", () => {
  it("uses the unchanged production graph resolver on the real lock", () => {
    assertNoLegacyZod(read("pnpm-lock.yaml"));
  });

  it.each(["dependencies", "optionalDependencies"])(
    "rejects legacy Zod through a workspace %s and nested optional edge",
    (section) => {
      expect(() =>
        assertNoLegacyZod(syntheticLock("zod: 3.25.76(patch_hash=not-a-version-fix)", section)),
      ).toThrow();
    },
  );

  it("rejects an aliased legacy parser despite patch hash decorations", () => {
    expect(() =>
      assertNoLegacyZod(
        syntheticLock("legacy-parser: npm:zod@3.25.76(patch_hash=not-a-version-fix)"),
      ),
    ).toThrow();
  });

  it("does not erase Zod advisory findings", () => {
    const findings = filterFindingsBySeverity(
      {
        zod: [
          {
            id: "GHSA-mrhx-c7xc-m3w5",
            severity: "high",
            title: "fixture",
            vulnerable_versions: "<4.6.6",
          },
        ],
      },
      "high",
      new Map([["zod", new Set(["3.25.76"])]]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].packageName).toBe("zod");
  });

  it("binds supported consumer pins, precise overrides, and actual patch bytes", () => {
    const workspace = YAML.parse(read("pnpm-workspace.yaml"));
    const lock = YAML.parse(pnpmLockfileDocuments(read("pnpm-lock.yaml")).dependencies);
    for (const file of ["package.json", "extensions/canvas/package.json"]) {
      const manifest = JSON.parse(read(file));
      const dependencies = { ...manifest.dependencies, ...manifest.devDependencies };
      expect(dependencies["@a2ui/lit"]).toBe(A2UI_VERSION);
      expect(dependencies["@a2ui/web_core"]).toBe(A2UI_VERSION);
    }
    expect(
      JSON.parse(read("extensions/discord/package.json")).dependencies["@discord/embedded-app-sdk"],
    ).toBe("2.5.0");
    expect(workspace.overrides[`@a2ui/lit@${A2UI_VERSION}>zod`]).toBe(ZOD_VERSION);
    expect(workspace.overrides[`@a2ui/web_core@${A2UI_VERSION}>zod`]).toBe(ZOD_VERSION);
    expect(workspace.overrides[`@a2ui/web_core@${A2UI_VERSION}>zod-to-json-schema`]).toBe("-");
    expect(workspace.overrides["@discord/embedded-app-sdk@2.5.0>zod"]).toBe(ZOD_VERSION);
    expect(workspace.overrides["zod-to-json-schema@3.25.2>zod"]).toBe("^3.25.28 || ^4");
    expect(workspace.overrides["zod-to-json-schema"]).toBeUndefined();
    for (const [specifier, filename] of Object.entries(PATCHED_OWNERS)) {
      expect(workspace.patchedDependencies[specifier]).toBe(filename);
      expect(lstatSync(path.join(ROOT, filename)).isFile()).toBe(true);
      const hash = createHash("sha256")
        .update(readFileSync(path.join(ROOT, filename)))
        .digest("hex");
      expect(lock.patchedDependencies[specifier]).toBe(hash);
      const [name, version] = (() => {
        const parsed = parseSnapshotKey(specifier);
        return [parsed.packageName, parsed.version];
      })();
      const snapshots = Object.keys(lock.snapshots).filter((key) => {
        const parsed = parseSnapshotKey(key);
        return parsed.packageName === name && parsed.version === version;
      });
      expect(snapshots.length).toBeGreaterThan(0);
      for (const snapshot of snapshots) {
        expect(snapshot).toContain(`patch_hash=${hash}`);
      }
    }
    for (const [key, snapshot] of Object.entries(lock.snapshots)) {
      if (parseSnapshotKey(key).packageName === "@a2ui/web_core") {
        expect(
          (snapshot as { dependencies?: Record<string, string> }).dependencies?.[
            "zod-to-json-schema"
          ],
        ).toBeUndefined();
      }
      if (parseSnapshotKey(key).packageName === "zod-to-json-schema") {
        expect((snapshot as { dependencies: Record<string, string> }).dependencies.zod).toContain(
          ZOD_VERSION,
        );
      }
    }
    expect(lock.packages["zod-to-json-schema@3.25.2"].peerDependencies.zod).toBe("^3.25.28 || ^4");
  });
});

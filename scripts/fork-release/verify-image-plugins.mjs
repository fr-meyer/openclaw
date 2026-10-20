#!/usr/bin/env node
import { lstatSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

function need(value, message) {
  if (!value) throw new Error(message);
}

function regularFile(path) {
  const stat = lstatSync(path);
  need(stat.isFile() && !stat.isSymbolicLink(), `Plugin payload is not a regular file: ${path}`);
  return readFileSync(path);
}

function json(path) {
  return JSON.parse(regularFile(path).toString("utf8"));
}

function versionParts(version) {
  need(/^\d{4}\.\d{1,2}\.\d{1,2}$/u.test(version), `Invalid plugin version: ${version}`);
  return version.split(".").map(Number);
}

function atLeast(version, minimum) {
  const left = versionParts(version);
  const right = versionParts(minimum);
  for (let i = 0; i < left.length; i += 1) {
    if (left[i] !== right[i]) return left[i] > right[i];
  }
  return true;
}

export function inspectImagePlugins(root, extensions, version) {
  const ids = extensions.split(",");
  need(ids.length > 0 && ids.every((id) => /^[a-z0-9][a-z0-9-]*$/u.test(id)),
    "Invalid selected plugin IDs");
  need(new Set(ids).size === ids.length, "Duplicate selected plugin ID");
  need(json(join(root, "package.json")).version === version, "Image host version changed");
  const inspected = [];
  for (const id of ids) {
    const packageJson = json(join(root, "extensions", id, "package.json"));
    const descriptor = json(join(root, "extensions", id, "openclaw.plugin.json"));
    need(descriptor.id === id, `Plugin identity changed: ${id}`);
    need(Array.isArray(packageJson.openclaw?.extensions) &&
      packageJson.openclaw.extensions.includes("./index.ts"), `Plugin entry missing: ${id}`);
    regularFile(join(root, "dist", "extensions", id, "index.js"));
    if (id === "codex") {
      need(packageJson.name === "@openclaw/codex" && packageJson.version === version,
        "Codex plugin package does not match the image host");
      need(atLeast(packageJson.version, "2026.9.7"), "Codex plugin predates admission minimum");
      need(packageJson.openclaw.compat?.pluginApi === `>=${version}` &&
        packageJson.openclaw.build?.openclawVersion === version,
      "Codex plugin API/build compatibility differs from the image host");
      need(descriptor.providers?.includes("codex") &&
        descriptor.doctorContract?.configRepair === true &&
        descriptor.doctorContract?.stateMigrations?.length > 0,
      "Codex Doctor contract missing from image");
    }
    inspected.push({ id, package: packageJson.name, version: packageJson.version });
  }
  return inspected;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [root, extensions, version] = process.argv.slice(2);
    need(root && extensions && version, "Usage: verify-image-plugins.mjs ROOT EXTENSIONS VERSION");
    process.stdout.write(`${JSON.stringify(inspectImagePlugins(root, extensions, version))}\n`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}

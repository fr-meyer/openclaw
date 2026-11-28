import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

export function writeJson(file: string, value: unknown) {
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify(value));
}

export function createDockerReleaseLayout(
  source: { sourceSha: string; repository: string; mediaType: string; indexMediaType: string },
  directory: string,
  architecture: string,
  options: { labelSha?: string; provenance?: boolean; version?: string; builtAt?: string } = {},
) {
  const { sourceSha, repository, mediaType, indexMediaType } = source;
  function blob(value: unknown) {
    const bytes = Buffer.from(JSON.stringify(value));
    const digest = createHash("sha256").update(bytes).digest("hex");
    const file = path.join(directory, "blobs", "sha256", digest);
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, bytes);
    return { digest: `sha256:${digest}`, size: bytes.length };
  }
  const config = blob({
    architecture,
    os: "linux",
    rootfs: { type: "layers", diff_ids: [] },
    config: {
      Labels: {
        "org.opencontainers.image.revision": options.labelSha ?? sourceSha,
        "org.opencontainers.image.version": options.version ?? "2026.8.1-beta.2",
        "org.opencontainers.image.created": options.builtAt ?? "2026-09-01T00:00:00.000Z",
      },
    },
  });
  const image = blob({
    schemaVersion: 2,
    mediaType,
    config: { mediaType: "application/vnd.oci.image.config.v1+json", ...config },
    layers: [],
  });
  const predicates = [
    "https://spdx.dev/Document",
    ...(options.provenance === false ? [] : ["https://slsa.dev/provenance/v1"]),
  ];
  const provenanceSource = {
    uri: `https://github.com/${repository}.git#${sourceSha}`,
    digest: { sha1: sourceSha },
  };
  const attestation = blob({
    schemaVersion: 2,
    mediaType,
    config: { mediaType: "application/vnd.oci.image.config.v1+json", ...blob({}) },
    layers: predicates.map((predicateType) =>
      Object.assign(
        blob({
          predicateType,
          subject: [{ digest: { sha256: image.digest.slice(7) } }],
          ...(predicateType === "https://slsa.dev/provenance/v1"
            ? {
                predicate: {
                  buildDefinition: {
                    externalParameters: { configSource: provenanceSource },
                    resolvedDependencies: [provenanceSource],
                  },
                },
              }
            : {}),
        }),
        {
          mediaType: "application/vnd.in-toto+json",
          annotations: { "in-toto.io/predicate-type": predicateType },
        },
      ),
    ),
  });
  const manifests = [
    { mediaType, ...image, platform: { os: "linux", architecture } },
    {
      mediaType,
      ...attestation,
      platform: { os: "unknown", architecture: "unknown" },
      annotations: {
        "vnd.docker.reference.type": "attestation-manifest",
        "vnd.docker.reference.digest": image.digest,
      },
    },
  ];
  const index = blob({ schemaVersion: 2, mediaType: indexMediaType, manifests });
  writeJson(path.join(directory, "oci-layout"), { imageLayoutVersion: "1.0.0" });
  writeJson(path.join(directory, "index.json"), {
    schemaVersion: 2,
    manifests: [{ mediaType: indexMediaType, ...index }],
  });
  return {
    indexDigest: index.digest,
    imageDigest: image.digest,
    configDigest: config.digest,
    manifests,
  };
}

// These exact releases declare Zod as a peer. Their published ranges were
// checked before restoring them from the fork's broad Zod security override.
// pnpm lock package metadata does not expose direct dependencies, so this
// list must not be generalized from a lock peerDependencies field alone.
const AUDITED_PEER_RANGES = new Map([
  ["@agentclientprotocol/sdk@2.0.1>zod", "^3.25.76 || ^4.0.0"],
  ["@anthropic-ai/claude-agent-sdk@0.3.309>zod", "^4.0.0"],
  ["zod-to-json-schema@3.25.2>zod", "^3.25.28 || ^4"],
]);

export function isAuditedPeerOverride(
  parentSelector: string,
  dependencyName: string,
  spec: unknown,
): boolean {
  return (
    typeof spec === "string" &&
    AUDITED_PEER_RANGES.get(`${parentSelector}>${dependencyName}`) === spec
  );
}

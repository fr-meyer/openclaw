import { resolveGatewayOperatorRoleActor } from "./operator-role-policy.js";
import type { GatewayClient } from "./server-methods/types.js";

/** Defer broad projection loading without borrowing a changed actor, grant or run. */
export async function loadGatewaySessionAccessPreparation(params: {
  client: GatewayClient;
  assertCurrent: () => void;
  readInheritedPolicy: () => unknown;
}) {
  const { client, assertCurrent, readInheritedPolicy } = params;
  assertCurrent();
  const originalActor = resolveGatewayOperatorRoleActor(client);
  const actorKind = originalActor?.kind;
  const profileId =
    originalActor?.kind === "operator"
      ? originalActor.profileId
      : client.authenticatedUserProfile?.profileId;
  const originalGrant = client.internal?.operatorAccessAuthority;
  const originalRun = client.internal?.operatorRunAuthority;
  const originalScopes = JSON.stringify(client.connect.scopes ?? []);
  const originalInheritedPolicy = JSON.stringify(readInheritedPolicy());
  originalGrant?.assertCurrent();
  originalRun?.assertCurrent();
  const assertSourceCurrent = () => {
    assertCurrent();
    originalGrant?.assertCurrent();
    originalRun?.assertCurrent();
    const currentActor = resolveGatewayOperatorRoleActor(client);
    const currentProfileId =
      currentActor?.kind === "operator"
        ? currentActor.profileId
        : client.authenticatedUserProfile?.profileId;
    if (
      currentActor?.kind !== actorKind ||
      currentProfileId !== profileId ||
      client.internal?.operatorAccessAuthority !== originalGrant ||
      client.internal?.operatorRunAuthority !== originalRun ||
      JSON.stringify(client.connect.scopes ?? []) !== originalScopes ||
      JSON.stringify(readInheritedPolicy()) !== originalInheritedPolicy
    ) {
      throw new Error("Managed task-flow session preparation authority changed while loading");
    }
  };
  const { prepareGatewaySessionAccessAuthority } = await import("./session-access-authority.js");
  assertSourceCurrent();
  return { prepareGatewaySessionAccessAuthority, assertSourceCurrent };
}

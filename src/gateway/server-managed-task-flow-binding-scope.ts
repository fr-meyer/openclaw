import { pluginInstanceInvocation } from "../plugins/plugin-instance-invocation.js";
import {
  getPluginInstanceOwner,
  hasCurrentPluginInstanceAuthority,
} from "../plugins/plugin-instance-scope.js";
import {
  getInProcessGatewayRequestContext,
  getPluginRuntimeGatewayRequestScope,
} from "../plugins/runtime/gateway-request-scope.js";
import { parseAgentSessionKey, isIncognitoSessionKey } from "../routing/session-key.js";
import {
  configuredManagedFlowOwners,
  configuredStatusAgentIds,
} from "./server-managed-task-flow-policy.js";
import type { GatewayContextResolver } from "./server-methods/types.js";

export function resolveGatewayManagedTaskFlowBindingScope(
  input: { sessionKey: string; agentId?: string },
  kind: "flow" | "run",
  resolveGatewayContext: GatewayContextResolver | undefined,
) {
  const currentScope = getPluginRuntimeGatewayRequestScope();
  const scope = currentScope && { ...currentScope };
  const context = getInProcessGatewayRequestContext(resolveGatewayContext);
  const gatewayResolver =
    resolveGatewayContext ?? scope?.resolveGatewayContext ?? context?.resolveGatewayContext;
  const client = scope?.client;
  const pluginId = scope?.pluginId?.trim();
  const invocation = pluginInstanceInvocation.getStore();
  const owner = invocation && getPluginInstanceOwner(invocation.instance);
  const instance = owner?.instance;
  if (
    !scope ||
    !owner ||
    !context ||
    !gatewayResolver ||
    gatewayResolver() !== context ||
    !pluginId ||
    !instance ||
    instance !== invocation?.instance ||
    instance.pluginId !== pluginId ||
    !hasCurrentPluginInstanceAuthority(pluginId)
  ) {
    throw new Error(
      "Controller state requires a current plugin instance and original Gateway binding",
    );
  }
  const sessionKey = input.sessionKey.trim();
  const parsed = parseAgentSessionKey(sessionKey);
  if (
    !parsed ||
    isIncognitoSessionKey(sessionKey) ||
    sessionKey !== input.sessionKey ||
    (input.agentId !== undefined && input.agentId !== parsed.agentId)
  ) {
    throw new Error("Managed task-flow binding requires a canonical session key");
  }
  const agentId = input.agentId;
  const controllerId = `${pluginId}/v1`;
  const ownerConfig = context.getRuntimeConfig();
  const configuredOwners =
    kind === "flow" ? configuredManagedFlowOwners(ownerConfig, pluginId, sessionKey) : [];
  const statusAgentIds = configuredStatusAgentIds(ownerConfig, pluginId);
  return {
    scope,
    context,
    gatewayResolver,
    client,
    pluginId,
    owner,
    instance,
    sessionKey,
    agentId,
    controllerId,
    ownerConfig,
    configuredOwners,
    statusAgentIds,
  };
}

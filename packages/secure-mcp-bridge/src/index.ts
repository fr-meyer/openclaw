import { randomUUID } from "node:crypto";
import { chmod, mkdir, open, rename, rm } from "node:fs/promises";
import path from "node:path";

const REQUIRED_AUTHORIZATION_PARAMETERS = [
  "client_id",
  "redirect_uri",
  "response_type",
  "state",
  "code_challenge",
  "scope",
] as const;

export type SecureMcpBridgeConfig = {
  mcpRemotePath: string;
  endpointUrl: string;
  callbackUrl: string;
  authorizationHosts: readonly string[];
  allowedScopes: readonly string[];
  clientInfoPath: string;
  clientMetadataPath: string;
  authStateDirectory: string;
  browserCapturePath: string;
  authorizationCapturePath: string;
  authTimeoutSeconds?: number;
};

export type SecureMcpBridgeLaunchPlan = {
  command: string;
  args: string[];
  env: Record<string, string>;
};

export type ProtectedCredentialBinding = {
  environmentName: string;
  value: string;
};

const ENVIRONMENT_NAME_RE = /^[A-Z_][A-Z0-9_]*$/;

function normalizeHostname(hostname: string): string {
  const normalized = hostname.trim().toLowerCase();
  if (normalized.startsWith("[") && normalized.endsWith("]")) {
    return normalized.slice(1, -1);
  }
  return normalized.endsWith(".") ? normalized.slice(0, -1) : normalized;
}

function assertAbsolutePath(label: string, value: string): void {
  if (!value || !path.isAbsolute(value) || value.includes("\0")) {
    throw new Error(`${label} must be a non-empty absolute path`);
  }
}

function parseUrl(label: string, value: string): URL {
  try {
    return new URL(value);
  } catch {
    throw new Error(`${label} must be a valid absolute URL`);
  }
}

function assertNoUrlCredentials(label: string, url: URL): void {
  if (url.username || url.password) {
    throw new Error(`${label} must not contain URL credentials`);
  }
}

function isLoopbackHostname(hostname: string): boolean {
  const normalized = normalizeHostname(hostname);
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1";
}

function parseCallbackUrl(raw: string): URL {
  const callback = parseUrl("callbackUrl", raw);
  assertNoUrlCredentials("callbackUrl", callback);
  if (callback.protocol !== "http:") {
    throw new Error("callbackUrl must use http on loopback");
  }
  if (!isLoopbackHostname(callback.hostname)) {
    throw new Error("callbackUrl must use a loopback hostname");
  }
  if (!callback.port) {
    throw new Error("callbackUrl must include an explicit port");
  }
  if (callback.pathname !== "/oauth/callback" || callback.search || callback.hash) {
    throw new Error("callbackUrl must be the exact /oauth/callback endpoint");
  }
  return callback;
}

function validateAuthorizationHost(host: string): string {
  const normalized = normalizeHostname(host);
  if (!normalized || normalized.includes(":") || /[\s/@%]/u.test(normalized)) {
    throw new Error("authorizationHosts must contain hostnames only");
  }
  const parsed = parseUrl("authorization host", `https://${normalized}`);
  if (normalizeHostname(parsed.hostname) !== normalized || parsed.port || parsed.pathname !== "/") {
    throw new Error("authorizationHosts must contain hostnames only");
  }
  return normalized;
}

export function validateSecureMcpBridgeConfig(config: SecureMcpBridgeConfig): void {
  assertAbsolutePath("mcpRemotePath", config.mcpRemotePath);
  assertAbsolutePath("clientInfoPath", config.clientInfoPath);
  assertAbsolutePath("clientMetadataPath", config.clientMetadataPath);
  assertAbsolutePath("authStateDirectory", config.authStateDirectory);
  assertAbsolutePath("browserCapturePath", config.browserCapturePath);
  assertAbsolutePath("authorizationCapturePath", config.authorizationCapturePath);

  const endpoint = parseUrl("endpointUrl", config.endpointUrl);
  assertNoUrlCredentials("endpointUrl", endpoint);
  if (endpoint.protocol !== "https:" || endpoint.hash) {
    throw new Error("endpointUrl must be an HTTPS URL without a fragment");
  }

  parseCallbackUrl(config.callbackUrl);

  if (config.authorizationHosts.length === 0) {
    throw new Error("authorizationHosts must contain at least one hostname");
  }
  for (const host of config.authorizationHosts) {
    validateAuthorizationHost(host);
  }
  if (config.allowedScopes.length === 0) {
    throw new Error("allowedScopes must contain at least one scope");
  }
  const uniqueScopes = new Set<string>();
  for (const scope of config.allowedScopes) {
    if (!scope || scope.length > 200 || /[\s\u0000-\u001f\u007f]/u.test(scope)) {
      throw new Error("allowedScopes must contain bounded non-whitespace scope values");
    }
    if (uniqueScopes.has(scope)) {
      throw new Error(`allowedScopes contains a duplicate scope: ${scope}`);
    }
    uniqueScopes.add(scope);
  }

  const timeout = config.authTimeoutSeconds ?? 300;
  if (!Number.isInteger(timeout) || timeout < 1 || timeout > 3600) {
    throw new Error("authTimeoutSeconds must be an integer between 1 and 3600");
  }
}

export function loadProtectedCredentialsFromEnvironment(
  environment: Readonly<Record<string, string | undefined>>,
  environmentNames: readonly string[],
): ProtectedCredentialBinding[] {
  if (environmentNames.length === 0) {
    throw new Error("at least one protected credential environment name is required");
  }
  const seen = new Set<string>();
  return environmentNames.map((environmentName) => {
    if (!ENVIRONMENT_NAME_RE.test(environmentName)) {
      throw new Error(`invalid protected credential environment name: ${environmentName}`);
    }
    if (seen.has(environmentName)) {
      throw new Error(`duplicate protected credential environment name: ${environmentName}`);
    }
    seen.add(environmentName);
    const value = environment[environmentName];
    if (!value || value.includes("\0")) {
      throw new Error(`protected credential ${environmentName} is unavailable`);
    }
    return { environmentName, value };
  });
}

export function buildSecureMcpBridgeLaunchPlan(
  config: SecureMcpBridgeConfig,
): SecureMcpBridgeLaunchPlan {
  validateSecureMcpBridgeConfig(config);
  const callback = parseCallbackUrl(config.callbackUrl);
  const timeout = config.authTimeoutSeconds ?? 300;

  return {
    command: config.mcpRemotePath,
    args: [
      config.endpointUrl,
      callback.port,
      "--host",
      normalizeHostname(callback.hostname),
      "--transport",
      "http-only",
      "--auth-timeout",
      String(timeout),
      "--static-oauth-client-info",
      `@${config.clientInfoPath}`,
      "--static-oauth-client-metadata",
      `@${config.clientMetadataPath}`,
    ],
    env: {
      MCP_REMOTE_CONFIG_DIR: config.authStateDirectory,
      BROWSER: config.browserCapturePath,
      OPENCLAW_AUTHORIZATION_CAPTURE_PATH: config.authorizationCapturePath,
    },
  };
}

export function validateAuthorizationUrl(raw: string, config: SecureMcpBridgeConfig): URL {
  validateSecureMcpBridgeConfig(config);
  const authorization = parseUrl("authorization URL", raw);
  assertNoUrlCredentials("authorization URL", authorization);
  if (authorization.protocol !== "https:" || authorization.hash) {
    throw new Error("authorization URL must use HTTPS without a fragment");
  }
  if (authorization.port && authorization.port !== "443") {
    throw new Error("authorization URL must use the default HTTPS port");
  }

  const allowedHosts = new Set(config.authorizationHosts.map(validateAuthorizationHost));
  if (!allowedHosts.has(normalizeHostname(authorization.hostname))) {
    throw new Error("authorization URL host is not allowlisted");
  }
  for (const parameter of REQUIRED_AUTHORIZATION_PARAMETERS) {
    const values = authorization.searchParams.getAll(parameter);
    if (values.length !== 1 || !values[0]?.trim()) {
      throw new Error(`authorization URL requires exactly one ${parameter}`);
    }
  }
  if (authorization.searchParams.get("redirect_uri") !== config.callbackUrl) {
    throw new Error("authorization URL redirect_uri does not match callbackUrl");
  }
  if (authorization.searchParams.get("response_type") !== "code") {
    throw new Error("authorization URL response_type must be code");
  }
  const requestedScopes = authorization.searchParams.get("scope")!.trim().split(/\s+/u);
  const allowedScopes = new Set(config.allowedScopes);
  if (
    new Set(requestedScopes).size !== requestedScopes.length ||
    requestedScopes.some((scope) => !allowedScopes.has(scope))
  ) {
    throw new Error("authorization URL requests a scope that is not allowlisted");
  }
  return authorization;
}

export function validateCallbackUrl(
  raw: string,
  config: SecureMcpBridgeConfig,
  expectedState?: string,
): URL {
  validateSecureMcpBridgeConfig(config);
  const callback = parseUrl("OAuth callback URL", raw);
  assertNoUrlCredentials("OAuth callback URL", callback);
  const expected = parseCallbackUrl(config.callbackUrl);
  if (
    callback.protocol !== expected.protocol ||
    normalizeHostname(callback.hostname) !== normalizeHostname(expected.hostname) ||
    callback.port !== expected.port ||
    callback.pathname !== expected.pathname ||
    callback.hash
  ) {
    throw new Error("OAuth callback URL does not match the configured callback endpoint");
  }
  for (const parameter of ["code", "state"] as const) {
    const values = callback.searchParams.getAll(parameter);
    if (values.length !== 1 || !values[0]?.trim()) {
      throw new Error(`OAuth callback URL requires exactly one ${parameter}`);
    }
  }
  if (expectedState !== undefined && callback.searchParams.get("state") !== expectedState) {
    throw new Error("OAuth callback state does not match the authorization request");
  }
  return callback;
}

export function redactOAuthUrl(raw: string): string {
  const url = parseUrl("OAuth URL", raw);
  for (const key of [...url.searchParams.keys()]) {
    url.searchParams.set(key, "[redacted]");
  }
  return url.toString();
}

export async function writePrivateFileAtomically(
  filePath: string,
  contents: string,
): Promise<void> {
  assertAbsolutePath("filePath", filePath);
  const directory = path.dirname(filePath);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await chmod(directory, 0o700);
  const temporaryPath = path.join(directory, `.${path.basename(filePath)}.${randomUUID()}.tmp`);
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(temporaryPath, "wx", 0o600);
    await handle.writeFile(contents, { encoding: "utf8" });
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporaryPath, filePath);
    await chmod(filePath, 0o600);
  } catch (error) {
    await handle?.close().catch(() => undefined);
    await rm(temporaryPath, { force: true }).catch(() => undefined);
    throw error;
  }
}

export async function capturePrivateAuthorizationUrl(
  raw: string,
  config: SecureMcpBridgeConfig,
): Promise<string> {
  const authorization = validateAuthorizationUrl(raw, config);
  await writePrivateFileAtomically(
    config.authorizationCapturePath,
    `${authorization.toString()}\n`,
  );
  return redactOAuthUrl(authorization.toString());
}

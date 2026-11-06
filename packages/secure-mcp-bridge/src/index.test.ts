import { mkdtemp, readFile, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  buildSecureMcpBridgeLaunchPlan,
  capturePrivateAuthorizationUrl,
  loadProtectedCredentialsFromEnvironment,
  redactOAuthUrl,
  validateAuthorizationUrl,
  validateCallbackUrl,
  validateSecureMcpBridgeConfig,
  writePrivateFileAtomically,
  type SecureMcpBridgeConfig,
} from "./index.js";

function fixture(): SecureMcpBridgeConfig {
  return {
    mcpRemotePath: "/opt/example/bin/mcp-remote",
    endpointUrl: "https://mcp.example.test/mcp",
    callbackUrl: "http://localhost:7331/oauth/callback",
    authorizationHosts: ["auth.example.test"],
    allowedScopes: ["mcp:read", "mcp:write"],
    clientInfoPath: "/var/lib/example/client-info.json",
    clientMetadataPath: "/var/lib/example/client-metadata.json",
    authStateDirectory: "/var/lib/example/auth",
    browserCapturePath: "/opt/example/bin/capture-authorization-url",
    authorizationCapturePath: "/var/lib/example/auth/authorization-url.txt",
    authTimeoutSeconds: 240,
  };
}

describe("secure MCP bridge", () => {
  it("builds an argument-vector launch plan without credential values", () => {
    const plan = buildSecureMcpBridgeLaunchPlan(fixture());
    expect(plan.command).toBe("/opt/example/bin/mcp-remote");
    expect(plan.args).toContain("@/var/lib/example/client-info.json");
    expect(plan.args).not.toContain("client-secret");
    expect(plan.env).toEqual({
      MCP_REMOTE_CONFIG_DIR: "/var/lib/example/auth",
      BROWSER: "/opt/example/bin/capture-authorization-url",
      OPENCLAW_AUTHORIZATION_CAPTURE_PATH: "/var/lib/example/auth/authorization-url.txt",
    });
  });

  it("loads only explicitly named protected credential environment bindings", () => {
    expect(
      loadProtectedCredentialsFromEnvironment(
        {
          EXAMPLE_CLIENT_ID: "synthetic-client",
          EXAMPLE_CLIENT_SECRET: "synthetic-secret",
          UNRELATED_VALUE: "ignored",
        },
        ["EXAMPLE_CLIENT_ID", "EXAMPLE_CLIENT_SECRET"],
      ),
    ).toEqual([
      { environmentName: "EXAMPLE_CLIENT_ID", value: "synthetic-client" },
      { environmentName: "EXAMPLE_CLIENT_SECRET", value: "synthetic-secret" },
    ]);
    expect(() => loadProtectedCredentialsFromEnvironment({}, ["EXAMPLE_CLIENT_SECRET"])).toThrow(
      /unavailable/,
    );
  });

  it("validates an allowlisted authorization URL", () => {
    const url = new URL("https://auth.example.test/oauth/authorize");
    url.searchParams.set("client_id", "synthetic-client");
    url.searchParams.set("redirect_uri", fixture().callbackUrl);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("state", "synthetic-state");
    url.searchParams.set("code_challenge", "synthetic-challenge");
    url.searchParams.set("scope", "mcp:read");
    expect(validateAuthorizationUrl(url.toString(), fixture()).hostname).toBe("auth.example.test");
  });

  it("rejects authorization hosts and redirects that are not exact", () => {
    const config = fixture();
    const url = new URL("https://other.example.test/oauth/authorize");
    for (const [key, value] of Object.entries({
      client_id: "synthetic-client",
      redirect_uri: config.callbackUrl,
      response_type: "code",
      state: "synthetic-state",
      code_challenge: "synthetic-challenge",
      scope: "mcp:read",
    })) {
      url.searchParams.set(key, value);
    }
    expect(() => validateAuthorizationUrl(url.toString(), config)).toThrow(/not allowlisted/);
    url.hostname = "auth.example.test";
    url.searchParams.set("redirect_uri", "http://localhost:7444/oauth/callback");
    expect(() => validateAuthorizationUrl(url.toString(), config)).toThrow(/does not match/);
    url.searchParams.set("redirect_uri", config.callbackUrl);
    url.searchParams.set("scope", "mcp:admin");
    expect(() => validateAuthorizationUrl(url.toString(), config)).toThrow(/not allowlisted/);
    url.searchParams.set("scope", "mcp:read");
    url.port = "8443";
    expect(() => validateAuthorizationUrl(url.toString(), config)).toThrow(/default HTTPS port/);
  });

  it("requires a matching loopback callback carrying one code and state", () => {
    const callback = "http://localhost:7331/oauth/callback?code=synthetic&state=synthetic-state";
    expect(
      validateCallbackUrl(callback, fixture(), "synthetic-state").searchParams.get("code"),
    ).toBe("synthetic");
    expect(() =>
      validateCallbackUrl(
        "http://127.0.0.1:7331/oauth/callback?code=synthetic&state=synthetic-state",
        fixture(),
      ),
    ).toThrow(/does not match/);
    expect(() => validateCallbackUrl(callback, fixture(), "other-state")).toThrow(
      /state does not match/,
    );
  });

  it("redacts every OAuth query value", () => {
    const redacted = redactOAuthUrl(
      "https://auth.example.test/oauth/authorize?client_id=synthetic&state=private-state",
    );
    expect(redacted).not.toContain("synthetic");
    expect(redacted).not.toContain("private-state");
    expect(redacted).toContain("%5Bredacted%5D");
  });

  it("rejects unsafe endpoint and callback configuration", () => {
    expect(() =>
      validateSecureMcpBridgeConfig({ ...fixture(), endpointUrl: "http://mcp.example.test" }),
    ).toThrow(/HTTPS/);
    expect(() =>
      validateSecureMcpBridgeConfig({
        ...fixture(),
        callbackUrl: "http://192.0.2.10:7331/oauth/callback",
      }),
    ).toThrow(/loopback/);
  });

  it("writes bridge state atomically with private modes", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "secure-mcp-bridge-"));
    const target = path.join(root, "private", "authorization-url.txt");
    await writePrivateFileAtomically(target, "synthetic-state\n");
    expect(await readFile(target, "utf8")).toBe("synthetic-state\n");
    expect((await stat(path.dirname(target))).mode & 0o777).toBe(0o700);
    expect((await stat(target)).mode & 0o777).toBe(0o600);
  });

  it("captures an authorization URL privately and returns only a redacted diagnostic", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "secure-mcp-capture-"));
    const config = {
      ...fixture(),
      authorizationCapturePath: path.join(root, "private", "authorization-url.txt"),
    };
    const url = new URL("https://auth.example.test/oauth/authorize");
    url.searchParams.set("client_id", "synthetic-client");
    url.searchParams.set("redirect_uri", config.callbackUrl);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("state", "synthetic-state");
    url.searchParams.set("code_challenge", "synthetic-challenge");
    url.searchParams.set("scope", "mcp:read");
    const diagnostic = await capturePrivateAuthorizationUrl(url.toString(), config);
    expect(diagnostic).not.toContain("synthetic-client");
    expect(diagnostic).not.toContain("synthetic-state");
    expect(await readFile(config.authorizationCapturePath, "utf8")).toContain("synthetic-state");
    expect((await stat(config.authorizationCapturePath)).mode & 0o777).toBe(0o600);
  });
});

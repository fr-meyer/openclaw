import assert from "node:assert/strict";
import { constants, generateKeyPairSync, verify } from "node:crypto";
import http from "node:http";
import https from "node:https";
import { createRequire } from "node:module";
import net from "node:net";
import path from "node:path";
import test from "node:test";
import tls from "node:tls";
import { fileURLToPath } from "node:url";

// Each native fixture runs in its own secretless child process. Additionally
// discard ambient provider/proxy configuration before loading either SDK. Do
// not print or use any inherited value, or consult a default runtime profile.
for (const name of Object.keys(process.env)) {
  if (name === "MSAL_TEST_PROJECT") {
    continue;
  }
  if (
    /^(?:AZURE_|MSAL_|IDENTITY_|MSI_|IMDS_|CLIENT_ID$|CLIENT_SECRET$|TENANT_ID$|MANAGED_IDENTITY_CLIENT_ID$|HTTPS?_PROXY$|ALL_PROXY$|NO_PROXY$)/i.test(
      name,
    )
  ) {
    delete process.env[name];
  }
}

// Fail closed before loading either actual parent: no provider, IMDS or other
// real network operation is permitted in this synthetic compatibility fixture.
let forbiddenNetworkCalls = 0;
function forbidNetwork() {
  forbiddenNetworkCalls++;
  throw new Error("real network forbidden in synthetic MSAL fixture");
}
http.request = https.request = http.get = https.get = forbidNetwork;
net.connect = net.createConnection = tls.connect = forbidNetwork;
globalThis.fetch = forbidNetwork;

// Commit this file under test/. The actual MSAL dependency owner is the Teams
// workspace, not the root package. An explicit override preserves tiny fixtures.
const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const projectOverride = process.env.MSAL_TEST_PROJECT;
if (projectOverride !== undefined) {
  assert.ok(projectOverride.trim(), "MSAL_TEST_PROJECT must be nonempty");
}
const project = path.resolve(projectOverride ?? path.join(repositoryRoot, "extensions/msteams"));
const require = createRequire(path.join(project, "package.json"));
const identityPath = require.resolve("@azure/identity/package.json");
const teamsPath = require.resolve("@microsoft/teams.apps/package.json");
const identityRequire = createRequire(identityPath);
const teamsRequire = createRequire(teamsPath);
const msal = identityRequire("@azure/msal-node");
const { ClientSecretCredential, ClientCertificateCredential } = require("@azure/identity");
const { createHttpHeaders } = identityRequire("@azure/core-rest-pipeline");
const { TokenManager } = teamsRequire("./dist/token-manager.js");

const tenantId = "11111111-1111-4111-8111-111111111111";
const clientId = "22222222-2222-4222-8222-222222222222";
const scope = "https://graph.microsoft.com/.default";
const authorityHost = "login.microsoftonline.com";
const b64 = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
const token = `${b64({ alg: "none", typ: "JWT" })}.${b64({ aud: "https://graph.microsoft.com", tid: tenantId, appid: clientId, exp: Math.floor(Date.now() / 1000) + 3600 })}.synthetic`;
const discovery = {
  authorization_endpoint: `https://${authorityHost}/${tenantId}/oauth2/v2.0/authorize`,
  token_endpoint: `https://${authorityHost}/${tenantId}/oauth2/v2.0/token`,
  issuer: `https://${authorityHost}/${tenantId}/v2.0`,
  jwks_uri: `https://${authorityHost}/${tenantId}/discovery/v2.0/keys`,
  end_session_endpoint: `https://${authorityHost}/${tenantId}/oauth2/v2.0/logout`,
};
const responseBody = {
  token_type: "Bearer",
  scope,
  expires_in: 3600,
  ext_expires_in: 3600,
  access_token: token,
};
function fakeService(events, inspectPost = () => {}) {
  return async (url, method, body) => {
    const parsed = new URL(url);
    assert.equal(parsed.hostname, authorityHost);
    events.push({ method, path: parsed.pathname });
    if (method === "GET" && parsed.pathname.endsWith("/.well-known/openid-configuration")) {
      return discovery;
    }
    assert.equal(method, "POST");
    assert.equal(parsed.pathname, `/${tenantId}/oauth2/v2.0/token`);
    inspectPost(new URLSearchParams(body));
    return responseBody;
  };
}
function azureTransport(events, inspectPost) {
  const service = fakeService(events, inspectPost);
  return {
    async sendRequest(request) {
      return {
        request,
        status: 200,
        headers: createHttpHeaders({ "content-type": "application/json" }),
        bodyAsText: JSON.stringify(await service(request.url, request.method, request.body)),
      };
    },
  };
}
function nativeTransport(events, inspectPost) {
  const service = fakeService(events, inspectPost);
  return {
    async sendGetRequestAsync(url) {
      return { status: 200, headers: {}, body: await service(url, "GET") };
    },
    async sendPostRequestAsync(url, options) {
      return { status: 200, headers: {}, body: await service(url, "POST", options?.body) };
    },
  };
}
const logger = {
  child() {
    return this;
  },
  log() {},
  debug() {},
  info() {},
  warn() {},
  error() {},
  loggerOptions: { level: "error" },
};

void test("both actual parent resolvers use fixed MSAL 7.1.0 and common 16.14.2", () => {
  for (const parent of [identityRequire, teamsRequire]) {
    assert.equal(parent("@azure/msal-node/package.json").version, "7.1.0");
    const child = createRequire(parent.resolve("@azure/msal-node/package.json"));
    assert.equal(child("@azure/msal-common/package.json").version, "16.14.2");
  }
  assert.equal(require("@azure/identity/package.json").version, "4.13.3");
  assert.equal(require("@microsoft/teams.apps/package.json").version, "2.1.0");
});

void test(
  "actual Azure Identity secret flow returns and caches a fake token through real MSAL",
  { timeout: 5000 },
  async () => {
    const events = [];
    const credential = new ClientSecretCredential(tenantId, clientId, "synthetic-secret", {
      disableInstanceDiscovery: true,
      httpClient: azureTransport(events, (body) => {
        assert.equal(body.get("grant_type"), "client_credentials");
        assert.equal(body.get("client_id"), clientId);
        assert.equal(body.get("client_secret"), "synthetic-secret");
      }),
      retryOptions: { maxRetries: 0 },
    });
    const result = await credential.getToken(scope);
    assert.equal(result.token, token);
    assert.ok(result.expiresOnTimestamp > Date.now());
    const requests = events.length;
    assert.equal((await credential.getToken(scope)).token, token);
    assert.equal(events.length, requests);
  },
);

void test(
  "actual Azure certificate flow signs a synthetic assertion and preserves token result",
  { timeout: 5000 },
  async () => {
    const events = [];
    const keys = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    // Opaque synthetic certificate envelope: tests local signing/SDK handling,
    // not acceptance of a real certificate by an authentication provider.
    const certificate = `-----BEGIN CERTIFICATE-----\n${Buffer.from("synthetic-public-certificate").toString("base64")}\n-----END CERTIFICATE-----\n${keys.privateKey}`;
    let assertionChecked = false;
    const credential = new ClientCertificateCredential(
      tenantId,
      clientId,
      { certificate },
      {
        disableInstanceDiscovery: true,
        httpClient: azureTransport(events, (body) => {
          assert.equal(body.get("grant_type"), "client_credentials");
          assert.equal(
            body.get("client_assertion_type"),
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          );
          const [header, claims, signature] = body.get("client_assertion").split(".");
          // Identity provides thumbprintSha256; MSAL consequently selects PS256.
          assert.equal(JSON.parse(Buffer.from(header, "base64url")).alg, "PS256");
          assert.equal(JSON.parse(Buffer.from(claims, "base64url")).iss, clientId);
          assert.equal(
            verify(
              "RSA-SHA256",
              Buffer.from(`${header}.${claims}`),
              { key: keys.publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
              Buffer.from(signature, "base64url"),
            ),
            true,
          );
          assertionChecked = true;
        }),
        retryOptions: { maxRetries: 0 },
      },
    );
    assert.equal((await credential.getToken(scope)).token, token);
    assert.equal(assertionChecked, true);
  },
);

void test(
  "actual Teams TokenManager secret flow runs its real confidential client and token wrapper",
  { timeout: 5000 },
  async () => {
    const events = [];
    const manager = new TokenManager(
      { clientId, tenantId, clientSecret: "synthetic-secret" },
      logger,
    );
    const client = manager.getConfidentialClient(manager.credentials, tenantId);
    assert.ok(client instanceof msal.ConfidentialClientApplication);
    // Per-instance test-only internal transport seam. Do not change source or
    // stub acquireTokenByClientCredential: the real SDK and MSAL execute it.
    client.config.auth.knownAuthorities = [authorityHost];
    client.config.system.networkClient = nativeTransport(events, (body) => {
      assert.equal(body.get("client_secret"), "synthetic-secret");
      assert.equal(body.get("grant_type"), "client_credentials");
    });
    assert.equal((await manager.getGraphToken(tenantId)).toString(), token);
    assert.equal(manager.getConfidentialClient(manager.credentials, tenantId), client);
    assert.ok(events.some((event) => event.method === "POST"));
  },
);

void test("actual Teams managed-identity configuration and consumed methods remain present without IMDS access", () => {
  const manager = new TokenManager({ clientId, tenantId }, logger);
  const client = manager.getManagedIdentityClient(manager.credentials);
  assert.ok(client instanceof msal.ManagedIdentityApplication);
  assert.equal(client.config.managedIdentityId.id, clientId);
  assert.equal(typeof client.acquireToken, "function");
  assert.equal(manager.getManagedIdentityClient(manager.credentials), client);
  for (const method of [
    "acquireTokenByClientCredential",
    "acquireTokenByCode",
    "acquireTokenOnBehalfOf",
    "acquireTokenByUserFederatedIdentityCredential",
  ]) {
    assert.equal(typeof msal.ConfidentialClientApplication.prototype[method], "function");
  }
});

void test("fixed confidential client rejects unsupported instance-aware inputs", async () => {
  assert.throws(
    () =>
      new msal.ConfidentialClientApplication({
        auth: { clientId, clientSecret: "synthetic-secret", instanceAware: true },
      }),
    (error) => error.errorCode === "unsupported_cca_instance_aware",
  );
  const client = new msal.ConfidentialClientApplication({
    auth: { clientId, clientSecret: "synthetic-secret" },
  });
  await assert.rejects(
    client.getAuthCodeUrl({
      scopes: [scope],
      redirectUri: "https://synthetic.invalid/callback",
      extraQueryParameters: { instance_aware: "true" },
    }),
    (error) => error.errorCode === "unsupported_cca_instance_aware",
  );
});

void test(
  "fixed auth-code path keeps request code and strips untrusted cloud-instance payload fields",
  { timeout: 5000 },
  async () => {
    const events = [];
    const client = new msal.ConfidentialClientApplication({
      auth: {
        clientId,
        clientSecret: "synthetic-secret",
        authority: `https://${authorityHost}/${tenantId}`,
        knownAuthorities: [authorityHost],
      },
      system: {
        networkClient: nativeTransport(events, (body) =>
          assert.equal(body.get("code"), "synthetic-safe-code"),
        ),
      },
    });
    const result = await client.acquireTokenByCode(
      {
        code: "synthetic-safe-code",
        scopes: [scope],
        redirectUri: "https://synthetic.invalid/callback",
      },
      {
        code: "untrusted-payload-code",
        cloud_instance_host_name: "untrusted.invalid",
        cloud_graph_host_name: "untrusted.invalid",
      },
    );
    assert.equal(result.accessToken, token);
    assert.ok(events.some((event) => event.method === "POST"));
  },
);

void test("no real authentication/provider/network call occurred", () =>
  assert.equal(forbiddenNetworkCalls, 0));

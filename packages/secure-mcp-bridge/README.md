# Secure MCP Bridge

`@openclaw/secure-mcp-bridge` contains vendor-neutral, fail-closed primitives for launching an
OAuth-capable remote MCP bridge without placing credentials in command arguments or logs.

The package:

- validates HTTPS MCP endpoints, authorization hosts, and requested OAuth scopes;
- loads only explicitly named credentials from an already protected child environment;
- requires an exact loopback OAuth callback;
- builds an argument-vector-only `mcp-remote` launch plan;
- validates authorization URLs and callback state before they are persisted or relayed;
- redacts OAuth query values for diagnostics;
- writes sensitive bridge state atomically with private filesystem modes.

It deliberately does not read `.env` files, prompt for client secrets, open a browser, or choose a
credential provider. Callers must resolve credentials through OpenClaw SecretRefs or another
approved protected store and keep the credential payload out of this package's launch plan.

All examples and tests use reserved synthetic domains and temporary paths.

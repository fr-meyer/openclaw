# Local MCP Service Supervisor

`@openclaw/local-mcp-service-supervisor` preserves reusable, Linux-oriented safety primitives for
supervising local HTTP MCP processes.

It provides:

- strict service-plan validation with absolute executable and state paths;
- loopback-only listener verification from `/proc/net/tcp` and `/proc/net/tcp6` snapshots;
- strict PID and command-line identity checks before process control;
- bounded loopback health probes that do not follow redirects;
- rejection of `.env` and `--env-file` process arguments;
- deterministic redaction for common credential-bearing log fields;
- safe start-plan construction without shell interpolation.

The package does not contain a service registry, production ports, host paths, credentials, or
deployment commands. Callers remain responsible for choosing a process manager and for resolving
secrets through an approved protected store.

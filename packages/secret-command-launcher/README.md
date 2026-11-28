# Secret Command Launcher

`@openclaw/secret-command-launcher` builds shell-free process launch plans for legacy commands that
still require secrets through environment variables.

The caller resolves secret values through OpenClaw SecretRefs or another approved protected store.
This package never reads `.env` files, accepts secret values in command arguments, or includes
secret values in summaries.

The package is intentionally small so service-specific wrappers can share one auditable boundary
instead of reimplementing credential handling around every command.

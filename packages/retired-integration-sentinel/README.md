# Retired Integration Sentinel

`@openclaw/retired-integration-sentinel` provides a deterministic fail-closed replacement for an
integration entrypoint that has been intentionally retired.

The sentinel emits one bounded diagnostic, returns a stable non-zero exit code, ignores untrusted
arguments, and exposes structured status without invoking the retired integration. It is useful
when an old executable path must remain present during a migration or rollback window.

The packaged `retired-integration-sentinel` executable accepts only bounded configuration through
its documented `OPENCLAW_RETIRED_INTEGRATION_*` environment variables. Invalid configuration also
fails closed.

The package contains no deployment names, paths, commands, or replacement endpoints.

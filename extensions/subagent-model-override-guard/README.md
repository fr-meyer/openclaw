# Subagent Model Override Guard

This bundled security plugin blocks explicit per-call `model` overrides on `sessions_spawn`. It keeps the configured subagent default and fallback chain authoritative instead of allowing a caller to select a different model for one spawn.

The policy is enabled by default for every agent. Configuration can narrow it to selected coordinator agents, change the denial message, or also block explicit `thinking` overrides.

```json5
{
  plugins: {
    entries: {
      "subagent-model-override-guard": {
        enabled: true,
        config: {
          agentIds: ["coordinator"],
          blockThinkingOverride: true,
        },
      },
    },
  },
}
```

Omit `model` and, when configured, `thinking` from `sessions_spawn` calls so OpenClaw uses the subagent defaults selected in configuration.

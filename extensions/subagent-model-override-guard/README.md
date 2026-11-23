# Subagent Model Override Guard

This bundled security plugin blocks explicit per-call `model` overrides on `sessions_spawn`. It keeps the configured subagent default and fallback chain authoritative instead of allowing a caller to select a different model for one spawn.

The bundled plugin is opt-in: enable it with `plugins.entries` as shown below. Once the plugin is enabled, its policy applies to every agent by default. Configuration can narrow it to selected coordinator agents, change the denial message, or also block explicit `thinking` overrides.

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

## Configuration surface

The plugin is opt-in through the existing plugin entry enable switch. Its four
policy settings are local to this plugin: enabled can suspend enforcement without
unloading the plugin, agentIds scopes enforcement, blockThinkingOverride opts into
the separate thinking restriction, and message customizes the model denial.
Existing model defaults select the model when no override is supplied; they do
not prohibit callers from supplying an override. Plugin subagent permissions
govern plugin-originated runs, not the agent's sessions_spawn tool calls. Those
existing controls therefore cannot replace this trusted tool policy.

The config baseline grows by 26 plugin paths for this new plugin entry, not 26
new policy settings. The shared plugin entry contributes 21 paths (the entry
itself, enable switch, hook controls, subagent and LLM permissions, config object
without a wildcard); the four policy properties and the agentIds item contribute
five more. No core or channel setting is added. Regenerate the tracked config
counts and hashes with pnpm config:docs:gen, and justify this opt-in plugin
surface in the PR body rather than bypassing the config-surface check.

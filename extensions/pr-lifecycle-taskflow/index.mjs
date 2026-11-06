import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { registerPrLifecycleTaskflow } from "./src/runtime.mjs";

export default definePluginEntry({
  id: "pr-lifecycle-taskflow",
  name: "PR Lifecycle TaskFlow",
  description:
    "Durable exact-head review, bounded remediation, and explicitly authorized merge orchestration through OpenClaw TaskFlow.",
  register: registerPrLifecycleTaskflow,
});

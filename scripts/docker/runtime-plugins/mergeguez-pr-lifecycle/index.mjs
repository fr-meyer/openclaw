import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { registerMergeguezPrLifecycle } from "./src/runtime.mjs";

export default definePluginEntry({
  id: "mergeguez-pr-lifecycle",
  name: "Mergeguez PR Lifecycle",
  description:
    "Durable exact-head Mergeguez review and bounded author remediation through OpenClaw TaskFlow.",
  register: registerMergeguezPrLifecycle,
});

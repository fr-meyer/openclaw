#!/usr/bin/env node

const id = process.env.OPENCLAW_RETIRED_INTEGRATION_ID ?? "retired-integration";
const reason =
  process.env.OPENCLAW_RETIRED_INTEGRATION_REASON ?? "the integration was intentionally retired";
const replacement = process.env.OPENCLAW_RETIRED_INTEGRATION_REPLACEMENT?.trim();
const rawExitCode = process.env.OPENCLAW_RETIRED_INTEGRATION_EXIT_CODE ?? "64";
const exitCode = Number(rawExitCode);
const safeText = (value, minimum, maximum) =>
  value.length >= minimum && value.length <= maximum && !/[\u0000-\u001f\u007f]/u.test(value);

if (!/^[a-z0-9][a-z0-9._-]{0,79}$/u.test(id)) {
  process.stderr.write("blocked: retired integration sentinel has an invalid identifier\n");
  process.exitCode = 78;
} else if (!safeText(reason.trim(), 1, 500)) {
  process.stderr.write("blocked: retired integration sentinel has an invalid reason\n");
  process.exitCode = 78;
} else if (replacement !== undefined && !safeText(replacement, 1, 300)) {
  process.stderr.write("blocked: retired integration sentinel has an invalid replacement\n");
  process.exitCode = 78;
} else if (!Number.isInteger(exitCode) || exitCode < 1 || exitCode > 255) {
  process.stderr.write("blocked: retired integration sentinel has an invalid exit code\n");
  process.exitCode = 78;
} else {
  const replacementNotice = replacement ? `; replacement: ${replacement}` : "";
  process.stderr.write(
    `blocked: integration ${id} is retired; reason: ${reason.trim()}${replacementNotice}\n`,
  );
  process.exitCode = exitCode;
}

// This independent container process owns the fixture CPU ceiling if the host observer disappears.
import { spawn } from "node:child_process";
import fs from "node:fs";

const child = spawn(process.execPath, process.argv.slice(2), { stdio: "inherit", env: process.env });
let failure;
let stopTimer;
function refuse(reason) {
  if (failure) return;
  failure = reason;
  console.error("TASK20_WATCHDOG_REFUSED " + JSON.stringify({ reason }));
  child.kill("SIGTERM");
  // PID1's GNU timeout exits when this monitor exits; the private PID namespace then drains.
  stopTimer = setTimeout(() => process.exit(124), 500);
}
const timer = setInterval(() => {
  try {
    const cpu = Object.fromEntries(fs.readFileSync("/sys/fs/cgroup/cpu.stat", "utf8").trim().split("\n").map((line) => line.split(/\s+/u)));
    // Leave one CPU second for bounded failure shutdown inside the thirty-second envelope.
    if (Number(cpu.usage_usec) >= 29_000_000) refuse("aggregate CPU reserve reached");
  } catch (error) {
    refuse("aggregate CPU counter unavailable: " + error.message);
  }
}, 100);
process.once("SIGTERM", () => refuse("container deadline or observer stop"));
process.once("SIGINT", () => refuse("container interrupted"));
child.once("error", (error) => refuse("fixture spawn failed: " + error.message));
child.once("exit", (code, signal) => {
  clearInterval(timer);
  clearTimeout(stopTimer);
  process.exit(failure ? 124 : signal ? 1 : code ?? 1);
});

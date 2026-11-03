import { afterEach, describe, expect, it, vi } from "vitest";
import { prepareDoctorCliStartup } from "./run-main-doctor-startup.js";

const preflightUpdateDoctorCli = vi.hoisted(() => vi.fn());
vi.mock("../commands/doctor-update-schema-guard.js", () => ({ preflightUpdateDoctorCli }));

describe("Doctor CLI startup reuse proof", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    preflightUpdateDoctorCli.mockClear();
  });

  it("rejects a malformed proof before update-mode database preflight", async () => {
    vi.stubEnv("OPENCLAW_UPDATE_IN_PROGRESS", "1");
    vi.stubEnv("OPENCLAW_UPDATE_POST_INSTALL_DOCTOR_RESULT_PATH", "");
    vi.stubEnv("OPENCLAW_DOCTOR_BACKUP_REUSE_PROOF", "{}");

    await expect(prepareDoctorCliStartup(["node", "openclaw", "doctor"], { json: false })).rejects.toThrow(
      "proof fields or syntax differ from the reviewed contract",
    );
    expect(preflightUpdateDoctorCli).not.toHaveBeenCalled();
  });
});

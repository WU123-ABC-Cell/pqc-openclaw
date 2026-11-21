import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { configureFsSafeNative } = vi.hoisted(() => ({
  configureFsSafeNative: vi.fn(),
}));

vi.mock("@openclaw/fs-safe/config", () => ({ configureFsSafeNative }));

describe("memory host fs-safe defaults", () => {
  beforeEach(() => {
    vi.resetModules();
    for (const prefix of ["", "OPENCLAW_"]) {
      for (const mode of ["NATIVE", "PYTHON"]) {
        vi.stubEnv(`${prefix}FS_SAFE_${mode}_MODE`, undefined);
      }
    }
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    configureFsSafeNative.mockReset();
  });

  it("leaves the Windows host's native ACL mode intact", async () => {
    vi.spyOn(process, "platform", "get").mockReturnValue("win32");
    await import("./fs-utils.js");
    expect(configureFsSafeNative).not.toHaveBeenCalled();
  });

  it("retains the non-Windows default", async () => {
    vi.spyOn(process, "platform", "get").mockReturnValue("linux");
    await import("./fs-utils.js");
    expect(configureFsSafeNative).toHaveBeenCalledWith({ mode: "off" });
  });

  it("respects an explicit non-Windows native mode", async () => {
    vi.spyOn(process, "platform", "get").mockReturnValue("linux");
    vi.stubEnv("OPENCLAW_FS_SAFE_NATIVE_MODE", "require");
    await import("./fs-utils.js");
    expect(configureFsSafeNative).not.toHaveBeenCalled();
  });
});

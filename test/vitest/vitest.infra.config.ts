// Vitest infra config wires the infra test shard.
import { createScopedVitestConfig } from "./vitest.scoped-config.ts";
import { boundaryTestFiles } from "./vitest.unit-paths.mjs";

export function createInfraVitestConfig(env?: Record<string, string | undefined>) {
  return createScopedVitestConfig(
    [
      "src/commands/wrap-key.test.ts",
      "src/flows/doctor-core-checks.test.ts",
      "src/infra/**/*.test.ts",
      "src/security/**/*.test.ts",
    ],
    {
      dir: "src",
      env,
      exclude: boundaryTestFiles,
      // PQC 2.2.5: include wrapping integration tests that OpenClaw
      // would otherwise exclude as "unit fast" candidates.
      excludeUnitFastTests: false,
      fileParallelism: false,
      isolate: true,
      name: "infra",
      passWithNoTests: true,
      pool: "forks",
    },
  );
}

export default createInfraVitestConfig();

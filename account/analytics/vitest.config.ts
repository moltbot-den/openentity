import { defineConfig } from "vitest/config";

// Own module-cache dir: `pnpm -r test` runs this package next to infra, and two vitest processes sharing
// <root>/node_modules/.vitest-cache race on its cleanup (ENOTEMPTY at startup).
export default defineConfig({ test: { fsModuleCachePath: "node_modules/.vitest-cache-account-analytics" } });

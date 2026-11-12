import { defineConfig } from "vitest/config";

// account/analytics is the Monitoring lane's own workspace package with its own suite; run only this package's tests.
export default defineConfig({ test: { include: ["test/**/*.test.ts"], testTimeout: 30_000 } });

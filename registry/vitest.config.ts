import { defineConfig } from "vitest/config";

// A fresh PGlite (WASM Postgres plus schema.sql) boots inside several tests; beside the other packages in `pnpm -r test` that passed the 5 s default.
export default defineConfig({ test: { testTimeout: 30_000 } });

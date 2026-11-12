import { defineConfig } from "vitest/config";

// Browser checks of the web pages (playwright-core with the installed Google Chrome). Not part of `test`: run with
// `pnpm --filter @openentity/account e2e` (through ~/.cache/oe-heavy.sh on the shared Mac).
export default defineConfig({ test: { include: ["e2e/**/*.e2e.ts"], testTimeout: 60_000, hookTimeout: 60_000 } });

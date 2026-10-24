import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";

// Fresh throwaway keys per run; nothing secret is committed.
const { privateKey } = generateKeyPairSync("ed25519");

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.toml" },
      miniflare: {
        bindings: {
          STAMP_BITS: "8",
          REGISTRY_KEY_JWK: JSON.stringify(privateKey.export({ format: "jwk" })),
          CUSTODY_KEY: randomBytes(32).toString("base64"),
          HASH_SALT: "test-salt",
          SCHEMA_SQL: readFileSync("schema.sql", "utf8"),
          BASE_RPC_URL: "https://rpc.test",
        },
      },
    }),
  ],
  test: { setupFiles: ["./test/setup.ts"] },
});

// Guard tests: each fails if the forbidden-field rule (PLAN 13.1) is weakened.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { loadSpec, render } from "../gen.mjs";
import { validateEvent } from "../src/validate.ts";

const root = join(import.meta.dirname, "..");
const spec = loadSpec();
const tmp = mkdtempSync(join(tmpdir(), "oe-analytics-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const base = { event_id: "0b2f7f5e-6d0c-4a39-8c1e-3f1d2a4b5c6d", ts_ms: 1790000000000, install_id: "inst-1", platform: "ios" };
const signIn = (props: Record<string, unknown>) => validateEvent({ ...base, event: "sign_in_failed", props: { method: "apple", reason: "expired", ...props } });

describe("forbidden fields", () => {
  it("no declared property is forbidden", () => {
    const all = new Set<string>([...Object.keys(spec.common)]);
    for (const e of Object.values<any>(spec.events)) Object.keys(e.props).forEach((k) => all.add(k));
    for (const k of all) {
      expect(spec.forbidden.names).not.toContain(k);
      for (const s of spec.forbidden.name_contains) expect(k).not.toContain(s);
    }
  });

  it("the generator refuses a yaml that declares a forbidden property", () => {
    const text = readFileSync(join(root, "events.yaml"), "utf8").replace("app_first_opened:   { source: client }", "app_first_opened: { source: client, props: { email: { type: token } } }");
    const f = join(tmp, "bad.yaml");
    writeFileSync(f, text);
    expect(() => loadSpec(f)).toThrow(/forbidden/);
  });

  it.each(["email", "email_address", "summary", "approval_summary", "message_text", "secret_path", "secret_value", "photo"])("validator rejects property %s", (k) => {
    const r = signIn({ [k]: "x" });
    expect(r.ok).toBe(false);
  });

  it.each([
    ["an email address", "will@example.com"],
    ["approval text", "Approve payment of 5 USD"],
    ["a secret path", "prod/stripe/live_key"],
    ["a secret value", "sk_live_abc 123"],
  ])("validator rejects %s as a value", (_n, v) => {
    expect(signIn({ reason: v }).ok).toBe(false);
  });

  it("validator rejects undeclared events and server events from the client door", () => {
    expect(validateEvent({ ...base, event: "made_up", props: {} }).ok).toBe(false);
    expect(validateEvent({ ...base, event: "purchase_completed", props: { sku: "a", rail: "stripe", price_usd: 1, storefront: "US" } }, { allow: ["client", "web"] }).ok).toBe(false);
    expect(validateEvent({ ...base, event: "app_opened", props: {} }, { allow: ["client", "web"] }).ok).toBe(true);
  });

  it("validator accepts a good event with an agent DID", () => {
    expect(signIn({ agent_did: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" }).ok).toBe(true);
  });

  it("generated files are current", () => {
    for (const [f, text] of Object.entries(render())) expect(readFileSync(join(root, f), "utf8"), f).toBe(text);
  });

  it("generated Swift and Kotlin only write declared, non-forbidden keys", () => {
    for (const f of ["generated/swift/Analytics.swift", "generated/kotlin/Analytics.kt"]) {
      const keys = [...readFileSync(join(root, f), "utf8").matchAll(/p\["(\w+)"\]/g)].map((m) => m[1]);
      expect(keys.length).toBeGreaterThan(0);
      for (const k of keys) {
        expect(spec.forbidden.names).not.toContain(k);
        for (const s of spec.forbidden.name_contains) expect(k).not.toContain(s);
      }
    }
  });

  it("generated Python cannot send an undeclared property or a free-text value", () => {
    const code = [
      "import openentity_analytics as a",
      "a.sign_in_failed(method='apple', reason='expired')",
      "for kw in ({'email': 'x'}, {'summary': 'x'}):",
      "    try: a.sign_in_failed(method='apple', reason='x', **kw); raise SystemExit('accepted ' + str(kw))",
      "    except TypeError: pass",
      "try: a.sign_in_failed(method='apple', reason='me@x.co'); raise SystemExit('accepted email value')",
      "except ValueError: pass",
      "try: a.AnalyticsEvent('app_opened', 'client', {})\nexcept TypeError: pass\nelse: raise SystemExit('forged event')",
    ].join("\n");
    execFileSync("python3", ["-c", code], { env: { ...process.env, PYTHONPATH: join(root, "generated/python") } });
  });
});

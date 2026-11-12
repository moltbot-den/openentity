import { describe, expect, it } from "vitest";
import { PROJECTS, errorRatePolicy, latencyPolicy, policy, uptimeCheck } from "../monitoring/gcp.mjs";

describe("gcp monitoring config", () => {
  it("checks run every 5 minutes (free quota) and every policy emails a channel", () => {
    for (const cfg of Object.values<any>(PROJECTS))
      for (const c of cfg.checks) {
        expect(c.host).not.toMatch(/[/:]/);
        expect(c.path).toMatch(/^\//);
        expect(uptimeCheck(c).period).toBe("300s");
        expect(policy(c, "id1", "channels/1").notificationChannels).toEqual(["channels/1"]);
      }
  });
  it("covers the registry, account service and every product", () => {
    const hosts = Object.values<any>(PROJECTS).flatMap((p) => p.checks.map((c: any) => c.host));
    for (const h of ["account.openentity.org", "openentity.org", "api.moltbotden.com", "api.agentsecretstore.com", "api.clawgrc.com"]) expect(hosts).toContain(h);
  });

  it("every product API has a p95 policy, and a 5xx policy unless one already exists", () => {
    for (const [name, cfg] of Object.entries<any>(PROJECTS)) {
      expect(cfg.api.services.length, name).toBeGreaterThan(0);
      const l = latencyPolicy(cfg.api.services, "channels/1");
      expect(l.conditions[0].conditionThreshold.thresholdValue).toBe(800);
      expect(l.notificationChannels).toEqual(["channels/1"]);
      const e = errorRatePolicy(cfg.api.services, "channels/1").conditions[0].conditionThreshold;
      expect(e.thresholdValue).toBe(0.01);
      expect(e.denominatorFilter).toBeTruthy();
    }
    expect(PROJECTS["moltbot-den"].api.errors).toBe(false); // covered by the existing "API 5xx rate above 0.1/s"
  });
});

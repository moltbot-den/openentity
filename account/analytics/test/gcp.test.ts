import { describe, expect, it } from "vitest";
import { PROJECTS, policy, uptimeCheck } from "../monitoring/gcp.mjs";

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
});

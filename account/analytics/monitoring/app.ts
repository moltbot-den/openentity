// Deploys the registry monitoring as its own stack (the OpenEntity stack is not touched):
//   Production: deploy.yml runs `npx cdk deploy OpenEntityMonitoring -a "npx tsx ../account/analytics/monitoring/app.ts"` from infra/ on every merge to main. Never deploy it from a branch.
// FUNCTION_NAME and DISTRIBUTION_IDS default to the OpenEntity stack outputs (the only thing the CI deploy role may read).
import { execFileSync } from "node:child_process";
import { App, Stack } from "aws-cdk-lib";
import { RegistryMonitoring } from "./registry.ts";

const out = (k: string) => execFileSync("aws", ["cloudformation", "describe-stacks", "--stack-name", "OpenEntity", "--query", `Stacks[0].Outputs[?OutputKey=='${k}'].OutputValue`, "--output", "text"], { encoding: "utf8" }).trim();
const app = new App();
const stack = new Stack(app, "OpenEntityMonitoring", { env: { account: "099705791378", region: "us-east-1" } });
new RegistryMonitoring(stack, "Registry", {
  alertEmail: "will@moltbotden.com", stage: "production",
  functionName: process.env.FUNCTION_NAME ?? out("FunctionName"),
  distributionIds: process.env.DISTRIBUTION_IDS?.split(",") ?? [out("DistributionId"), out("McpDistributionId")], // outputs only (the deploy role may only DescribeStacks on OpenEntity); the hub is covered by the uptime probe
  probeTargets: [
    { name: "registry /v1/stats", url: "https://openentity.org/v1/stats", expect: 200 },
    { name: "hub oeis.dev", url: "https://oeis.dev/", expect: 200 },
    { name: "mcp", url: "https://mcp.openentity.org/", expect: "lt500" }, // answers 406 without the MCP Accept header
  ],
});

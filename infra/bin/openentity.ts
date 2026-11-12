import { App } from "aws-cdk-lib";
import { OpenEntityAccountStack } from "../lib/account-stack.ts";
import { OpenEntityStack } from "../lib/stack.ts";

const app = new App();
const env = { account: "099705791378", region: "us-east-1" };
new OpenEntityStack(app, "OpenEntity", { env, terminationProtection: true });
// The account service (ADR 0007) in two stages; staging deploys first, production after it.
new OpenEntityAccountStack(app, "OpenEntityAccountStaging", { env, stage: "staging" });
new OpenEntityAccountStack(app, "OpenEntityAccount", { env, stage: "production", terminationProtection: true });
// Throwaway copy for the load test, synthesized only on request: cdk deploy OpenEntityLoad -c load=1, then cdk destroy.
if (app.node.tryGetContext("load")) new OpenEntityStack(app, "OpenEntityLoad", { env, load: true });

import { App } from "aws-cdk-lib";
import { OpenEntityStack } from "../lib/stack.ts";

const app = new App();
const env = { account: "099705791378", region: "us-east-1" };
new OpenEntityStack(app, "OpenEntity", { env, terminationProtection: true });
// Throwaway copy for the load test, synthesized only on request: cdk deploy OpenEntityLoad -c load=1, then cdk destroy.
if (app.node.tryGetContext("load")) new OpenEntityStack(app, "OpenEntityLoad", { env, load: true });

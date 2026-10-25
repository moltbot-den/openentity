import { App } from "aws-cdk-lib";
import { OpenEntityStack } from "../lib/stack.ts";

new OpenEntityStack(new App(), "OpenEntity", {
  env: { account: "099705791378", region: "us-east-1" },
  terminationProtection: true,
});

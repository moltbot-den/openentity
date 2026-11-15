// Deploys the Remotion Lambda render stack for the short-form videos (docs/SOCIAL.md "Video"), idempotently:
// the render role, the render function, the Remotion S3 bucket, and the composition site (social-video/).
// Writes registry/social/remotion.json, which the app Lambda reads to start renders. Re-run after changing social-video/ or the Remotion version.
//   AWS_PROFILE=openentity pnpm --filter @openentity/infra exec tsx scripts/remotion-deploy.ts
import { CreateRoleCommand, IAMClient, PutRolePolicyCommand } from "@aws-sdk/client-iam";
import { deployFunction, deploySite, getOrCreateBucket, getRolePolicy } from "@remotion/lambda";
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const region = "us-east-1";
const root = (p: string) => fileURLToPath(new URL(`../../${p}`, import.meta.url));
execFileSync("node", [root("social-video/scripts/prepare.mjs")], { stdio: "inherit" });

// Remotion looks up this role by name.
const iam = new IAMClient({ region });
try {
  await iam.send(new CreateRoleCommand({
    RoleName: "remotion-lambda-role",
    AssumeRolePolicyDocument: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { Service: "lambda.amazonaws.com" }, Action: "sts:AssumeRole" }] }),
  }));
} catch (e) {
  if ((e as Error).name !== "EntityAlreadyExistsException") throw e;
}
await iam.send(new PutRolePolicyCommand({ RoleName: "remotion-lambda-role", PolicyName: "remotion-lambda-policy", PolicyDocument: getRolePolicy() }));
await new Promise((r) => setTimeout(r, 10_000)); // a new role takes a few seconds to be assumable

const { functionName } = await deployFunction({ region, timeoutInSeconds: 120, memorySizeInMb: 2048, diskSizeInMb: 2048, createCloudWatchLogGroup: true, cloudWatchLogRetentionPeriodInDays: 30 });
const { bucketName } = await getOrCreateBucket({ region });
const { serveUrl } = await deploySite({ region, bucketName, siteName: "openentity-social", entryPoint: root("social-video/src/index.ts"), options: { publicDir: root("social-video/public") } });
writeFileSync(root("registry/social/remotion.json"), JSON.stringify({ region, functionName, serveUrl, bucket: bucketName }, null, 1) + "\n");
console.log({ functionName, bucketName, serveUrl });

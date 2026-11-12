// End-to-end check of agent pairing against a live account service (PLAN 8.1, 8.2), from the agent's side, with a throwaway
// did:key that never touches this machine's identity or any registry. The owner's side runs in the OpenEntity app (staging
// build or account web): it shows the code, compares the match items and confirms.
//   node scripts/pair-e2e.mjs OE-XXXX-XXXX [--account https://staging.account.openentity.org] [--listen 60]
// Without a code it only checks that the Agent API is deployed. Exit 0 when every step passed, 1 on a failed step, 2 when the
// service has no /v1/pair yet. Afterwards unlink "pair-e2e" in the app: the throwaway key is gone, so the agent cannot.
import { parseArgs } from "node:util";
import { generateKeyPair, Owner, pair } from "../sdk/ts/dist/index.js";

const { values: v, positionals } = parseArgs({ allowPositionals: true, options: { account: { type: "string" }, listen: { type: "string" } } });
const account = (v.account ?? "https://staging.account.openentity.org").replace(/\/+$/, "");
const code = positionals[0];
const steps = [];
async function step(name, fn) {
  try {
    const detail = await fn();
    steps.push([name, "PASS", detail ?? ""]);
  } catch (e) {
    steps.push([name, "FAIL", `${e.code ?? ""} ${e.message}`.trim()]);
  }
}
const report = (exit) => {
  for (const [name, result, detail] of steps) console.log(`${result}  ${name}${detail ? `: ${detail}` : ""}`);
  process.exit(exit ?? (steps.some((s) => s[1] === "FAIL") ? 1 : 0));
};

// 1. Is the Agent API there? An unsigned claim gets 400/401 from a deployed /v1/pair, 404 no such endpoint before it.
const probe = await fetch(`${account}/v1/pair`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
const probeBody = await probe.text();
if (probe.status === 404) {
  console.log(`${account}/v1/pair is not deployed yet (404: ${probeBody.slice(0, 120)}). Run this again once the Account lane ships pairing.`);
  process.exit(2);
}
steps.push(["POST /v1/pair is deployed", "PASS", `unsigned claim answered ${probe.status}`]);
if (!code) report();

// 2. Pair a throwaway agent: the owner compares the match items in the app and confirms.
const kp = await generateKeyPair();
console.log(`Agent ${kp.did}`);
let paired;
await step("pair (claim, local match check, owner confirms)", async () => {
  paired = await pair(code, {
    identity: kp, framework: "pair-e2e", sdk: "scripts/pair-e2e.mjs", sdkVersion: "1", host: "pair-e2e", account,
    onMatch: (names) => console.log(`Match: ${names.join(", ")}\nConfirm in the OpenEntity app if it shows the same four items...`),
  });
  return `owner ${paired.ownerDid}, permissions ${paired.permissions.join(", ") || "none"}, ${paired.credentials.length} product keys`;
});
if (!paired) report();

// 3. The owner channel, every call signed by the throwaway key.
const owner = new Owner(kp, { account });
await step("owner.status running", () => owner.status({ state: "running", summary: "pair-e2e: checking the owner channel", progress: 0.5 }));
await step("owner.message", async () => `id ${(await owner.message("pair-e2e: hello from the end-to-end check. Unlink me when done.")).id}`);
await step("owner.askApproval (low risk, 60 s)", async () => {
  const a = await owner.askApproval({ title: "pair-e2e test approval", summary: "A test request from the end-to-end check; approve or deny, either is fine.", risk: "low", expiresIn: 60 });
  return `${a.id} ${a.state}`;
});

// 4. The WebSocket: connect signed, sync, and print what the owner sends (a message, a checkup command, the approval result).
const seconds = Number(v.listen ?? 60);
await step(`onCommand for ${seconds} s (send a message or a checkup from the app)`, async () => {
  const got = [], errors = [];
  const l = owner.onCommand((item) => {
    got.push(`${item.type}${item.command ? `:${item.command}` : ""}`);
    console.log("item", JSON.stringify(item));
  }, { onError: (e) => errors.push(`${e.code ?? ""} ${e.message}`.trim()), onPaused: () => console.log("paused by the owner") });
  await new Promise((ok) => setTimeout(ok, seconds * 1000));
  const mode = l.mode;
  l.close();
  if (errors.length) throw new Error(errors.join("; "));
  return `mode ${mode}; received ${got.join(", ") || "nothing"}`;
});
await step("owner.status done", () => owner.status({ state: "done", summary: "pair-e2e: finished" }));
report();

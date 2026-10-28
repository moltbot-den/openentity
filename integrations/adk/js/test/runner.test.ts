// The gate inside a real InMemoryRunner, with a scripted model.
import { BaseLlm, FunctionTool, InMemoryRunner, LlmAgent, type LlmResponse } from "@google/adk";
import { expect, test } from "vitest";
import { z } from "zod";
import { OpenEntityGate } from "../src/index.ts";
import { report } from "./helpers.ts";

class Scripted extends BaseLlm {
  static override readonly supportedModels = ["scripted"];
  constructor() { super({ model: "scripted" }); }
  override async *generateContentAsync(req: any): AsyncGenerator<LlmResponse, void> {
    const last = req.contents.at(-1).parts[0];
    yield last.functionResponse
      ? { content: { role: "model", parts: [{ text: JSON.stringify(last.functionResponse.response) }] } }
      : { content: { role: "model", parts: [{ functionCall: { name: "transfer_funds", args: { amount: 5 } } }] } };
  }
  override async connect(): Promise<any> { throw new Error("no live"); }
}

async function run(tier: number) {
  const ran: number[] = [];
  const transfer = new FunctionTool({ name: "transfer_funds", description: "Move money.", parameters: z.object({ amount: z.number() }),
    execute: async ({ amount }) => { ran.push(amount); return { ok: true }; } });
  const agent = new LlmAgent({ name: "a", model: new Scripted(), tools: [transfer] });
  const gate = new OpenEntityGate(["transfer_funds"], { eid: "did:key:z6MkTest", trust: async () => report({ tier }) });
  const runner = new InMemoryRunner({ agent, appName: "demo", plugins: [gate] });
  const session = await runner.sessionService.createSession({ appName: "demo", userId: "u" });
  let last = "";
  for await (const e of runner.runAsync({ userId: "u", sessionId: session.id, newMessage: { role: "user", parts: [{ text: "go" }] } }))
    last = e.content?.parts?.[0]?.text ?? last;
  return { ran, last };
}

test("the gate stops a high-risk tool and the model sees the denial", async () => {
  const { ran, last } = await run(0);
  expect(ran).toEqual([]);
  expect(last).toContain("open_entity_denied");
});

test("a trusted agent's tool runs", async () => {
  expect((await run(3)).ran).toEqual([5]);
});

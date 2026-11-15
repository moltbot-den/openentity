import { expect, test } from "vitest";
import { type Budget, draftMandate, parseBudget, within } from "../src/orgbudget.ts";

const b = (o: Partial<Budget> = {}): Budget => ({ per_tx_max: 5000, period: "P1D", period_max: 20000, step_up_over: 2500, merchants: [], rails: ["credits", "x402"], ...o });

test("within: a narrower budget fits, each limit that exceeds the wider one does not", () => {
  expect(within(b({ per_tx_max: 1000, period_max: 5000, step_up_over: 500, rails: ["credits"] }), b())).toBe(true);
  expect(within(b(), b())).toBe(true);
  for (const over of [{ per_tx_max: 5001 }, { period_max: 20001 }, { step_up_over: 2501 }, { rails: ["credits", "card"] }]) expect(within(b(over), b()), JSON.stringify(over)).toBe(false);
});

test("within compares periods by their per-day rate, in integers", () => {
  const month = b({ period: "P1M", period_max: 600000 }); // $200 a day, like b()
  expect(within(b({ period_max: 20000 }), month)).toBe(true);
  expect(within(b({ period_max: 20001 }), month)).toBe(false);
  expect(within(b({ period: "P7D", period_max: 140000 }), b())).toBe(true);
  expect(within(b({ period: "P7D", period_max: 140001 }), b())).toBe(false);
});

test("within: merchants. An unrestricted wider budget allows any; a restricted one needs a listed subset, never 'any'", () => {
  const shop = b({ merchants: ["did:web:shop.example", "*.moltbotden.com"] });
  expect(within(b({ merchants: ["did:web:shop.example"] }), shop)).toBe(true);
  expect(within(b({ merchants: ["did:web:other.example"] }), shop)).toBe(false);
  expect(within(b({ merchants: [] }), shop)).toBe(false); // empty means any merchant: wider than the list
  expect(within(b({ merchants: ["did:web:x.example"] }), b())).toBe(true);
});

test("parseBudget refuses floats, a period cap below the transaction cap, unknown rails and a step-up over the cap", () => {
  const ok = { per_tx_max: 5000, period: "P1D", period_max: 20000, rails: ["credits"] };
  expect(parseBudget(ok)).toMatchObject({ step_up_over: 2500, merchants: [] });
  for (const bad of [{ per_tx_max: 50.5 }, { period_max: 4999 }, { period: "P2D" }, { rails: [] }, { rails: ["cash"] }, { rails: ["credits", "credits"] }, { step_up_over: 5001 }, { merchants: [""] }, { per_tx_max: 0 }, { per_tx_max: "5000" }]) {
    expect(typeof parseBudget({ ...ok, ...bad }), JSON.stringify(bad)).toBe("string");
  }
});

test("draftMandate spends exactly the budget, with a total that covers every period of the mandate", () => {
  const m = draftMandate(b({ period: "P7D" }), { id: "md_x", issuer: "did:web:o", agent: "did:key:z", t: 100, days: 30, status: "https://s" });
  expect(m.limits).toEqual({ currency: "USD", per_tx_max: 5000, period: "P7D", period_max: 20000, total_max: 20000 * 5 });
  expect(m.expires_at).toBe(100 + 30 * 86_400);
  expect(m.step_up_over).toBe(2500);
});

import { afterEach, expect, it, vi } from "vitest";
import { Registry } from "../src/http";

afterEach(() => vi.unstubAllGlobals());

it("Registry.record follows `next` past the registry's 1000-entry page", async () => {
  const seen: string[] = [];
  vi.stubGlobal("fetch", async (url: string) => {
    seen.push(url.split("?")[1]);
    const after = Number(new URL(url).searchParams.get("after"));
    const entries = Array.from({ length: after === 0 ? 1000 : 5 }, (_, i) => ({ seq: after + i + 1 }));
    return new Response(JSON.stringify({ entries, log_indexes: entries.map((e) => e.seq + 10), next: after === 0 ? 1000 : null }), { headers: { "content-type": "application/json" } });
  });
  const { entries: all, log_indexes } = await new Registry("https://r.test").record("did:key:z");
  expect(all).toHaveLength(1005);
  expect(log_indexes.slice(-2)).toEqual([1014, 1015]);
  expect(all.at(-1)).toEqual({ seq: 1005 });
  expect(seen).toEqual(["after=0", "after=1000"]);
});

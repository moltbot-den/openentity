import { test } from "node:test";
import assert from "node:assert/strict";
import worker from "./index.js";

test("legacy domain keeps the path with a 301", () => {
  const r = worker.fetch(new Request("https://www.openentityidentitystandard.com/spec/1.0?x=1"));
  assert.equal(r.status, 301);
  assert.equal(r.headers.get("location"), "https://openentity.org/spec/1.0?x=1");
});

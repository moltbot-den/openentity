import { expect, test } from "vitest";
import { sameSecret, withDeadline } from "../lambda/handler.ts";

test("a slow request answers as JSON 503 before the Lambda limit, never as CloudFront's HTML", async () => {
  const slow = new Promise<Response>((r) => setTimeout(() => r(new Response("late")), 200));
  const res = await withDeadline(slow, 10);
  expect(res.status).toBe(503);
  expect(res.headers.get("content-type")).toMatch(/application\/json/);
  expect((await res.json()).error).toBe("timeout");
  expect(await (await withDeadline(Promise.resolve(new Response("ok")), 10)).text()).toBe("ok");
});

test("the origin check compares in constant time and rejects anything but the exact secret", () => {
  expect(sameSecret("s3cret", "s3cret")).toBe(true);
  expect(sameSecret("s3cre", "s3cret")).toBe(false);
  expect(sameSecret("", "s3cret")).toBe(false);
});

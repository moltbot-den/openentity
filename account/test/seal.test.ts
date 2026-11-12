import { randomBytes } from "node:crypto";
import { expect, test } from "vitest";
import { dataKey, open, seal } from "../src/seal.ts";

const key = randomBytes(32); // a throwaway key per run

test("a sealed value opens under the same key and purpose", () => {
  expect(open(key, "apple-refresh", seal(key, "apple-refresh", "r.apple-refresh-token"))).toBe("r.apple-refresh-token");
  expect(seal(key, "data", "x")).not.toBe(seal(key, "data", "x")); // fresh IV every time
});

test("purposes are separate: a value sealed for one purpose fails to open as the other, either way", () => {
  expect(() => open(key, "data", seal(key, "apple-refresh", "secret"))).toThrow();
  expect(() => open(key, "apple-refresh", seal(key, "data", "secret"))).toThrow();
});

test("another key, a flipped bit or a truncated value fails", () => {
  const s = seal(key, "data", "secret");
  expect(() => open(randomBytes(32), "data", s)).toThrow();
  const b = Buffer.from(s, "base64url");
  b[14] ^= 1;
  expect(() => open(key, "data", b.toString("base64url"))).toThrow();
  expect(() => open(key, "data", s.slice(0, 20))).toThrow();
});

test("the data key must be exactly 32 bytes", () => {
  expect(dataKey(randomBytes(32).toString("base64url")).length).toBe(32);
  expect(() => dataKey(randomBytes(16).toString("base64url"))).toThrow();
  expect(() => dataKey(undefined)).toThrow();
});

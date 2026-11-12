// Pairing (core lane, PLAN 8.1): /v1/pairings (owner) and /v1/pair (agent), the product fan-out. Its own routes only; registered once in app.ts.
import type { Hono } from "hono";
import type { Deps } from "./app.ts";

export function routes(_app: Hono, _d: Deps) {}

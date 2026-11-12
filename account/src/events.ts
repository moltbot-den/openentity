// Analytics events (core lane, PLAN 13.1): /v1/installs, /v1/events, /v1/events/ingest, to SQS. Its own routes only; registered once in app.ts.
import type { Hono } from "hono";
import type { Deps } from "./app.ts";

export function routes(_app: Hono, _d: Deps) {}

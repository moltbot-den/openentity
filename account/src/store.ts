// Store purchases (web lane): /v1/purchases, /v1/entitlements, App Store and Play notifications, plan.changed. Its own routes only; registered once in app.ts.
import type { Hono } from "hono";
import type { Deps } from "./app.ts";

export function routes(_app: Hono, _d: Deps) {}

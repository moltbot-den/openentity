// Sign-in methods and the account email (web lane): /v1/account/methods, /v1/account/email. Its own routes only; registered once in app.ts.
import type { Hono } from "hono";
import type { Deps } from "./app.ts";

export function routes(_app: Hono, _d: Deps) {}

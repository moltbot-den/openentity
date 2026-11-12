// Web approvals (web lane): the /approve page, /v1/approve/check and /v1/account/links. Its own routes only; registered once in app.ts.
import type { Hono } from "hono";
import type { Deps } from "./app.ts";

export function routes(_app: Hono, _d: Deps) {}

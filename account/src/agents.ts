// Agents (core lane, PLAN 8.2, 8.3): the agent API, owner agent routes, pause, resume, commands, messages. Its own routes only; registered once in app.ts.
import type { Hono } from "hono";
import type { Deps } from "./app.ts";

export function routes(_app: Hono, _d: Deps) {}

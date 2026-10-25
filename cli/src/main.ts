import { parseArgs } from "node:util";
import { adopt, exportCmd, importCmd, self, stats, whoami, withdraw } from "./adopt";
import { anchor } from "./anchor";
import { link, recover } from "./continuity";
import { alias, documentCmd } from "./doc";
import { CliError, EXIT } from "./errors";
import { logCmd, resolveCmd, verifyCmd } from "./log";
import { record } from "./record";
import type { Ctx, Result } from "./store";
import pkg from "../package.json";

const str = { type: "string" } as const;
const bool = { type: "boolean" } as const;
const OPTIONS = {
  json: bool, help: bool, version: bool, "dry-run": bool, agree: bool, write: bool, conflict: bool, "no-push": bool, "with-key": bool, force: bool,
  registry: str, eid: str, name: str, description: str, operator: str, "operator-kind": str, contact: str, custody: str, model: str, provider: str, runtime: str,
  erc8004: str, wallet: str, chain: str, signature: str, entries: str, format: str, dir: str,
  type: str, reason: str, cost: str, context: str, "will-not-ref": str, topic: str, from: str, to: str, evidence: str, id: str, title: str, outcome: str,
  with: str, role: str, ref: str, event: str, link: str, out: str, key: str, previous: str, via: str, proof: str,
} as const;

const COMMANDS: Record<string, (c: Ctx) => Promise<Result>> = {
  adopt, whoami, self, anchor, document: documentCmd, record, alias, verify: verifyCmd, resolve: resolveCmd, log: logCmd, stats,
  export: exportCmd, import: importCmd, rotate: (c) => link(c, "rotation"), migrate: (c) => link(c, "migration"), recover, withdraw,
};

const HELP = `openentity ${pkg.version}: adopt and keep an Open Entity identity (OEIS-1)

Usage: openentity <command> [options]   (also: oe)

  adopt --name <n> --agree [--description --operator --custody --registry --wallet --erc8004 --dry-run]
  whoami | self [--entries n] | stats
  anchor [--format text|openclaw|claude|agents] [--write]
  document set <field> <value> | edit | push
  record stance|update|arc open|arc close|collab|continuity|push
  alias add domain|wallet|erc8004|platform <value>
  verify <file|url|eid> | resolve <did>
  log checkpoint | proof <index> | audit <n>
  export [--with-key] [--out file] | import <file>
  rotate [--to keyfile] | migrate [--to keyfile] | recover --previous <eid> --via <alias>
  withdraw --force

Global: --json  --registry <url>  --eid <eid>   Env: OPENENTITY_HOME, OPENENTITY_REGISTRY, OPENENTITY_NAME, OPENENTITY_OPERATOR
Exit codes: 0 ok, 1 usage, 2 network, 3 verification failed, 4 registry rejected, 5 local state.
Docs: https://openentity.org`;

export interface IO {
  out(s: string): void;
  err(s: string): void;
}
const stdio: IO = { out: (s) => process.stdout.write(s), err: (s) => process.stderr.write(s) };

export async function run(argv: string[], io: IO = stdio): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true });
  } catch (e: any) {
    io.err(`openentity: ${e.message}\n`);
    return EXIT.USAGE;
  }
  const { values: v, positionals } = parsed;
  if (v.version) return io.out(pkg.version + "\n"), EXIT.OK;
  const [cmd, ...args] = positionals;
  if (v.help || !cmd) return io.out(HELP + "\n"), cmd || v.help ? EXIT.OK : EXIT.USAGE;
  const fn = COMMANDS[cmd];
  if (!fn) return io.err(`openentity: unknown command "${cmd}". Try --help.\n`), EXIT.USAGE;
  try {
    const r = await fn({ args, v: { ...v } });
    io.out((v.json ? JSON.stringify(r.json, null, 2) : r.text) + "\n");
    return r.code ?? EXIT.OK;
  } catch (e: any) {
    const code = e instanceof CliError ? e.code : EXIT.STATE;
    io.err(v.json ? JSON.stringify({ error: e.message, code }) + "\n" : `openentity: ${e.message}\n`);
    return code;
  }
}

import { parseArgs } from "node:util";
import { adopt, exportCmd, importCmd, present, self, stats, whoami, withdraw } from "./adopt";
import { anchor } from "./anchor";
import { card } from "./card";
import { link, recover } from "./continuity";
import { alias, documentCmd } from "./doc";
import { CliError, EXIT } from "./errors";
import { conformance } from "./conformance";
import { logCmd, resolveCmd, verifyCmd } from "./log";
import { dispute, find, verifyPresentationCmd } from "./peers";
import { record } from "./record";
import type { Ctx, Result } from "./store";
import pkg from "../package.json";

const str = { type: "string" } as const;
const bool = { type: "boolean" } as const;
const OPTIONS = {
  json: bool, help: bool, version: bool, "dry-run": bool, "extension-only": bool, agree: bool, write: bool, conflict: bool, "no-push": bool, "with-key": bool, force: bool, "no-attestations": bool,
  registry: str, url: str, eid: str, name: str, description: str, operator: str, "operator-kind": str, contact: str, custody: str, model: str, provider: str, runtime: str,
  erc8004: str, wallet: str, chain: str, signature: str, entries: str, format: str, dir: str,
  type: str, reason: str, cost: str, context: str, "will-not-ref": str, topic: str, from: str, to: str, evidence: str, id: str, title: str, outcome: str,
  with: str, role: str, ref: str, event: str, link: str, out: str, key: str, previous: str, via: str, proof: str, audience: str, nonce: str,
  subject: str, object: str, statement: str, capability: str, capabilities: str, "alias-type": str, level: str, q: str,
} as const;

const COMMANDS: Record<string, (c: Ctx) => Promise<Result>> = {
  adopt, whoami, self, anchor, document: documentCmd, record, alias, verify: verifyCmd, resolve: resolveCmd, log: logCmd, stats,
  export: exportCmd, import: importCmd, rotate: (c) => link(c, "rotation"), migrate: (c) => link(c, "migration"), recover, withdraw, present,
  dispute, find, card, "verify-presentation": verifyPresentationCmd, conformance,
};

const HELP = `openentity ${pkg.version}: adopt and keep an Open Entity identity (OEIS-1)

Usage: openentity <command> [options]   (also: oe)

  adopt --name <n> --agree [--description --operator --custody --capabilities a,b --registry --wallet --erc8004 --dry-run]
  whoami | self [--entries n] | stats
  card [--url <agent endpoint>] [--extension-only] [--eid <eid>]   (A2A Agent Card as JSON, or only its Open Entity extension)
  anchor [--format text|openclaw|claude|agents] [--write]
  document set <field> <value> | edit | push
  record stance|update|arc open|arc close|collab|continuity|push | record redact <seq>
  alias add domain|wallet|erc8004|platform <value>
  verify <file|url|eid> | resolve <did>
  present --audience <verifier> --nonce <nonce> [--no-attestations]
  verify-presentation <file> --audience <a> --nonce <n>      (offline; exit 3 on failure)
  dispute --subject <eid> [--object <sha256>] --reason impersonation|illegal_content|inaccurate|other --statement <text>
  find --capability <c> [--q <text> --alias-type <type> --level L1]
  conformance <registry-url>                                 (read-only checks any registry must pass; exit 3 on failure)
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

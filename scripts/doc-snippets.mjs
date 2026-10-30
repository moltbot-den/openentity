// Doc drift guard: runs every sh/bash/js/ts/python code block in the guides, the skill, the SDK and integration READMEs and
// the oeis.dev reference pages against a throwaway local registry, in file order, one fresh HOME per doc.
// A block that cannot run offline carries `<!-- oe:skip reason -->` (MDX: `{/* oe:skip reason */}`) on the line before its fence;
// the reason is required and names the one thing that stops it. A fragment that uses names defined outside the block carries
// `<!-- oe:fixtures -->` instead: it runs with the globals of scripts/doc-snippets-prelude.mjs (ts, js) or scripts/doc_snippets_prelude.py (python).
// Env in blocks: OPENENTITY_REGISTRY and https://openentity.org both point at the local registry. Installs of our packages (npm, pnpm,
// pip, uv, uvx) are satisfied from the workspace by scripts/doc-snippets-shim.mjs; third-party ones only if a lockfile pins them.
// Run: node scripts/doc-snippets.mjs [doc-path-substring]   (needs `pnpm -r build` for cli/dist)
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { homedir, tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const only = process.argv[2];
// Tracked and new files only: generated pages (gitignored) are not hand-written docs.
const files = spawnSync("git", ["ls-files", "--cached", "--others", "--exclude-standard"], { cwd: root, encoding: "utf8" }).stdout.split("\n");
const walk = (d) => files.filter((f) => f.startsWith(`${d}/`) && /\.mdx?$/.test(f));
const docs = [
  ...walk("site/src/content/docs/guides"), "skill/openentity/SKILL.md", "sdk/ts/README.md", "sdk/python/README.md",
  ...readdirSync(join(root, "integrations")).map((i) => `integrations/${i}/README.md`),
  ...walk("site-dev/src/content/docs"),
].filter((d) => existsSync(join(root, d)) && (!only || d.includes(only)));

const LANGS = { sh: "sh", bash: "sh", js: "js", ts: "ts", python: "py" };
const SKIP = /^\s*(?:<!--|\{\/\*)\s*oe:(skip|fixtures)(?:\s+(.*?))?\s*(?:-->|\*\/\})\s*$/;

/** Fenced blocks of a doc: {line, lang, code, skip, fixtures} where skip is the reason, "" for a marker without one, or null. */
function blocks(text) {
  const L = text.split("\n"), out = [];
  for (let i = 0; i < L.length; i++) {
    const m = /^(\s*)```(\w+)\s*$/.exec(L[i]);
    if (!m) continue;
    let j = i + 1;
    while (j < L.length && !L[j].trimStart().startsWith("```")) j++;
    if (LANGS[m[2]]) {
      let p = i - 1;
      while (p >= 0 && !L[p].trim()) p--;
      const s = p >= 0 ? SKIP.exec(L[p]) : null;
      out.push({ line: i + 1, lang: LANGS[m[2]], code: L.slice(i + 1, j).map((l) => l.slice(m[1].length)).join("\n"), skip: s?.[1] === "skip" ? (s[2] ?? "") : null, fixtures: s?.[1] === "fixtures" });
    }
    i = j;
  }
  return out;
}

const freePort = () => new Promise((ok) => { const s = createServer().listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => ok(p)); }); });

const tmp = mkdtempSync(join(tmpdir(), "oe-docs-"));
let reg;
let ran = 0, skipped = 0;
const failures = [];
try {
  // Shims: `openentity`/`oe` and `npx openentity@...` run the repo's built CLI; any other npx is an error (mark the block).
  const bin = join(tmp, "bin");
  mkdirSync(bin);
  const shim = (name, body) => { writeFileSync(join(bin, name), `#!/bin/sh\n${body}\n`); chmodSync(join(bin, name), 0o755); };
  const cli = `node "${root}cli/dist/cli.js"`;
  shim("openentity", `exec ${cli} "$@"`);
  shim("oe", `exec ${cli} "$@"`);
  for (const t of ["npm", "pnpm", "pip", "uv", "uvx"]) shim(t, `OE_DOC_ROOT="${root}" OE_DOC_BIN="${bin}" exec node "${root}scripts/doc-snippets-shim.mjs" ${t} "$@"`);
  shim("npx", `case "$1" in openentity*) shift; exec ${cli} "$@";; *) echo "doc-snippets: npx $1 is not runnable offline; add an oe:skip marker" >&2; exit 1;; esac`);
  // TS and JS blocks import "@openentity/sdk" from a scratch dir that links the workspace package.
  const scratch = join(tmp, "ts");
  mkdirSync(join(scratch, "node_modules/@openentity"), { recursive: true });
  symlinkSync(join(root, "sdk/ts"), join(scratch, "node_modules/@openentity/sdk"));
  writeFileSync(join(scratch, "package.json"), '{"type":"module"}');
  copyFileSync(join(root, "scripts/doc-snippets-prelude.mjs"), join(scratch, "prelude.mjs"));

  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  reg = spawn(join(root, "registry/node_modules/.bin/tsx"), ["scripts/local.ts", String(port)], {
    cwd: join(root, "registry"), env: { ...process.env, WRITE_PER_MINUTE: "100000", IP_DAILY_LIMIT: "1000000" }, stdio: ["ignore", "pipe", "inherit"],
  });
  await new Promise((ok, no) => {
    const t = setTimeout(() => no(new Error("local registry did not start in 60 s")), 60000);
    reg.stdout.on("data", (d) => { if (String(d).includes("local registry on")) { clearTimeout(t); ok(); } });
    reg.on("exit", (c) => no(new Error(`local registry exited ${c}`)));
  });

  for (const doc of docs) {
    const bs = blocks(readFileSync(join(root, doc), "utf8"));
    if (!bs.length) continue;
    const work = join(tmp, "w", doc.replace(/\W/g, "_"));
    mkdirSync(join(work, "home"), { recursive: true });
    if (existsSync(join(homedir(), ".tool-versions"))) symlinkSync(join(homedir(), ".tool-versions"), join(work, "home/.tool-versions")); // asdf shims (python3) need it
    // Docs that say `node cli/dist/cli.js` or `sh scripts/adopt.sh` mean the checkout's paths.
    symlinkSync(join(root, "cli"), join(work, "cli"));
    symlinkSync(join(root, existsSync(join(root, dirname(doc), "scripts")) ? dirname(doc) : ".", "scripts"), join(work, "scripts"));
    const env = { ...process.env, PATH: `${bin}:${process.env.PATH}`, HOME: join(work, "home"), OPENENTITY_HOME: join(work, "oe"), OPENENTITY_REGISTRY: base, NO_COLOR: "1", ISSUED_NONCE: "issued-nonce-0001" };
    const eid = () => { try { return readdirSync(env.OPENENTITY_HOME).find((e) => e.startsWith("did:")) ?? "did:key:unset"; } catch { return "did:key:unset"; } };
    for (const b of bs) {
      const where = `${doc}:${b.line}`;
      if (b.skip === "") { failures.push(`${where}: oe:skip needs a reason`); continue; }
      if (b.skip !== null) { skipped++; continue; }
      // Blocks that need an entity (the placeholders below, `present`, `dispute`) get one adopted first, unless they adopt themselves.
      if (b.lang === "sh" && eid() === "did:key:unset" && !/\badopt\b/.test(b.code) && /<(?:your )?eid>|z6Mk\.\.\.|\bpresent\b|presentation\.json|\bdispute\b/.test(b.code)) {
        const a = spawnSync("openentity", ["adopt", "--name", "Doc Fixture", "--agree"], { cwd: work, env, encoding: "utf8" });
        if (a.status !== 0) { failures.push(`${where}: fixture adopt failed\n${a.stderr}`); continue; }
      }
      if (/presentation\.json/.test(b.code) && b.lang === "sh") spawnSync("sh", ["-c", `openentity present --audience https://platform.example --nonce issued-nonce-0001 > presentation.json`], { cwd: work, env });
      let declHash = "";
      if (b.code.includes("<sha256>")) { // the sha256 of this entity's Declaration, as a dispute names it
        const sdk = await import(join(root, "sdk/ts/dist/index.js"));
        declHash = await sdk.sha256Hex(sdk.canonicalize(await (await fetch(`${base}/v1/entities/${eid()}/declaration`)).json()));
      }
      const code = b.code.replaceAll("https://openentity.org", base).replace(/<(?:your )?eid>/g, eid()).replaceAll("<your name>", "Doc Snippet")
        .replaceAll("https://registry.example", base).replaceAll("did:key:z6Mk...", eid()).replaceAll("<sha256>", declHash)
        .replaceAll("<the verifier's origin or DID>", "https://platform.example").replaceAll("<its nonce>", "issued-nonce-0001").replaceAll("127.0.0.1:8787", `127.0.0.1:${port}`);
      let cmd;
      if (b.lang === "sh") cmd = ["bash", ["-eo", "pipefail", "-c", code]];
      else if (b.lang === "py") {
        const f = join(work, "block.py");
        writeFileSync(f, (b.fixtures ? `import sys; sys.path.insert(0, ${JSON.stringify(join(root, "scripts"))}); import doc_snippets_prelude\n` : "") + code);
        cmd = ["uv", ["run", "--frozen", "--quiet", "--project", join(root, "sdk/python"), "python", f]];
      } else {
        const f = join(scratch, `${basename(work)}_${b.line}.${b.lang === "ts" ? "ts" : "mjs"}`); writeFileSync(f, (b.fixtures ? 'await import("./prelude.mjs");\n' : "") + code);
        cmd = [join(root, "registry/node_modules/.bin/tsx"), [f]];
      }
      ran++;
      const adopted = /\/v1\/adopt|\badopt\(/.test(code) ? "0" : "1";
      const go = () => spawnSync(cmd[0], cmd[1], { cwd: work, env: { ...env, OE_PRELUDE_ADOPT: adopted }, encoding: "utf8", timeout: 60000, maxBuffer: 1 << 24 });
      let r = go();
      // A fresh write reaches the log within a second (the docs say "run it again"): one retry.
      if (r.status !== 0) { await new Promise((ok) => setTimeout(ok, 2500)); r = go(); }
      if (r.status !== 0) failures.push(`${where} [${b.lang}] exit ${r.status ?? r.signal}\n${(r.stderr + r.stdout).trim().split("\n").slice(-8).map((l) => "    " + l).join("\n")}`);
    }
  }
} finally {
  reg?.kill();
  rmSync(tmp, { recursive: true, force: true });
}
console.log(`doc-snippets: ${ran} blocks ran, ${skipped} skipped (oe:skip), ${failures.length} failed`);
if (failures.length) { console.error(failures.join("\n")); process.exit(1); }

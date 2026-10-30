// Package-manager shim for scripts/doc-snippets.mjs. Doc blocks say `npm install @openentity/sdk` or `pip install openentity`;
// offline, a package of ours is satisfied from the workspace (npm: symlinked into ./node_modules; pip: its pyproject must exist,
// and any [extra] must be declared there). A third-party package is allowed only if a lockfile already pins it. Anything else fails loud.
// Usage (from the PATH shims): node doc-snippets-shim.mjs npm|pnpm|pip|uv|uvx <args...>   (env OE_DOC_ROOT = repo root)
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, symlinkSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

const root = process.env.OE_DOC_ROOT;
const [tool, ...args] = process.argv.slice(2);
const die = (m) => { console.error(`doc-snippets: ${tool} ${args.join(" ")}: ${m}; add an oe:skip marker with the reason`); process.exit(1); };
const files = spawnSync("git", ["ls-files"], { cwd: root, encoding: "utf8" }).stdout.split("\n");
const read = (f) => readFileSync(join(root, f), "utf8");
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const js = {}, py = {};
for (const f of files.filter((f) => /(^|\/)package\.json$/.test(f))) { const n = JSON.parse(read(f)).name; if (n) js[n] = dirname(f); }
for (const f of files.filter((f) => /(^|\/)pyproject\.toml$/.test(f))) { const n = /^name\s*=\s*"([^"]+)"/m.exec(read(f))?.[1]; if (n) py[n.toLowerCase().replace(/_/g, "-")] = dirname(f); }

const flags = args.filter((a) => a.startsWith("-"));
const pos = args.filter((a) => !a.startsWith("-"));

// Everything that is not an install goes to the real tool (`uv run ...`, `pnpm test`), found on the PATH without this shim directory.
const real = (t) => {
  const path = process.env.PATH.split(":").filter((d) => d !== process.env.OE_DOC_BIN).join(":");
  const r = spawnSync(t, args, { stdio: "inherit", env: { ...process.env, PATH: path } });
  process.exit(r.status ?? 1);
};
if (tool === "uv" && !["pip", "add"].includes(pos[0])) real("uv");

if (tool === "uvx") {
  if (!py[args[0]]) die(`${args[0]} is not a workspace Python package`);
  // The workspace package's own command line, run from its project.
  const r = spawnSync("uv", ["run", "--frozen", "--quiet", "--project", join(root, py[args[0]]), ...args], { stdio: "inherit" });
  process.exit(r.status ?? 1);
}

if (tool === "npm" || tool === "pnpm") {
  const [sub, ...rest] = pos;
  if (tool === "pnpm" && flags.includes("--filter") && rest.at(-1) === "build" && js[pos[0]]) process.exit(0); // the workspace is already built by verify.sh
  if (!["install", "i", "add"].includes(sub) || !rest.length) die("only `install <packages>` is supported");
  const lock = read("pnpm-lock.yaml");
  for (const spec of rest) {
    const name = /^(@?[^@]+)/.exec(spec)[1];
    if (js[name]) {
      const dest = join(process.cwd(), "node_modules", name);
      mkdirSync(dirname(dest), { recursive: true });
      if (!existsSync(dest)) symlinkSync(join(root, js[name]), dest);
    } else if (/^@?openentity/.test(name)) die(`${name} is not a workspace package`);
    else if (!new RegExp(`^\\s+'?${esc(name)}[@:'\\s]`, "m").test(lock)) die(`${name} is not in pnpm-lock.yaml`);
  }
  process.exit(0);
}

// pip install, uv pip install, uv add
const [a, b] = pos;
const specs = tool === "uv" ? (a === "pip" && b === "install" ? pos.slice(2) : a === "add" ? pos.slice(1) : die("only `uv pip install` and `uv add` are supported")) : (a === "install" ? pos.slice(1) : die("only `pip install` is supported"));
if (!specs.length) die("no packages");
const locks = files.filter((f) => /uv\.lock$/.test(f)).map(read).join("\n");
for (const spec of specs) {
  if (/^\.{0,2}\//.test(spec) || spec === ".") { // a path into the checkout
    const dir = resolve(root, spec); // docs mean the checkout's root
    if (!existsSync(join(dir, "pyproject.toml"))) die(`${spec} has no pyproject.toml`);
    continue;
  }
  const m = /^([A-Za-z0-9_.-]+)(?:\[([^\]]+)\])?/.exec(spec);
  const name = m[1].toLowerCase().replace(/_/g, "-");
  if (py[name]) {
    const toml = read(join(py[name], "pyproject.toml"));
    for (const x of (m[2] ?? "").split(",").filter(Boolean)) if (!new RegExp(`^${esc(x)}\\s*=`, "m").test(toml.split("[project.optional-dependencies]")[1] ?? "")) die(`${name} has no extra [${x}]`);
  } else if (/^(langchain-)?openentity/.test(name)) die(`${name} is not a workspace package`);
  else if (!locks.includes(`name = "${name}"`)) die(`${name} is not in a uv.lock`);
}

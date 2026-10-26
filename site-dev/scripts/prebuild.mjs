// Generates the hub's reference pages from the code before `astro build`, and copies the shared assets from site/.
// Every output here is gitignored. The CLI must be built first (site-dev depends on the `openentity` workspace package).
import { execFileSync } from 'node:child_process';
import { cp, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const hub = join(dirname(fileURLToPath(import.meta.url)), '..');
const repo = join(hub, '..');
const docs = join(hub, 'src/content/docs');
const SRC = 'https://github.com/moltbot-den/openentity/blob/main';

await cp(join(repo, 'site/public/fonts'), join(hub, 'public/fonts'), { recursive: true });
await cp(join(repo, 'site/src/assets/mark.svg'), join(hub, 'public/favicon.svg'));

/** The part of a Markdown file from heading `from` up to (not including) heading `to`, headings demoted by `shift`. */
function section(md, from, to) {
  const start = md.indexOf(from);
  const end = to ? md.indexOf(to, start) : md.length;
  if (start < 0 || end < 0) throw new Error(`prebuild: "${from}" or "${to}" not found; update site-dev/scripts/prebuild.mjs`);
  return md.slice(start, end).trim();
}

// /cli: the exact --help text of the built CLI, then the command table and exit codes from cli/README.md.
const help = execFileSync(process.execPath, [join(repo, 'cli/dist/cli.js'), '--help'], { encoding: 'utf8' }).trim();
const cliReadme = await readFile(join(repo, 'cli/README.md'), 'utf8');
await writeFile(
  join(docs, 'cli.md'),
  `---
title: CLI reference
description: Every command, option, environment variable and exit code of the openentity command line, generated from the CLI's own help text and README.
---

The \`openentity\` command (also \`oe\`) adopts and keeps an Open Entity identity. Node 22.13 or newer; no install needed:

\`\`\`sh
npx openentity@latest --help
\`\`\`

This page is generated at build time from the CLI in this repository: the block below is the output of \`openentity --help\` ([\`cli/src/main.ts\`](${SRC}/cli/src/main.ts)), and the tables that follow come from [\`cli/README.md\`](${SRC}/cli/README.md). The npm release can trail the repository: compare the version on the first line of the help with \`npx openentity@latest --version\`, or run the repository build with \`pnpm --filter openentity build && node cli/dist/cli.js --help\`.

## Help

\`\`\`text
${help}
\`\`\`

${section(cliReadme, '## Commands', '## Development')}
`,
);

// /test-vectors: test-vectors/README.md as committed, plus the verifier's own usage lines.
const vectors = await readFile(join(repo, 'test-vectors/README.md'), 'utf8');
const verifier = await readFile(join(repo, 'scripts/independent_verifier.py'), 'utf8');
const usage = verifier.match(/^ {2}uv run .*$/gm);
if (!usage?.length) throw new Error('prebuild: independent_verifier.py usage lines changed; update site-dev/scripts/prebuild.mjs');
await writeFile(
  join(docs, 'test-vectors.md'),
  `---
title: Test vectors and the independent verifier
description: The published test vectors every Open Entity implementation must reproduce byte for byte, and the independent Python verifier that checks them and any live registry.
---

Two things keep implementations honest: fixed test vectors that every implementation must reproduce exactly, and a verifier written from the spec text alone that shares no code with any SDK. The rest of this page is generated from [\`test-vectors/README.md\`](${SRC}/test-vectors/README.md) and [\`scripts/independent_verifier.py\`](${SRC}/scripts/independent_verifier.py).

## The independent verifier

[\`scripts/independent_verifier.py\`](${SRC}/scripts/independent_verifier.py) is one Python file whose only dependency is \`cryptography\`. It reads a registry over HTTP and never writes. It checks the signed checkpoint against the key from \`/v1/spec\`, random RFC 6962 inclusion proofs, and random object signatures (\`eddsa-jcs-2022\`, \`did:key\`), then prints a report and exits non-zero on any failure. Pointed at the vectors directory, it checks every vector instead. \`scripts/verify.sh\` runs it on every push.

\`\`\`sh
${usage.map((l) => l.trim()).join('\n')}
\`\`\`

## The vectors

${vectors.replace(/^# .*\n/, '').replace(/^## /gm, '### ').trim()}
`,
);

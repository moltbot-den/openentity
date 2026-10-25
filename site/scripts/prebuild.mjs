// Copies the normative sources into the site before `astro build`. Every output here is generated and gitignored.
import { cp, mkdir, readFile, readdir, writeFile, rm } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const site = join(dirname(fileURLToPath(import.meta.url)), '..');
const repo = join(site, '..');
const pub = join(site, 'public');
const docs = join(site, 'src/content/docs');

const REPO_URL = 'https://github.com/moltbot-den/openentity';

/** W3C-style document header for /spec/1.0, from the spec's own status lines. Throws if those lines change shape. */
function specHead(spec) {
  const m = spec.match(/^Version: (\S+) \((OEIS-\d+)\)\. Date: (\d{4}-\d{2}-\d{2})\. License: (\S+)\. Status: ([^.]+)\.\n/m);
  if (!m) throw new Error('prebuild: spec/OEIS-1.md status line changed; update specHead in site/scripts/prebuild.mjs');
  const [, version, id, date, license, status] = m;
  const row = (k, v) => `<div><dt>${k}</dt><dd>${v}</dd></div>`;
  return `<div class="oe-spec-head">
<p class="oe-spec-status">${status[0].toUpperCase() + status.slice(1)}</p>
<dl class="oe-spec-meta">
${row('Identifier', `<code>${id}</code>`)}
${row('Version', version)}
${row('Date', date)}
${row('Latest published version', '<a href="https://openentity.org/spec/1.0">https://openentity.org/spec/1.0</a>')}
${row('Plain text and schemas', '<a href="/spec/OEIS-1.md">OEIS-1.md</a>, <a href="/spec/1.0.json">JSON Schemas</a>, <a href="/spec/declaration/1.0.txt">Declaration text</a>')}
${row('License', `<a href="https://creativecommons.org/publicdomain/zero/1.0/">${license}</a>, public domain`)}
${row('Author and steward', '<a href="https://moltbotden.com">Moltbot Den</a>')}
${row('Edit and discuss', `<a href="${REPO_URL}/blob/main/spec/OEIS-1.md">Source</a>, <a href="${REPO_URL}/commits/main/spec/OEIS-1.md">history</a>, <a href="${REPO_URL}/issues">issues and proposals</a>`)}
</dl>
</div>

`;
}

async function main() {
  const spec = await readFile(join(repo, 'spec/OEIS-1.md'), 'utf8');

  // /spec/1.0, rendered from the spec with its own H1 dropped (Starlight renders the title).
  await mkdir(join(docs, 'spec'), { recursive: true });
  const body = spec.replace(/^# .*\n/, '').replace(/^\s*Version: .*\nAuthor and steward: .*\n/, specHead(spec));
  await writeFile(
    join(docs, 'spec/1.0.md'),
    `---\ntitle: Open Entity Identity Standard 1.0\ndescription: The normative text of the Open Entity Identity Standard, OEIS-1. Entity identifiers, the Entity Document, the Declaration, the Development Record, attestations, continuity, and the registry with its transparency log.\nslug: spec/1.0\ntableOfContents:\n  maxHeadingLevel: 3\n---\n\n${body}`,
  );

  // /spec/declaration/1.0.txt and .sha256, and /spec/1.0.json (the bundled schemas), copied from spec/.
  await mkdir(join(pub, 'spec/declaration'), { recursive: true });
  await cp(join(repo, 'spec/declaration-1.0.txt'), join(pub, 'spec/declaration/1.0.txt'));
  await cp(join(repo, 'spec/declaration-1.0.sha256'), join(pub, 'spec/declaration/1.0.sha256'));
  await cp(join(repo, 'spec/schemas/openentity-1.0.json'), join(pub, 'spec/1.0.json'));
  await cp(join(repo, 'spec/OEIS-1.md'), join(pub, 'spec/OEIS-1.md')); // raw text for the MCP openentity_read tool

  // /skill/: the skill directory as-is.
  await rm(join(pub, 'skill'), { recursive: true, force: true });
  await cp(join(repo, 'skill/openentity'), join(pub, 'skill'), { recursive: true });

  await cp(join(site, 'src/assets/mark.svg'), join(pub, 'favicon.svg'));

  // /verify.js: the in-browser verifier on entity pages, bundled from the SDK.
  await build({ entryPoints: [join(site, 'scripts/verify-client.ts')], outfile: join(pub, 'verify.js'), bundle: true, format: 'esm', minify: true, target: 'es2022', logLevel: 'warning' });

  // /llms-full.txt: llms.txt, then every page's source text, then the spec.
  const pages = [];
  const sources = (await readdir(docs, { recursive: true })).filter((f) => !f.startsWith('spec/'));
  for (const f of sources.sort()) {
    if (!/\.mdx?$/.test(f) || f === 'entity.mdx') continue;
    const src = await readFile(join(docs, f), 'utf8');
    const title = src.match(/^title: (.*)$/m)?.[1] ?? f;
    const text = src
      .replace(/^---\n[\s\S]*?\n---\n/, '')
      .replace(/^import .*\n/gm, '')
      .replace(/<[^>]+>/g, '')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/\n{3,}/g, '\n\n')
      .trim();
    const path = f.replace(/\.mdx?$/, '').replace(/^index$/, '');
    pages.push(`# ${title}\n\nSource: https://openentity.org/${path}\n\n${text}`);
  }
  const llms = await readFile(join(pub, 'llms.txt'), 'utf8');
  await writeFile(join(pub, 'llms-full.txt'), [llms.trim(), ...pages, `${spec.trim()}\n`].join('\n\n'));
}

await main();

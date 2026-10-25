// Copies the normative sources into the site before `astro build`. Every output here is generated and gitignored.
import { cp, mkdir, readFile, readdir, writeFile, rm } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const site = join(dirname(fileURLToPath(import.meta.url)), '..');
const repo = join(site, '..');
const pub = join(site, 'public');
const docs = join(site, 'src/content/docs');

async function main() {
  const spec = await readFile(join(repo, 'spec/OEIS-1.md'), 'utf8');

  // /spec/1.0, rendered from the spec with its own H1 dropped (Starlight renders the title).
  await mkdir(join(docs, 'spec'), { recursive: true });
  const body = spec.replace(/^# .*\n/, '');
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

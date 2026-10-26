// Build hooks shared by openentity.org (site/) and the developer hub at oeis.dev (site-dev/).
import { createHash } from 'node:crypto';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * /sitemap.xml (robots.txt points here): every built page under `origin` except the 404 and the entity template.
 * Named '@astrojs/sitemap' so Starlight does not add its own sitemap, which would list the entity template.
 */
export const sitemap = (origin) => ({
  name: '@astrojs/sitemap',
  hooks: {
    'astro:build:done': async ({ pages, dir }) => {
      const urls = pages
        .map((p) => p.pathname.replace(/\/$/, ''))
        .filter((p) => p !== '404' && p !== 'entity')
        .sort()
        .map((p) => `  <url><loc>${origin}/${p}</loc></url>`);
      const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.join('\n')}\n</urlset>\n`;
      await writeFile(new URL('sitemap.xml', dir), xml);
    },
  },
});

// Every executable script ships as a file so the Content-Security-Policy can say script-src 'self' with no
// 'unsafe-inline'. Starlight's is:inline scripts (theme bootstrap, sidebar state) move to /_astro/inline-<hash>.js;
// a classic <script src> still runs in place, so the theme is set before first paint as before.
export const externalScripts = {
  name: 'openentity-external-scripts',
  hooks: {
    'astro:build:done': async ({ dir }) => {
      const root = fileURLToPath(dir);
      const scripts = new Map();
      for (const file of await readdir(root, { recursive: true })) {
        if (!file.endsWith('.html')) continue;
        const path = join(root, file);
        const html = await readFile(path, 'utf8');
        const out = html.replace(/<script\b([^>]*)>([\s\S]*?)<\/script>/g, (tag, attrs, body) => {
          if (/\bsrc=|application\/(ld\+)?json/.test(attrs) || !body.trim()) return tag;
          const name = `inline-${createHash('sha256').update(body).digest('hex').slice(0, 16)}.js`;
          scripts.set(name, body);
          return `<script${attrs} src="/_astro/${name}"></script>`;
        });
        if (out !== html) await writeFile(path, out);
      }
      for (const [name, body] of scripts) await writeFile(join(root, '_astro', name), body);
    },
  },
};

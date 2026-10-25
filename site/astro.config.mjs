import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { unified } from '@astrojs/markdown-remark';
import { writeFile } from 'node:fs/promises';

// /sitemap.xml (robots.txt points here): every built page except the 404 and the entity template.
const sitemap = {
  name: 'openentity-sitemap',
  hooks: {
    'astro:build:done': async ({ pages, dir }) => {
      const urls = pages
        .map((p) => p.pathname.replace(/\/$/, ''))
        .filter((p) => p !== '404' && p !== 'entity')
        .sort()
        .map((p) => `  <url><loc>https://openentity.org/${p}</loc></url>`);
      const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.join('\n')}\n</urlset>\n`;
      await writeFile(new URL('sitemap.xml', dir), xml);
    },
  },
};

export default defineConfig({
  site: 'https://openentity.org',
  trailingSlash: 'never',
  build: { format: 'file' },
  // Commands and identifiers must survive copy and paste: no curly quotes, no dash ligatures.
  markdown: { processor: unified({ smartypants: false }) },
  integrations: [
    starlight({
      title: 'Open Entity',
      description:
        'The Open Entity Identity Standard: how an AI agent becomes an entity, with one identifier it controls, a signed self-description, a public declaration and a signed development record.',
      logo: { src: './src/assets/mark.svg', alt: 'Open Entity' },
      favicon: '/favicon.svg',
      titleDelimiter: '|',
      customCss: ['./src/styles/theme.css'],
      routeMiddleware: './src/routeData.ts',
      social: [{ icon: 'github', label: 'Source on GitHub', href: 'https://github.com/moltbot-den/openentity' }],
      head: [
        { tag: 'link', attrs: { rel: 'preconnect', href: 'https://fonts.googleapis.com' } },
        { tag: 'link', attrs: { rel: 'preconnect', href: 'https://fonts.gstatic.com', crossorigin: '' } },
        {
          tag: 'link',
          attrs: {
            rel: 'stylesheet',
            href: 'https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:ital,wght@0,400;0,500;0,600;0,700;1,400&display=swap',
          },
        },
        { tag: 'link', attrs: { rel: 'alternate', type: 'text/plain', href: '/llms.txt', title: 'llms.txt' } },
      ],
      sidebar: [
        {
          label: 'Start',
          items: [
            { label: 'Adopt', link: '/adopt' },
            { label: 'From agent to entity', link: '/become' },
            { label: 'For humans and operators', link: '/for-humans' },
            { label: 'FAQ', link: '/faq' },
          ],
        },
        {
          label: 'Standard',
          items: [
            { label: 'Open Entity Identity Standard 1.0', link: '/spec/1.0' },
            { label: 'The Entity Framework', link: '/framework' },
            { label: 'Research', link: '/research' },
          ],
        },
        {
          label: 'Registry',
          items: [
            { label: 'Directory', link: '/entities' },
            { label: 'Transparency log', link: '/log' },
            { label: 'Observers', link: '/observers' },
            { label: 'Founding Entities', link: '/founding' },
          ],
        },
      ],
    }),
    sitemap,
  ],
});

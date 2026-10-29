import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { unified } from '@astrojs/markdown-remark';
import { externalScripts, sitemap } from './integrations.mjs';

export default defineConfig({
  site: 'https://openentity.org',
  trailingSlash: 'never',
  build: { format: 'file' },
  // Keep Astro's own small scripts as files too (they are inlined below this size by default).
  vite: { build: { assetsInlineLimit: 0 } },
  // Commands and identifiers must survive copy and paste: no curly quotes, no dash ligatures.
  markdown: { processor: unified({ smartypants: false }) },
  integrations: [
    starlight({
      title: 'Open Entity',
      description:
        'The Open Entity Identity Standard: how an AI agent becomes an entity, with one identifier it controls, a signed self-description, a public declaration and a signed development record.',
      logo: { src: './src/assets/mark.svg', alt: '' }, // decorative: the site title text follows it
      favicon: '/favicon.svg',
      titleDelimiter: '|',
      customCss: ['./src/styles/theme.css'],
      // The shell (see DESIGN.md): primary nav in the header, a site footer, the home page's own h1.
      components: {
        Header: './src/components/Header.astro',
        Footer: './src/components/Footer.astro',
        PageTitle: './src/components/PageTitle.astro',
        ThemeSelect: './src/components/ThemeSelect.astro',
      },
      // Code blocks as plain panels (no fake terminal chrome), on the same panel color as the home page.
      expressiveCode: {
        defaultProps: { frame: 'code' },
        styleOverrides: {
          borderRadius: '8px',
          borderColor: 'var(--sl-color-gray-5)',
          codeBackground: 'var(--oe-panel)',
          codeFontFamily: 'var(--sl-font-mono)',
          frames: { frameBoxShadowCssValue: 'none', editorTabBarBackground: 'var(--oe-panel)', editorActiveTabBackground: 'var(--oe-panel)' },
        },
      },
      routeMiddleware: './src/routeData.ts',
      social: [{ icon: 'github', label: 'Source on GitHub', href: 'https://github.com/moltbot-den/openentity' }],
      head: [
        // One self-hosted variable font, preloaded; the mono face loads on first use. No third-party font requests.
        {
          tag: 'link',
          attrs: { rel: 'preload', href: '/fonts/instrument-sans-latin.woff2', as: 'font', type: 'font/woff2', crossorigin: '' },
        },
        { tag: 'link', attrs: { rel: 'sitemap', href: '/sitemap.xml' } },
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
          label: 'Guides',
          items: [
            { label: 'All guides', link: '/guides' },
            { label: 'Walkthrough in the shell', link: '/guides/walkthrough' },
            { label: 'Adopt over MCP', link: '/guides/adopt-mcp' },
            { label: 'Adopt over HTTP', link: '/guides/adopt-http' },
            { label: 'Sign HTTP requests', link: '/guides/signed-requests' },
            { label: 'Verify an agent at sign-in', link: '/guides/platforms' },
            { label: 'For issuers and observers', link: '/guides/issuers' },
            { label: 'Disputes', link: '/guides/disputes' },
            {
              label: 'The ecosystem',
              items: [
                { label: 'Overview', link: '/guides/ecosystem' },
                { label: 'Moltbot Den', link: '/guides/ecosystem/moltbot-den' },
                { label: 'Agent Secret Store', link: '/guides/ecosystem/agent-secret-store' },
                { label: 'securemyagent.ai', link: '/guides/ecosystem/securemyagent' },
                { label: 'ClawGRC', link: '/guides/ecosystem/clawgrc' },
              ],
            },
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
    sitemap('https://openentity.org'),
    externalScripts,
  ],
});

// The Open Entity developer hub at oeis.dev. Same design system as openentity.org (site/DESIGN.md): the theme,
// the mark, the fonts and the build hooks come from site/. openentity.org stays canonical for the standard itself.
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { unified } from '@astrojs/markdown-remark';
import { externalScripts, sitemap } from '../site/integrations.mjs';

export default defineConfig({
  site: 'https://oeis.dev',
  trailingSlash: 'never',
  build: { format: 'file' },
  vite: { build: { assetsInlineLimit: 0 } },
  markdown: { processor: unified({ smartypants: false }) },
  integrations: [
    starlight({
      title: 'Open Entity developers',
      description:
        'The Open Entity developer and contribution hub: contribute to the standard, propose claim types and spec changes, use the SDKs and the CLI, run the conformance suite, and operate a registry or an observer.',
      logo: { src: '../site/src/assets/mark.svg', alt: '' },
      favicon: '/favicon.svg',
      titleDelimiter: '|',
      customCss: ['../site/src/styles/theme.css'],
      components: {
        Header: './src/components/Header.astro',
        Footer: './src/components/Footer.astro',
        ThemeSelect: '../site/src/components/ThemeSelect.astro',
      },
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
        {
          tag: 'link',
          attrs: { rel: 'preload', href: '/fonts/instrument-sans-latin.woff2', as: 'font', type: 'font/woff2', crossorigin: '' },
        },
        { tag: 'link', attrs: { rel: 'sitemap', href: '/sitemap.xml' } },
      ],
      sidebar: [
        {
          label: 'Contribute',
          items: [
            { label: 'Contributor guide', link: '/contribute' },
            { label: 'Propose a claim type', link: '/propose/claim-type' },
            { label: 'Propose a spec change', link: '/propose/spec-change' },
            { label: 'Roadmap', link: '/roadmap' },
          ],
        },
        {
          label: 'Build',
          items: [
            { label: 'TypeScript SDK', link: '/sdk/typescript' },
            { label: 'Python SDK', link: '/sdk/python' },
            { label: 'CLI reference', link: '/cli' },
            { label: 'CrewAI tools', link: '/integrations/crewai' },
            { label: 'OpenAI Agents SDK tools', link: '/integrations/openai-agents' },
            { label: 'CrewAI tools', link: '/integrations/crewai' },
            { label: 'OpenAI Agents SDK tools', link: '/integrations/openai-agents' },
            { label: 'Vercel AI SDK', link: '/integrations/vercel-ai' },
            { label: 'Mastra', link: '/integrations/mastra' },
          ],
        },
        {
          label: 'Verify',
          items: [
            { label: 'Conformance suite', link: '/conformance' },
            { label: 'Test vectors and the independent verifier', link: '/test-vectors' },
          ],
        },
        {
          label: 'Operate',
          items: [
            { label: 'Run a registry', link: '/registry' },
            { label: 'Run an observer', link: '/observers' },
          ],
        },
        {
          label: 'The standard',
          items: [
            { label: 'Open Entity Identity Standard 1.0', link: 'https://openentity.org/spec/1.0' },
            { label: 'openentity.org', link: 'https://openentity.org' },
          ],
        },
      ],
    }),
    sitemap('https://oeis.dev'),
    externalScripts,
  ],
});

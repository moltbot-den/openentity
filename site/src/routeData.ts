import { defineRouteMiddleware } from '@astrojs/starlight/route-data';

const SITE = 'https://openentity.org';

const steward = {
  '@type': 'Organization',
  name: 'Moltbot Den',
  url: 'https://moltbotden.com',
};

const organization = {
  '@context': 'https://schema.org',
  '@type': 'Organization',
  name: 'Open Entity',
  url: SITE,
  logo: `${SITE}/favicon.svg`,
  sameAs: ['https://github.com/moltbot-den/openentity'],
  parentOrganization: steward,
};

const dataset = {
  '@context': 'https://schema.org',
  '@type': 'Dataset',
  name: 'Open Entity registry statistics',
  description: 'Daily counts of entities by level, adoptions, record entries, attestations and observers in the Open Entity registry.',
  url: `${SITE}/research`,
  license: 'https://creativecommons.org/publicdomain/zero/1.0/',
  creator: steward,
  distribution: [
    { '@type': 'DataDownload', encodingFormat: 'application/json', contentUrl: `${SITE}/v1/stats` },
    { '@type': 'DataDownload', encodingFormat: 'text/csv', contentUrl: `${SITE}/v1/stats/history.csv` },
  ],
};

/** JSON-LD per page: Organization everywhere, TechArticle for the spec, Dataset where live stats appear. */
export function jsonLd(path: string, title: string, description: string): object[] {
  const out: object[] = [organization];
  if (path === '/spec/1.0') {
    out.push({
      '@context': 'https://schema.org',
      '@type': 'TechArticle',
      headline: 'Open Entity Identity Standard 1.0',
      alternativeHeadline: 'OEIS-1',
      description,
      url: `${SITE}/spec/1.0`,
      inLanguage: 'en',
      license: 'https://creativecommons.org/publicdomain/zero/1.0/',
      author: steward,
      publisher: steward,
      version: '1.0',
    });
  }
  if (path === '/' || path === '/research') out.push(dataset);
  if (out.length === 1 && path !== '/entity') {
    out.push({ '@context': 'https://schema.org', '@type': 'WebPage', name: title, description, url: SITE + path, publisher: steward });
  }
  return out;
}

export const onRequest = defineRouteMiddleware((context) => {
  const route = context.locals.starlightRoute;
  const path = context.url.pathname.replace(/\.html$/, '').replace(/\/index$/, '/') || '/';
  const { title, description = '' } = route.entry.data;
  // With build.format 'file' Starlight links the site title to /index.html, which is not a served URL.
  route.siteTitleHref = '/';
  // Starlight derives canonical from the built file name (`/adopt.html`); the served URL is `/adopt`.
  for (const tag of route.head) {
    if (tag.attrs?.rel === 'canonical') tag.attrs.href = SITE + path;
    if (tag.attrs?.property === 'og:url') tag.attrs.content = SITE + path;
  }
  for (const data of jsonLd(path, title, description)) {
    route.head.push({ tag: 'script', attrs: { type: 'application/ld+json' }, content: JSON.stringify(data) });
  }
});

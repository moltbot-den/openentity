import { defineRouteMiddleware } from '@astrojs/starlight/route-data';

const HUB = 'https://oeis.dev';
const steward = { '@type': 'Organization', name: 'Moltbot Den', url: 'https://moltbotden.com' };

export const onRequest = defineRouteMiddleware((context) => {
  const route = context.locals.starlightRoute;
  const path = context.url.pathname.replace(/\.html$/, '').replace(/\/index$/, '/') || '/';
  const { title, description = '' } = route.entry.data;
  // With build.format 'file' Starlight links the site title to /index.html and derives canonical from the file name.
  route.siteTitleHref = '/';
  for (const tag of route.head) {
    if (tag.attrs?.rel === 'canonical') tag.attrs.href = HUB + path;
    if (tag.attrs?.property === 'og:url') tag.attrs.content = HUB + path;
  }
  const page = { '@context': 'https://schema.org', '@type': 'TechArticle', headline: title, description, url: HUB + path, publisher: steward, isPartOf: { '@type': 'WebSite', name: 'Open Entity', url: 'https://openentity.org' } };
  route.head.push({ tag: 'script', attrs: { type: 'application/ld+json' }, content: JSON.stringify(page) });
});

// /pair, the page the OpenEntity app's QR code opens (https://openentity.org/pair#OE-XXXX-XXXX). Runs on the built site.
// Every command carries the code placeholder, and the shipped script fills in only a well-formed code from the URL fragment, as text.
// No DOM library: the script touches location, the placeholders and one listener, so a stand-in for those is enough.
import { afterEach, describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const dist = join(import.meta.dirname, '..', 'dist');
const html = readFileSync(join(dist, 'pair.html'), 'utf8');
const PLACEHOLDER = 'OE-XXXX-XXXX';
const script = [...html.matchAll(/<script\b[^>]*\ssrc="(\/_astro\/[^"]+\.js)"/g)]
  .map((m) => readFileSync(join(dist, m[1]), 'utf8'))
  .find((s) => s.includes('[data-pair-code]'));
if (!script) throw new Error('/pair ships no script that fills [data-pair-code]');

/** Run the shipped script as a browser would on a page whose URL fragment is `hash`. */
function load(hash: string) {
  const els = [{ textContent: PLACEHOLDER }, { textContent: PLACEHOLDER }];
  const listeners: Record<string, () => void> = {};
  const g = globalThis as any;
  g.location = { hash };
  g.document = { querySelectorAll: (s: string) => (s === '[data-pair-code]' ? els : []) };
  g.addEventListener = (type: string, fn: () => void) => (listeners[type] = fn);
  new Function(script!)();
  return {
    texts: () => els.map((e) => e.textContent),
    navigate(h: string) {
      g.location.hash = h;
      listeners.hashchange?.();
    },
  };
}

afterEach(() => {
  for (const k of ['location', 'document', 'addEventListener']) delete (globalThis as any)[k];
});

describe('/pair', () => {
  it('puts the code of every command in a placeholder the script fills', () => {
    const pres = [...html.matchAll(/<pre\b[\s\S]*?<\/pre>/g)].map((m) => m[0]).filter((p) => p.includes(PLACEHOLDER));
    expect(pres.length).toBeGreaterThan(0);
    for (const p of pres) expect(p.split(PLACEHOLDER).length - 1, p).toBe(p.match(/<span data-pair-code(="")?>OE-XXXX-XXXX<\/span>/g)?.length);
  });

  it('fills a well-formed code from the fragment, upper-cased, into every placeholder', () => {
    expect(load('#oe-7k4m-q2xp').texts()).toEqual(['OE-7K4M-Q2XP', 'OE-7K4M-Q2XP']);
  });

  it('keeps OE-XXXX-XXXX for anything else', () => {
    const bad = ['', '#', '#OE-7K4M-Q2X', '#OE-7K4M-Q2XPA', '#XOE-7K4M-Q2XP', '#OE-7K4M-Q2XP\n', '#OE-IL0U-Q2XP', '#OE-7K4M%2DQ2XP', '#<img src=x onerror=alert(1)>', '#OE-7K4M-Q2XP<b>x</b>'];
    for (const hash of bad) expect(load(hash).texts(), hash).toEqual([PLACEHOLDER, PLACEHOLDER]);
  });

  it('takes a new code from a later fragment, and keeps it when the reader jumps to a section', () => {
    const page = load('#OE-7K4M-Q2XP');
    page.navigate('#OE-AAAA-BBBB');
    expect(page.texts()).toEqual(['OE-AAAA-BBBB', 'OE-AAAA-BBBB']);
    page.navigate('#claude-code');
    expect(page.texts()).toEqual(['OE-AAAA-BBBB', 'OE-AAAA-BBBB']);
  });

  it('writes text only, never markup', () => {
    expect(script).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write/);
  });
});

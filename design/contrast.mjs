// WCAG 2.1 contrast of every color pair the app uses. Exits 1 if any pair is under AA (4.5:1).
import { readFileSync } from 'node:fs';
const t = JSON.parse(readFileSync(new URL('./tokens.json', import.meta.url)));
const lum = (h) => { const c = [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16) / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4)); return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]; };
export const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
export function pairs() {
  const out = [];
  for (const mode of ['light', 'dark']) {
    const c = t.color[mode];
    const p = (fg, bg, fgv = c[fg], bgv = c[bg]) => out.push({ mode, fg, bg, fgv, bgv, r: ratio(fgv, bgv) });
    for (const f of ['text', 'textSecondary', 'textMuted', 'accent', 'danger', 'warn']) { p(f, 'bg'); p(f, 'panel'); }
    p('text', 'accentLow'); p('accent', 'accentLow'); p('onAccent', 'accent'); p('onDanger', 'danger');
    for (const [k, v] of Object.entries(c.product)) { p(`product.${k}`, 'bg', v); p(`product.${k}`, 'panel', v, c.panel); }
  }
  return out;
}
if (import.meta.url === `file://${process.argv[1]}`) {
  const all = pairs();
  console.log('| Mode | Foreground | Background | Ratio | AA |\n|---|---|---|---|---|');
  for (const x of all) console.log(`| ${x.mode} | ${x.fg} ${x.fgv} | ${x.bg} ${x.bgv} | ${x.r.toFixed(2)} | ${x.r >= 4.5 ? 'pass' : 'FAIL'} |`);
  const bad = all.filter((x) => x.r < 4.5);
  if (bad.length) { console.error(`contrast: ${bad.length} pair(s) under 4.5:1`); process.exit(1); }
}

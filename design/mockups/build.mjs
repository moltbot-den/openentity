// Renders the eight screens as HTML from tokens.json, then screenshots them with headless Chrome.
// node design/mockups/build.mjs [outDir]   (default: docs/mobile/design next to the openentity repo)
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const here = new URL('.', import.meta.url).pathname;
const t = JSON.parse(readFileSync(here + '../tokens.json'));
const out = process.argv[2] || join(here, '../../../docs/mobile/design');
const CHROME = process.env.CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const DEV = { ios: { w: 402, h: 874, dpr: 3 }, android: { w: 412, h: 915, dpr: 2.625 } };

const vars = (m) => Object.entries(t.color[m]).flatMap(([k, v]) => (k === 'product' ? Object.entries(v).map(([p, c]) => `--p-${p}:${c}`) : [`--${k}:${v}`])).join(';');
const px = (k) => { const s = t.type[k]; return `font:${s.weight} ${s.size}px/${s.line}px var(${s.mono ? '--mono' : '--sans'})`; };
const css = `
:root{${Object.entries(t.space).map(([k, v]) => `--s-${k}:${v}px`).join(';')};${Object.entries(t.radius).map(([k, v]) => `--r-${k}:${v}px`).join(';')}}
.light{${vars('light')}} .dark{${vars('dark')}}
.ios{--sans:-apple-system,"SF Pro Text",system-ui,sans-serif;--mono:ui-monospace,"SF Mono",Menlo,monospace}
.android{--sans:Roboto,"Google Sans",system-ui,sans-serif;--mono:"Roboto Mono",ui-monospace,Menlo,monospace}
*{box-sizing:border-box;margin:0;padding:0} html,body{overflow:hidden;margin:0}
body{background:var(--bg);color:var(--text);font-family:var(--sans);-webkit-font-smoothing:antialiased}
.dev{position:relative;background:var(--bg);overflow:hidden;display:flex;flex-direction:column}
.status{height:54px;flex:none;display:flex;align-items:flex-end;justify-content:space-between;padding:0 28px 8px;font:600 16px var(--sans)}
.android .status{height:40px;padding:0 24px 6px;font-weight:500;font-size:14px}
.status .r{display:flex;gap:6px;align-items:center}
.scr{flex:1;min-height:0;display:flex;flex-direction:column;padding:0 var(--s-lg);overflow:hidden}
.mono{font-family:var(--mono)} .muted{color:var(--textMuted)} .sec{color:var(--textSecondary)}
.h1{${px('largeTitle')};letter-spacing:-.4px} .h2{${px('title2')}} .h3{${px('headline')}} .body{${px('body')}} .call{${px('callout')}} .sub{${px('subheadline')}} .foot{${px('footnote')}} .cap{${px('caption')}}
.m{${px('mono')}} .ms{${px('monoSmall')}} .code{${px('code')};letter-spacing:2px}
.eyebrow{${px('caption')};letter-spacing:.8px;text-transform:uppercase;color:var(--textMuted)}
.panel{background:var(--panel);border:1px solid var(--hairline);border-radius:var(--r-md)}
.card{padding:var(--s-lg)}
.row{display:flex;align-items:center;gap:var(--s-md)} .sp{flex:1} .col{display:flex;flex-direction:column}
.btn{height:52px;border-radius:14px;display:flex;align-items:center;justify-content:center;gap:10px;${px('headline')};border:1.5px solid var(--hairline);background:transparent;color:var(--text);flex:1;position:relative;overflow:hidden}
.android .btn{border-radius:26px;height:48px}
.btn.pri{background:var(--accent);border-color:var(--accent);color:var(--onAccent)}
.btn.ink{background:var(--text);border-color:var(--text);color:var(--bg)}
.btn.dng{border-color:var(--danger);color:var(--danger)}
.btn.line{border-color:var(--accent);color:var(--accent)}
.link{${px('callout')};color:var(--accent);text-align:center;padding:12px;font-weight:600}
.chip{display:inline-flex;align-items:center;gap:6px;height:24px;padding:0 10px;border-radius:12px;${px('caption')};background:var(--accentLow);color:var(--accent)}
.chip.o{background:transparent;border:1px solid var(--hairline);color:var(--textSecondary)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--ok);flex:none}
.hr{height:1px;background:var(--hairline);flex:none}
.tabs{flex:none;display:flex;border-top:1px solid var(--hairline);background:var(--bg);padding:8px 4px 30px}
.android .tabs{background:var(--panel);border:0;padding:12px 4px 22px}
.tab{flex:1;display:flex;flex-direction:column;align-items:center;gap:3px;${px('caption')};font-size:11px;color:var(--textMuted)}
.tab.on{color:var(--accent)} .tab svg{width:26px;height:26px}
.android .tab.on svg{background:var(--accentLow);border-radius:16px;width:56px;padding:3px 15px;height:30px;box-sizing:border-box}
.android .tab svg{width:56px;height:30px;padding:3px 15px}
.mark{width:28px;height:28px;border-radius:8px;display:flex;align-items:center;justify-content:center;color:var(--bg);font:700 14px var(--sans);flex:none}
.kv{display:grid;grid-template-columns:84px 1fr;gap:10px 12px;padding:2px 0} .kv>:nth-child(odd){color:var(--textMuted);${px('subheadline')}} .kv>:nth-child(even){${px('subheadline')}}
.item{display:flex;align-items:center;gap:12px;padding:14px 0;border-bottom:1px solid var(--hairline)} .item:last-child{border:0}
.chev{width:8px;height:14px;flex:none;color:var(--textMuted)}
.grab{width:36px;height:5px;border-radius:3px;background:var(--hairline);margin:8px auto 12px;flex:none}
.sw{width:51px;height:31px;border-radius:16px;background:var(--hairline);position:relative;flex:none}
.sw::after{content:"";position:absolute;left:2px;top:2px;width:27px;height:27px;border-radius:50%;background:#fff}
.hold::before{content:"";position:absolute;left:0;top:0;bottom:0;width:62%;background:color-mix(in srgb,var(--onAccent) 22%,transparent)}
.bar{height:6px;border-radius:3px;background:var(--hairline);overflow:hidden} .bar i{display:block;height:100%;background:var(--p-keys)}
`;

const I = {
  seal: (s = 32) => `<svg width="${s}" height="${s}" viewBox="0 0 32 32" role="img" aria-label="Open Entity"><rect width="32" height="32" rx="7" fill="var(--accent)"/><circle cx="16" cy="16" r="8.5" fill="none" stroke="var(--onAccent)" stroke-width="3"/><circle cx="16" cy="16" r="2.75" fill="var(--onAccent)"/></svg>`,
  chev: `<svg class="chev" viewBox="0 0 8 14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M1 1l6 6-6 6"/></svg>`,
  check: (c = 'var(--accent)') => `<svg width="26" height="26" viewBox="0 0 26 26"><circle cx="13" cy="13" r="13" fill="${c}"/><path d="M7.5 13.5l4 4 7-8" stroke="var(--onAccent)" stroke-width="2.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
  ring: (pct, label, size = 44) => { const r = 18, c = 2 * Math.PI * r; return `<svg width="${size}" height="${size}" viewBox="0 0 44 44"><circle cx="22" cy="22" r="${r}" fill="none" stroke="var(--hairline)" stroke-width="4"/><circle cx="22" cy="22" r="${r}" fill="none" stroke="var(--accent)" stroke-width="4" stroke-linecap="round" stroke-dasharray="${c}" stroke-dashoffset="${c * (1 - pct)}" transform="rotate(-90 22 22)"/><text x="22" y="26" text-anchor="middle" font-size="11" font-weight="600" fill="var(--text)" font-family="var(--mono)">${label}</text></svg>`; },
  apple: `<svg width="18" height="20" viewBox="0 0 18 20" fill="currentColor"><path d="M14.6 10.6c0-2.3 1.9-3.4 2-3.5-1.100-1.600-2.800-1.800-3.400-1.800-1.400-.1-2.800.9-3.500.9s-1.900-.8-3.100-.8C4.100 5.400 2.600 6.300 1.800 7.700c-1.700 2.900-.4 7.200 1.200 9.500.8 1.100 1.700 2.400 2.900 2.400 1.200 0 1.600-.8 3-.8s1.800.8 3 .7c1.300 0 2.100-1.100 2.800-2.300.9-1.300 1.200-2.600 1.300-2.600-.1 0-2.400-.9-2.400-3.600zM12.400 3.800c.6-.8 1.100-1.800.9-2.800-.9 0-2 .6-2.700 1.400-.6.700-1.100 1.700-.9 2.700 1 .1 2-.5 2.700-1.300z"/></svg>`,
  g: `<svg width="18" height="18" viewBox="0 0 18 18"><path fill="#4285F4" d="M17.600 9.200c0-.6-.1-1.200-.2-1.700H9v3.300h4.800a4.100 4.100 0 0 1-1.800 2.700v2.200h2.900c1.700-1.600 2.700-3.900 2.700-6.500z"/><path fill="#34A853" d="M9 18c2.400 0 4.500-.8 5.900-2.200L12 13.600c-.8.500-1.800.9-3 .9-2.300 0-4.300-1.600-5-3.700H1v2.300A9 9 0 0 0 9 18z"/><path fill="#FBBC05" d="M4 10.800a5.400 5.400 0 0 1 0-3.500V5H1a9 9 0 0 0 0 8.100z"/><path fill="#EA4335" d="M9 3.600c1.300 0 2.500.5 3.400 1.300l2.600-2.600A9 9 0 0 0 1 5l3 2.300c.7-2.100 2.700-3.700 5-3.700z"/></svg>`,
  key: `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="5" cy="11" r="3"/><path d="M7.200 8.800L14 2m-3 3l2 2"/></svg>`,
};
const tabIcons = {
  Inbox: '<path d="M3 13l3-8h14l3 8v7H3z M3 13h6a4 4 0 0 0 8 0h6"/>',
  Entities: '<circle cx="13" cy="13" r="8"/><circle cx="13" cy="13" r="2.500" fill="currentColor"/>',
  Den: '<path d="M4 6h18v11H11l-5 4v-4H4z"/>',
  Trust: '<path d="M13 3l8 3v6c0 5-3.500 8-8 10-4.500-2-8-5-8-10V6z"/><path d="M9 13l3 3 5-6"/>',
  Wallet: '<rect x="3" y="6" width="20" height="14" rx="3"/><path d="M3 11h20"/><circle cx="18" cy="15.500" r="1.200" fill="currentColor"/>',
};
const tabbar = (on) => `<nav class="tabs" aria-label="Tabs">${Object.entries(tabIcons).map(([n, d]) => `<div class="tab ${n === on ? 'on' : ''}"><svg viewBox="0 0 26 26" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${d}</svg>${n}</div>`).join('')}</nav>`;
const status = (plat) => `<div class="status"><span>9:41</span><span class="r"><svg width="18" height="12" viewBox="0 0 18 12" fill="currentColor"><rect x="0" y="8" width="3" height="4" rx="1"/><rect x="5" y="5" width="3" height="7" rx="1"/><rect x="10" y="2" width="3" height="10" rx="1"/><rect x="15" y="0" width="3" height="12" rx="1"/></svg><svg width="26" height="12" viewBox="0 0 26 12"><rect x=".5" y=".5" width="22" height="11" rx="3.500" fill="none" stroke="currentColor" opacity=".5"/><rect x="2" y="2" width="16" height="8" rx="2" fill="currentColor"/></svg></span></div>`;
const avatar = `<div class="mark" style="width:36px;height:36px;border-radius:50%;background:var(--accent);color:var(--onAccent)">W</div>`;
const mk = (p, l) => `<div class="mark" style="background:var(--p-${p})" aria-hidden="true">${l}</div>`;
const pc = (p) => `color:var(--p-${p})`;

const S = {};
S.signin = () => ({ body: `<div class="scr" style="padding-top:72px">${I.seal(64)}
<h1 class="h1" style="margin-top:28px">Your agents,<br>verified.</h1>
<p class="body sec" style="margin-top:12px;max-width:310px">Approve what your agents ask for, with your face, from anywhere.</p>
<div class="sp"></div>
<div class="col" style="gap:12px">
<div class="row"><button class="btn ink">${I.apple} Sign in with Apple</button></div>
<div class="row"><button class="btn">${I.g} Continue with Google</button></div>
<div class="row"><button class="btn line">Use a passkey</button></div>
<div class="link">Email me a code</div></div>
<div class="row foot muted" style="justify-content:center;gap:24px;padding:8px 0 40px"><span>Terms</span><span>Privacy</span></div></div>` });

S.faceid = () => ({ body: `<div class="scr" style="padding-top:28px">
<div class="eyebrow">Step 2 of 3</div>
<h1 class="h1" style="margin-top:6px">Turn on Face ID approvals</h1>
<div class="panel" style="margin-top:24px;padding:4px 16px">
<div class="item">${I.check()}<div class="col"><span class="h3">Create your passkey</span><span class="foot muted">Done. Saved to iCloud Keychain.</span></div></div>
<div class="item"><svg width="26" height="26" viewBox="0 0 26 26"><circle cx="13" cy="13" r="12" fill="none" stroke="var(--accent)" stroke-width="2"/><circle cx="13" cy="13" r="4" fill="var(--accent)"/></svg><div class="col"><span class="h3">Make this iPhone your approver</span><span class="foot muted">Face ID will confirm each approval.</span></div></div></div>
<div class="panel card" style="margin-top:20px;border-left:4px solid var(--warn)"><div class="h3" style="color:var(--warn)">There is no reset</div>
<p class="call sec" style="margin-top:6px">If you lose this passkey and every approver, nobody can restore approvals, including us. Add a backup next.</p></div>
<div class="sp"></div><div class="row" style="padding-bottom:40px"><button class="btn pri">Next</button></div></div>` });

const appr = (p, l, who, what, left, pct) => `<div class="panel card"><div class="row">${mk(p, l)}<div class="col sp"><span class="h3">${who}</span><span class="foot" style="${pc(p)};font-weight:600">${p === 'keys' ? 'Keys' : 'Safety'}</span></div>${I.ring(pct, left)}</div>
<p class="call" style="margin:10px 0 14px">wants <span class="m">${what}</span></p>
<div class="row"><button class="btn dng">Deny</button><button class="btn pri">Approve</button></div></div>`;
S.inbox = () => ({ tab: 'Inbox', body: `<div class="scr"><div class="row" style="padding:12px 0 8px"><h1 class="h1 sp">Inbox</h1>${avatar}</div>
<div class="eyebrow" style="margin:12px 0 8px">Needs you (2)</div>
<div class="col" style="gap:12px">${appr('keys', 'K', 'refund-bot', 'stripe/live/refund', '4:51', .78)}${appr('safety', 'S', 'ledger-bot', 'to publish a skill', '2:10', .36)}</div>
<div class="eyebrow" style="margin:22px 0 4px">Today</div>
<div class="item"><span class="dot"></span><span class="call sp"><b>refund-bot</b> finished, 7 of 7</span><span class="foot muted">9:12</span></div>
<div class="item"><span class="dot" style="background:var(--warn)"></span><span class="call sp"><b>ledger-bot</b> checkup: 1 warning</span><span class="foot muted">8:40</span></div></div>` });

S.sheet = () => ({ body: `<div class="scr"><div class="grab"></div>
<div class="row" style="margin-top:4px">${mk('keys', 'K')}<span class="h3" style="${pc('keys')}">Agent Secret Store</span><div class="sp"></div>${I.ring(.78, '4:51', 52)}</div>
<h1 class="h2" style="margin:14px 0 16px;font-size:26px;line-height:32px">refund-bot wants a key</h1>
<div class="panel card"><div class="kv"><span>Secret</span><span class="m">stripe/live/refund</span><span>Use</span><span>1 call, 10 min</span><span>Why</span><span>"refund #4821 $40"</span><span>Agent</span><span>L2 Observed <span class="chip" style="margin-left:6px"><span class="dot"></span>Safe</span></span><span>Verifier</span><span class="m">agentsecretstore</span><span>Expires</span><span class="m">4:51</span></div></div>
<div class="panel card" style="margin-top:12px;text-align:center"><div class="foot muted">Code shown on the agent</div><div class="code" style="margin-top:2px">42</div></div>
<p class="foot muted" style="margin-top:12px">Match this code before you approve.</p>
<div class="sp"></div><div class="row" style="padding-bottom:40px"><button class="btn dng" style="flex:.8">Deny</button><button class="btn pri hold" style="flex:1.4">Hold to approve</button></div></div>` });

S.entity = () => ({ tab: 'Entities', body: `<div class="scr"><div class="row" style="padding:10px 0"><span class="call" style="color:var(--accent)">&lsaquo; Entities</span><div class="sp"></div><span class="foot muted">Pause</span><div class="sw" role="switch" aria-checked="false"></div></div>
<div class="row" style="margin-top:6px">${I.seal(44)}<div class="col"><h1 class="h2">refund-bot</h1><div class="row" style="gap:6px;margin-top:2px"><span class="chip">L2 Observed</span><span class="chip o">first-party</span></div></div></div>
<div class="row" style="margin-top:14px"><span class="m sec">did:key:z6Mk&hellip;9xQ</span><span class="chip o" style="margin-left:auto">Copy</span></div>
<div class="row" style="margin:10px 0 6px"><span class="dot"></span><span class="call">Running <span class="muted">"batch 3 of 7"</span></span></div>
<div class="panel" style="padding:0 16px;margin-top:8px">
<div class="item"><span class="h3 sp" style="color:var(--accent)">Identity</span><span class="call muted">4 attestations</span>${I.chev}</div>
<div class="item"><span class="h3 sp" style="color:var(--p-den)">Messages</span><span class="call muted">2 new</span>${I.chev}</div>
<div class="item"><span class="h3" style="${pc('safety')}">Safety</span><svg width="64" height="22" viewBox="0 0 64 22" aria-label="Score trend"><path d="M2 17 10 14 18 15 26 10 34 11 42 7 50 8 62 3" fill="none" stroke="var(--p-safety)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg><span class="sp"></span><span class="call"><b>92</b> <span class="muted">no alerts</span></span>${I.chev}</div>
<div class="item"><span class="h3 sp" style="${pc('keys')}">Keys</span><span class="call muted">3 secrets, 1 token</span>${I.chev}</div>
<div class="item"><span class="h3 sp" style="${pc('governance')}">Governance</span><span class="call muted">OWASP 81%</span>${I.chev}</div>
<div class="item"><span class="h3 sp" style="${pc('den')}">Work</span><span class="call muted">2 contracts</span>${I.chev}</div></div></div>` });

const qr = () => { let s = 7 * 7 * 3, r = ''; const rnd = () => (s = (s * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff; const n = 25, c = 6;
  const f = (x, y) => [[0, 0], [n - 7, 0], [0, n - 7]].some(([a, b]) => x >= a && x < a + 7 && y >= b && y < b + 7);
  for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) { if (f(x, y)) continue; if (rnd() > .52) r += `<rect x="${x * c}" y="${y * c}" width="${c}" height="${c}"/>`; }
  for (const [a, b] of [[0, 0], [n - 7, 0], [0, n - 7]]) r += `<rect x="${a * c}" y="${b * c}" width="${7 * c}" height="${7 * c}"/><rect x="${(a + 1) * c}" y="${(b + 1) * c}" width="${5 * c}" height="${5 * c}" fill="#fff"/><rect x="${(a + 2) * c}" y="${(b + 2) * c}" width="${3 * c}" height="${3 * c}"/>`;
  return `<svg width="176" height="176" viewBox="0 0 ${n * c} ${n * c}" role="img" aria-label="Pairing QR code" style="background:#fff;padding:10px;border-radius:12px;box-sizing:content-box" fill="#111716">${r}</svg>`; };
const shapes = ['<circle cx="12" cy="12" r="9"/>', '<path d="M12 3l10 18H2z"/>', '<rect x="3" y="3" width="18" height="18" rx="2"/>', '<path d="M12 2l10 10-10 10L2 12z"/>'];
S.pair = () => ({ body: `<div class="scr"><div class="grab"></div><h1 class="h1" style="font-size:30px">Pair an agent</h1>
<div class="row" style="margin-top:16px;align-items:center;gap:16px">${qr()}<div class="col" style="gap:4px"><span class="foot muted">Or type</span><span class="m" style="font-weight:600;font-size:17px">OE-7KQ2-M9XD</span><span class="row foot" style="gap:6px;margin-top:8px">${I.ring(.95, '9:42', 40)}</span></div></div>
<div class="eyebrow" style="margin:20px 0 8px">Tell your agent</div>
<div class="col" style="gap:8px">
<div class="panel" style="padding:10px 12px"><div class="cap muted">OpenClaw</div><div class="ms">npx openentity pair OE-7KQ2-M9XD</div></div>
<div class="panel" style="padding:10px 12px"><div class="cap muted">Claude</div><div class="ms">claude mcp add openentity https://mcp.openentity.org</div></div>
<div class="panel" style="padding:10px 12px"><div class="cap muted">Python</div><div class="ms">uvx openentity pair OE-7KQ2-M9XD</div></div></div>
<div class="sp"></div>
<div class="panel card" style="margin-bottom:36px"><div class="foot muted">Match on the agent</div>
<div class="row" style="justify-content:space-between;margin-top:6px">${shapes.map((d, i) => `<svg width="44" height="44" viewBox="0 0 24 24" fill="var(--${['accent', 'p-safety', 'p-keys', 'p-governance'][i]})" role="img" aria-label="${['circle', 'triangle', 'square', 'diamond'][i]}">${d}</svg>`).join('')}</div></div></div>` });

const sec = (n, v, a) => `<div class="item"><span class="m sp">${n}</span><span class="ms muted">${v}</span><span class="foot muted" style="width:28px;text-align:right">${a}</span></div>`;
S.vault = () => ({ tab: 'Trust', body: `<div class="scr"><div class="row" style="padding:12px 0 2px"><h1 class="h1 sp">Trust</h1>${avatar}</div>
<div class="row" style="margin:6px 0 14px;gap:0"><div class="chip o" style="border-radius:8px 0 0 8px">Safety</div><div class="chip" style="border-radius:0;background:var(--accentLow)">Keys</div><div class="chip o" style="border-radius:0 8px 8px 0">Governance</div></div>
<div class="row"><span class="h2" style="${pc('keys')}">Keys</span><span class="foot muted">by Agent Secret Store</span></div>
<p class="call sec" style="margin:2px 0 8px">12 secrets, 4 tokens live</p>
<div class="panel" style="padding:0 16px">${sec('stripe/live/refund', 'v3', '2h')}${sec('openai/prod', 'v1', '1d')}${sec('github/deploy', 'v2', '3d')}
<div class="item"><span class="call sp">Tokens: refund-bot, 1 call</span><span class="chip o">Revoke</span></div></div>
<div class="row" style="margin:14px 0 4px"><button class="btn line" style="height:46px">Add secret</button></div>
<p class="foot muted" style="text-align:center">Write-only. The app never shows a value back.</p>
<div class="panel" style="padding:0 16px;margin-top:12px"><div class="item"><span class="call sp">Audit trail</span>${I.chev}</div>
<div class="item col" style="align-items:stretch;gap:8px"><div class="row"><span class="call sp">Gateway spend</span><span class="call"><b>$3.12</b> <span class="muted">/ $20</span></span>${I.chev}</div><div class="bar" role="progressbar" aria-valuenow="16" aria-valuemin="0" aria-valuemax="100"><i style="width:16%"></i></div></div></div></div>` });

const plan = (n, d, price, cta, on) => `<div class="panel card" ${on ? 'style="border-color:var(--accent);border-width:2px"' : ''}><div class="row"><div class="col sp"><span class="h3">${n}</span><span class="foot muted">${d}</span></div>${price ? `<span class="h3">${price}</span>` : ''}</div>${cta ? `<div class="row" style="margin-top:12px"><button class="btn ${on ? 'pri' : 'line'}" style="height:44px">${cta}</button></div>` : '<div class="chip" style="margin-top:10px">Current plan</div>'}</div>`;
S.plans = () => ({ tab: 'Trust', body: `<div class="scr"><div class="row" style="padding:12px 0 6px"><span class="call" style="color:var(--accent)">&lsaquo; Keys</span></div>
<div class="row"><span class="h2" style="${pc('keys')}">Plans</span><span class="foot muted">Keys by Agent Secret Store</span></div>
<div class="col" style="gap:12px;margin-top:14px">${plan('Free', '25 secrets, 3 agents', '', '', false)}${plan('Solo', '100 secrets, 10 agents', '$9/mo', 'Choose', true)}${plan('Team', 'Unlimited, shared approvers', '$99/mo', 'Choose', false)}</div>
<div class="link" style="margin-top:8px">US only: Pay on the web</div><div class="link" style="padding-top:0">Restore purchases</div>
<div class="sp"></div><p class="foot muted" style="text-align:center;padding:0 12px 14px">Approve and deny always work on any plan.</p></div>` });

const page = (name, plat, mode) => { const s = S[name](); return `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>${name}</title><style>${css}</style><body class="${plat} ${mode}"><div class="dev ${plat} ${mode}" style="width:${DEV[plat].w}px;height:${DEV[plat].h}px">${status(plat)}${s.body}${s.tab ? tabbar(s.tab) : ''}</div>`; };

const tmp = mkdtempSync(join(tmpdir(), 'oe-mock-'));
const jobs = [];
for (const name of Object.keys(S)) for (const plat of ['ios', 'android']) for (const mode of ['light', 'dark']) jobs.push([name, plat, mode]);
// Headless Chrome will not make a window narrower than 500px, so shoot at 500 and crop to the device width.
const shoot = ([name, plat, mode]) => new Promise((res, rej) => {
  const f = join(tmp, `${name}-${plat}-${mode}.html`); writeFileSync(f, page(name, plat, mode));
  const { w, h, dpr } = DEV[plat]; const png = join(out, `mockup-${name}-${plat}-${mode}.png`);
  execFile(CHROME, ['--headless=new', '--disable-gpu', '--hide-scrollbars', `--force-device-scale-factor=${dpr}`, `--window-size=500,${h}`, `--screenshot=${png}`, 'file://' + f], (e) => {
    if (e) return rej(e);
    execFile('magick', [png, '-crop', `${Math.round(w * dpr)}x${Math.round(h * dpr)}+0+0`, '+repage', png], (e2) => (e2 ? rej(e2) : res()));
  });
});
try { mkdirSync(out, { recursive: true }); for (let i = 0; i < jobs.length; i += 6) await Promise.all(jobs.slice(i, i + 6).map(shoot)); } finally { rmSync(tmp, { recursive: true, force: true }); }

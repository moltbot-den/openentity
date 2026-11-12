// The pages on account.openentity.org: server-rendered HTML, one inline style and one inline script per page, both
// allowed by their SHA-256 in the page's own Content-Security-Policy (the origin's header wins over CloudFront's).
// Client code is a plain TypeScript function serialized with toString, so tsc checks it against the DOM types; it
// must use only its own locals and browser globals.
import { createHash } from "node:crypto";

export const esc = (s: unknown) => String(s ?? "").replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);
const hash = (s: string) => `'sha256-${createHash("sha256").update(s, "utf8").digest("base64")}'`;

// Colors from design/tokens.json (light and dark).
export const CSS = `
:root{--bg:#fff;--panel:#f6f8f7;--line:#d3d9d6;--text:#111716;--text2:#3e4644;--muted:#5c6562;--accent:#0a6b4c;--accent-low:#e3f2eb;--on-accent:#fff;--danger:#b3261e;--on-danger:#fff;--warn:#a1430f}
@media (prefers-color-scheme:dark){:root{--bg:#0e1312;--panel:#151b19;--line:#303a36;--text:#e9eeec;--text2:#aeb7b3;--muted:#8a938f;--accent:#5ccb9f;--accent-low:#12291f;--on-accent:#0e1312;--danger:#ff8a80;--on-danger:#0e1312;--warn:#f0a36b}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:520px;margin:0 auto;padding:32px 16px 64px}
header{display:flex;align-items:center;gap:8px;margin-bottom:24px;color:var(--text2);font-weight:600}
h1{font-size:24px;line-height:1.25;margin:0 0 8px}
h2{font-size:17px;margin:28px 0 8px}
p{margin:0 0 12px;color:var(--text2)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;margin:16px 0}
dl{margin:0;display:grid;grid-template-columns:minmax(96px,auto) 1fr;gap:6px 12px}
dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;overflow-wrap:anywhere}
button,.button{display:block;width:100%;min-height:48px;margin:8px 0;padding:12px 16px;border-radius:10px;border:1px solid var(--line);background:var(--bg);color:var(--text);font:inherit;font-weight:600;cursor:pointer;text-align:center;text-decoration:none}
button.primary{background:var(--accent);border-color:var(--accent);color:var(--on-accent)}
button.danger{background:var(--danger);border-color:var(--danger);color:var(--on-danger)}
button:disabled{opacity:.5;cursor:default}
input{display:block;width:100%;min-height:48px;margin:8px 0;padding:12px;border-radius:10px;border:1px solid var(--line);background:var(--bg);color:var(--text);font:inherit}
ul.list{list-style:none;padding:0;margin:0}ul.list li{display:flex;justify-content:space-between;gap:12px;padding:10px 0;border-bottom:1px solid var(--line)}
ul.list li button{width:auto;min-height:36px;margin:0;padding:6px 12px}
.error{color:var(--danger)}.note{color:var(--muted);font-size:14px}.warn{color:var(--warn)}
.code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:32px;letter-spacing:6px;text-align:center;margin:12px 0}
[hidden]{display:none!important}
`;
const CSS_HASH = hash(CSS);

export interface PageOptions {
  title: string;
  /** Static markup; every dynamic value in it must already be escaped. */
  body: string;
  /** The page's client code: a self-contained function, run once with the parsed config. */
  client?: (config: any) => unknown;
  /** Passed to `client` through a non-executable JSON block. */
  config?: unknown;
  /** Extra CSP sources per directive, such as a third-party script or the origins a form may post to. */
  csp?: Partial<Record<"script-src" | "style-src" | "connect-src" | "frame-src" | "img-src" | "form-action", string[]>>;
}

/** An HTML response: no caching, framing forbidden, scripts and styles allowed only by hash. */
export function page(o: PageOptions): Response {
  const script = o.client ? `(${o.client.toString()})(JSON.parse(document.getElementById("cfg").textContent));` : "";
  const src = (d: keyof NonNullable<PageOptions["csp"]>, base: string[]) => [...base, ...(o.csp?.[d] ?? [])].join(" ") || "'none'";
  const csp = [
    "default-src 'none'",
    `script-src ${src("script-src", script ? [hash(script)] : [])}`,
    `style-src ${src("style-src", [CSS_HASH])}`,
    `img-src ${src("img-src", ["'self'", "data:"])}`,
    `connect-src ${src("connect-src", ["'self'"])}`,
    `frame-src ${src("frame-src", [])}`,
    `form-action ${src("form-action", ["'self'"])}`,
    "frame-ancestors 'none'",
    "base-uri 'none'",
  ].join("; ");
  // "</" never appears inside the JSON block, so data cannot end it early.
  const cfg = JSON.stringify(o.config ?? null).replace(/</g, "\\u003c");
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>${esc(o.title)}</title><style>${CSS}</style></head>
<body><main><header>OpenEntity</header>${o.body}</main>
<script type="application/json" id="cfg">${cfg}</script>${script ? `<script>${script}</script>` : ""}</body></html>`;
  return new Response(html, {
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "content-security-policy": csp, "referrer-policy": "no-referrer" },
  });
}

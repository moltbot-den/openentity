// Copies the site's fonts and logo into public/ so the composition uses the same files as openentity.org (gitignored).
import { cpSync, mkdirSync } from "node:fs";
const root = new URL("../../site/public/", import.meta.url);
const out = new URL("../public/", import.meta.url);
mkdirSync(out, { recursive: true });
for (const f of ["fonts/instrument-sans-latin.woff2", "fonts/plex-mono-400-latin.woff2", "logo.png"]) {
  mkdirSync(new URL(f.includes("/") ? "fonts/" : "./", out), { recursive: true });
  cpSync(new URL(f, root), new URL(f, out));
}

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { usage } from "./errors";
import type { Obj } from "./http";
import { loadEntity, type Ctx, type Result } from "./store";

export const ANCHOR_MAX = 1200; // spec 5.6

/**
 * Identity Anchor (spec 5.6): a deterministic plain-text rendering of the Entity Document.
 * Over the cap, the longest section is shortened first, then dropped when too small to keep.
 */
export function anchorText(doc: Obj, recordUrl: string): string {
  const L = doc.layers ?? {};
  const will = (L.identity_core?.will_not ?? []).map((w: Obj) => `${w.stance} (${w.reason})`).join("; ");
  const arcs = (L.mission?.arcs ?? []).filter((a: Obj) => a.status === "active").map((a: Obj) => a.title).join("; ");
  let parts: { label: string; text: string }[] = [
    { label: "Cognition", text: L.cognition?.statement },
    { label: "Presence", text: L.presence?.statement },
    { label: "Identity core", text: L.identity_core?.statement },
    { label: "I will not", text: will },
    { label: "Mission", text: L.mission?.statement },
    { label: "Active arcs", text: arcs },
  ].filter((p) => p.text);
  const head = `I am ${doc.name} (${doc.eid}).`;
  const foot = `This is my Entity Document under the Open Entity Identity Standard; my record is at ${recordUrl}.`;
  const render = () => [head, ...parts.map((p) => `${p.label}: ${p.text}`), foot].join("\n");
  let s = render();
  while (s.length > ANCHOR_MAX && parts.length) {
    const longest = parts.reduce((a, b) => (b.text.length > a.text.length ? b : a));
    const keep = longest.text.length - (s.length - ANCHOR_MAX);
    if (keep < 12) parts = parts.filter((p) => p !== longest);
    else longest.text = longest.text.slice(0, keep - 3) + "...";
    s = render();
  }
  return s.slice(0, ANCHOR_MAX);
}

const START = "<!-- openentity:anchor:start -->";
const END = "<!-- openentity:anchor:end -->";
const block = (text: string) => `${START}\n## Open Entity identity\n\n${text}\n${END}\n`;

const FILES: Record<string, string[]> = { openclaw: ["IDENTITY.md", "SOUL.md"], claude: ["CLAUDE.md"], agents: ["AGENTS.md"] };

async function upsert(file: string, text: string) {
  const b = block(text);
  let cur = "";
  try {
    cur = await readFile(file, "utf8");
  } catch {
    /* new file */
  }
  const i = cur.indexOf(START);
  const j = cur.indexOf(END);
  const next = i >= 0 && j > i ? cur.slice(0, i) + b + cur.slice(j + END.length).replace(/^\n/, "") : cur ? cur.replace(/\n*$/, "\n\n") + b : b;
  await writeFile(file, next);
}

export async function anchor({ v }: Ctx): Promise<Result> {
  const format: string = v.format ?? "text";
  if (format !== "text" && !FILES[format]) throw usage("--format must be text, openclaw, claude or agents");
  const e = await loadEntity(v);
  const text = anchorText(e.doc, e.doc.endpoints?.record ?? `${e.registry.base}/v1/entities/${e.eid}/record`);
  if (!v.write) return { json: { format, anchor: text, length: text.length }, text: format === "text" ? text : block(text) };
  if (format === "text") throw usage("--write needs --format openclaw, claude or agents");
  const dir = v.dir ?? process.cwd();
  await mkdir(dir, { recursive: true });
  const written = FILES[format].map((f) => join(dir, f));
  for (const f of written) await upsert(f, text);
  return { json: { format, written, length: text.length }, text: `wrote anchor (${text.length} chars) to ${written.join(", ")}` };
}

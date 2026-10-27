import { a2aExtension, agentCard } from "@openentity/sdk";
import { usage } from "./errors";
import { Registry } from "./http";
import { assertEid, loadEntity, regUrl, type Ctx, type Result } from "./store";

/** Emit the spec 11.2 A2A AgentExtension block (--extension-only) or a full agent-card.json, for the local entity or for `--eid` read from the registry. */
export async function card({ v }: Ctx): Promise<Result> {
  let doc: any;
  let registry = regUrl(v);
  if (v.eid) doc = await new Registry(registry).get(`/v1/entities/${encodeURIComponent(assertEid(v.eid))}/document`);
  else {
    const e = await loadEntity(v);
    doc = e.doc;
    registry = regUrl(v, e.state);
  }
  const documentUrl = `${registry}/v1/entities/${doc.eid}/document`;
  let json: object;
  if (v["extension-only"]) json = a2aExtension(doc.eid, documentUrl);
  else {
    const url = v.url ?? doc.endpoints?.web;
    if (!url) throw usage("card needs the agent's endpoint: pass --url <https://...>, or use --extension-only");
    json = agentCard(doc, { url, documentUrl });
  }
  return { json, text: JSON.stringify(json, null, 2) };
}

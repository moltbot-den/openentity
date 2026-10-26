// Idempotent Cloudflare DNS writer for openentity.org and oeis.dev. Every record it writes is DNS-only.
//   tsx scripts/cloudflare-dns.ts validation   # ACM validation CNAMEs for openentity.org, mcp.openentity.org and oeis.dev; polls until all are issued
//   tsx scripts/cloudflare-dns.ts apex         # each domain -> its CloudFront distribution (replaces any Worker custom domain on it)
// Needs: aws CLI (profile openentity) and the gcloud configuration moltbot-den (service account; reads the Cloudflare token at runtime, never written out).
import { execFileSync } from "node:child_process";

const ACCOUNT = "b9ebc7de787d7dd325eabbe7a0baedce";
const DOMAIN = "openentity.org";
const MCP = "mcp.openentity.org";
const HUB = "oeis.dev";
// Zone of every name this script writes, validation records included.
const ZONES: Record<string, string> = { "openentity.org": "029c9b190e8777ad33c216b9857c674a", "oeis.dev": "8d7aa2319833bbab58e66e3887e6a992" };
const zoneOf = (name: string) => ZONES[Object.keys(ZONES).find((z) => name === z || name.endsWith(`.${z}`))!];
const API = "https://api.cloudflare.com/client/v4";

const run = (cmd: string, args: string[]) => execFileSync(cmd, args, { encoding: "utf8" }).trim();
const aws = (...args: string[]): any => JSON.parse(run("aws", [...args, "--profile", "openentity", "--region", "us-east-1", "--output", "json"]));
const token = run("gcloud", ["--configuration=moltbot-den", "secrets", "versions", "access", "latest", "--project", "moltbot-den", "--secret", "cloudflare-api-token"]);

async function api(path: string, init: RequestInit = {}): Promise<any> {
  const res = await fetch(API + path, { ...init, headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } });
  const body: any = await res.json();
  if (!body.success) throw new Error(`Cloudflare ${init.method ?? "GET"} ${path}: ${JSON.stringify(body.errors)}`);
  return body.result;
}

const cf = (name: string, path: string, init?: RequestInit) => api(`/zones/${zoneOf(name)}/dns_records${path}`, init);

// Upsert one record by name and type.
async function upsert(type: string, name: string, content: string) {
  name = name.replace(/\.$/, "");
  const found: any[] = await cf(name, `?type=${type}&name=${encodeURIComponent(name)}`);
  const body = JSON.stringify({ type, name, content, proxied: false, ttl: 1 });
  if (found[0]?.content.replace(/\.$/, "") === content.replace(/\.$/, "") && !found[0].proxied) return console.log(`ok      ${type} ${name}`);
  await cf(name, found[0] ? `/${found[0].id}` : "", { method: found[0] ? "PUT" : "POST", body });
  console.log(`set     ${type} ${name} -> ${content}`);
}

async function validation() {
  const pending = new Set([DOMAIN, MCP, HUB]);
  for (const deadline = Date.now() + 20 * 60_000; pending.size && Date.now() < deadline; await new Promise((r) => setTimeout(r, 15_000))) {
    for (const name of pending) {
      const cert = aws("acm", "list-certificates").CertificateSummaryList.find((c: any) => c.DomainName === name && c.Status !== "FAILED");
      if (!cert) continue;
      const d = aws("acm", "describe-certificate", "--certificate-arn", cert.CertificateArn).Certificate;
      if (d.Status === "ISSUED") {
        pending.delete(name);
        console.log(`certificate issued: ${name}`);
        continue;
      }
      for (const o of d.DomainValidationOptions ?? []) if (o.ResourceRecord) await upsert("CNAME", o.ResourceRecord.Name, o.ResourceRecord.Value);
    }
  }
  if (pending.size) throw new Error(`certificate not issued within 20 min: ${[...pending].join(", ")}`);
}

async function apex() {
  const outputs = aws("cloudformation", "describe-stacks", "--stack-name", "OpenEntity").Stacks[0].Outputs;
  const out = (k: string) => outputs.find((o: any) => o.OutputKey === k).OutputValue;
  // A Workers custom domain (AAAA 100::) would shadow the CNAME; detach it, then remove any leftover address record.
  for (const [name, key] of [[DOMAIN, "DistributionDomain"], [MCP, "McpDistributionDomain"], [HUB, "HubDistributionDomain"]]) {
    for (const d of await api(`/accounts/${ACCOUNT}/workers/domains?hostname=${name}`)) {
      if (d.hostname !== name) continue;
      await api(`/accounts/${ACCOUNT}/workers/domains/${d.id}`, { method: "DELETE" });
      console.log(`removed Worker ${d.service} from ${name}`);
    }
    for (const r of await cf(name, `?name=${name}`)) if (r.type === "AAAA" || r.type === "A") await cf(name, `/${r.id}`, { method: "DELETE" });
    await upsert("CNAME", name, out(key));
  }
}

const phase = process.argv[2];
if (phase === "validation") await validation();
else if (phase === "apex") await apex();
else (console.error("usage: cloudflare-dns.ts validation|apex"), process.exit(2));

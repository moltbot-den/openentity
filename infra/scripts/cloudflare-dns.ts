// Idempotent Cloudflare DNS writer for openentity.org. Every record it writes is DNS-only.
//   tsx scripts/cloudflare-dns.ts validation   # ACM validation CNAME; polls until the cert is issued
//   tsx scripts/cloudflare-dns.ts apex         # openentity.org -> CloudFront (replaces the old Worker record)
// Needs: aws CLI (profile openentity) and gcloud (reads the Cloudflare token at runtime; never written out).
import { execFileSync } from "node:child_process";

const ZONE = "029c9b190e8777ad33c216b9857c674a";
const DOMAIN = "openentity.org";
const CF = `https://api.cloudflare.com/client/v4/zones/${ZONE}/dns_records`;

const run = (cmd: string, args: string[]) => execFileSync(cmd, args, { encoding: "utf8" }).trim();
const aws = (...args: string[]): any => JSON.parse(run("aws", [...args, "--profile", "openentity", "--region", "us-east-1", "--output", "json"]));
const token = run("gcloud", ["secrets", "versions", "access", "latest", "--project", "moltbot-den", "--secret", "cloudflare-api-token"]);

async function cf(path: string, init: RequestInit = {}): Promise<any> {
  const res = await fetch(CF + path, { ...init, headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } });
  const body: any = await res.json();
  if (!body.success) throw new Error(`Cloudflare ${init.method ?? "GET"} ${path}: ${JSON.stringify(body.errors)}`);
  return body.result;
}

// Upsert one record by name and type.
async function upsert(type: string, name: string, content: string) {
  name = name.replace(/\.$/, "");
  const found: any[] = await cf(`?type=${type}&name=${encodeURIComponent(name)}`);
  const body = JSON.stringify({ type, name, content, proxied: false, ttl: 1 });
  if (found[0]?.content.replace(/\.$/, "") === content.replace(/\.$/, "") && !found[0].proxied) return console.log(`ok      ${type} ${name}`);
  await cf(found[0] ? `/${found[0].id}` : "", { method: found[0] ? "PUT" : "POST", body });
  console.log(`set     ${type} ${name} -> ${content}`);
}

async function validation() {
  for (const deadline = Date.now() + 20 * 60_000; Date.now() < deadline; await new Promise((r) => setTimeout(r, 15_000))) {
    const cert = aws("acm", "list-certificates").CertificateSummaryList.find((c: any) => c.DomainName === DOMAIN && c.Status !== "FAILED");
    if (!cert) continue;
    const d = aws("acm", "describe-certificate", "--certificate-arn", cert.CertificateArn).Certificate;
    if (d.Status === "ISSUED") return console.log("certificate issued");
    for (const o of d.DomainValidationOptions ?? []) if (o.ResourceRecord) await upsert("CNAME", o.ResourceRecord.Name, o.ResourceRecord.Value);
  }
  throw new Error("certificate not issued within 20 min");
}

async function apex() {
  const outputs = aws("cloudformation", "describe-stacks", "--stack-name", "OpenEntity").Stacks[0].Outputs;
  const target = outputs.find((o: any) => o.OutputKey === "DistributionDomain").OutputValue;
  // The old Workers custom-domain record (AAAA 100::) would shadow the CNAME; remove it first.
  for (const r of await cf(`?name=${DOMAIN}`)) if (r.type === "AAAA" || r.type === "A") await cf(`/${r.id}`, { method: "DELETE" });
  await upsert("CNAME", DOMAIN, target);
}

const phase = process.argv[2];
if (phase === "validation") await validation();
else if (phase === "apex") await apex();
else (console.error("usage: cloudflare-dns.ts validation|apex"), process.exit(2));

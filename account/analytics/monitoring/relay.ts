// SNS -> Customer.io relay. A Lambda subscription needs no confirmation click, so no alert path depends on a person.
// Verifies the SNS signature, formats the CloudWatch alarm, and emails the ops address through Customer.io transactional.
import { createVerify } from "node:crypto";
import type { SNSEvent, SNSEventRecord } from "aws-lambda";
import { GetParametersCommand, SSMClient } from "@aws-sdk/client-ssm";

type Sns = SNSEventRecord["Sns"];
export type Mail = { subject: string; text: string; html: string };

// ---- signature ----
const CERT_HOST = /^sns\.[a-z0-9-]+\.amazonaws\.com$/;

/** Only SNS's own signing certificates may be fetched: https, an sns.<region>.amazonaws.com host, a .pem path. */
export function certUrlOk(raw: string): boolean {
  try {
    const u = new URL(raw);
    return u.protocol === "https:" && !u.port && !u.username && CERT_HOST.test(u.hostname) && u.pathname.endsWith(".pem");
  } catch {
    return false;
  }
}

/** Canonical string SNS signs, for Notification messages (the only type a Lambda subscription receives). */
export function stringToSign(m: Sns): string {
  const parts: [string, string | undefined][] = [["Message", m.Message], ["MessageId", m.MessageId], ["Subject", m.Subject || undefined], ["Timestamp", m.Timestamp], ["TopicArn", m.TopicArn], ["Type", m.Type]];
  return parts.filter(([, v]) => v !== undefined).map(([k, v]) => `${k}\n${v}\n`).join("");
}

/** certPem may be a certificate or a public key PEM (tests pass a key). */
export function signatureOk(m: Sns, certPem: string): boolean {
  const algo = m.SignatureVersion === "2" ? "RSA-SHA256" : m.SignatureVersion === "1" ? "RSA-SHA1" : undefined;
  if (!algo || m.Type !== "Notification") return false;
  try {
    return createVerify(algo).update(stringToSign(m), "utf8").verify(certPem, m.Signature, "base64");
  } catch {
    return false;
  }
}

// ---- formatting ----
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
const VERB: Record<string, string> = { ALARM: "FIRED", OK: "RESOLVED", INSUFFICIENT_DATA: "NO DATA" };

export function formatMail(m: Sns, stage: string): Mail {
  let a: Record<string, unknown> | undefined;
  try { a = JSON.parse(m.Message); } catch { /* not a CloudWatch alarm */ }
  const tag = `[OpenEntity ${stage}]`;
  if (a && typeof a.AlarmName === "string" && typeof a.NewStateValue === "string") {
    const verb = VERB[a.NewStateValue] ?? a.NewStateValue;
    const lines = [
      `Alarm: ${a.AlarmName}`, `State: ${verb} (was ${String(a.OldStateValue ?? "unknown")})`, `Stage: ${stage}`,
      `Reason: ${String(a.NewStateReason ?? "")}`, `Time: ${String(a.StateChangeTime ?? m.Timestamp)}`, `Region: ${String(a.Region ?? "")}`,
      ...(a.AlarmDescription ? [`Description: ${String(a.AlarmDescription)}`] : []),
    ];
    return { subject: `${tag} ${verb}: ${a.AlarmName}`, text: lines.join("\n"), html: `<p>${lines.map(esc).join("<br>")}</p>` };
  }
  const body = m.Message.slice(0, 2000);
  return { subject: `${tag} Notice: ${(m.Subject || "message").slice(0, 120)}`, text: body, html: `<pre>${esc(body)}</pre>` };
}

/** A new alarm settling from INSUFFICIENT_DATA to OK is not news: no "RESOLVED" mail for it (a deploy would send one per alarm). */
export function isNoise(m: Sns): boolean {
  try { const a = JSON.parse(m.Message); return a.NewStateValue === "OK" && a.OldStateValue === "INSUFFICIENT_DATA"; } catch { return false; }
}

// ---- handler ----
export type Deps = {
  stage: string;
  topicArn: string;
  to: string;
  getCert: (url: string) => Promise<string>;
  send: (mail: Mail & { to: string }) => Promise<void>;
};

export function makeRelay(d: Deps) {
  return async (event: SNSEvent): Promise<void> => {
    for (const r of event.Records) {
      const m = r.Sns;
      if (m.TopicArn !== d.topicArn) throw new Error(`unexpected topic ${m.TopicArn}`);
      if (!certUrlOk(m.SigningCertUrl)) throw new Error("bad SigningCertUrl");
      if (!signatureOk(m, await d.getCert(m.SigningCertUrl))) throw new Error("bad SNS signature"); // never email an unverified message
      if (isNoise(m)) continue;
      await d.send({ ...formatMail(m, d.stage), to: d.to });
    }
  };
}

const certs = new Map<string, Promise<string>>();
const getCert = (url: string) => {
  if (!certs.has(url)) certs.set(url, fetch(url).then((r) => { if (!r.ok) throw new Error(`cert ${r.status}`); return r.text(); }).catch((e) => { certs.delete(url); throw e; }));
  return certs.get(url)!;
};

export const PARAM_PATH = "/openentity/account/";
/** The account service's own Customer.io key: <name> for both stages, <name>_<prod|staging> for one (this stage wins). */
export const cioParamNames = (stage: string) => [`cio_app_api_key_${stage === "production" ? "prod" : "staging"}`, "cio_app_api_key"];

const ssm = new SSMClient({});
let cio: Promise<string> | undefined;
// Explicit names only (GetParameters, never a path): the role cannot read any other parameter.
const appKey = () => (cio ??= ssm.send(new GetParametersCommand({ Names: cioParamNames(process.env.STAGE!).map((n) => PARAM_PATH + n), WithDecryption: true }))
  .then((r) => {
    const got = Object.fromEntries((r.Parameters ?? []).map((p) => [p.Name!.slice(PARAM_PATH.length), p.Value!]));
    const k = cioParamNames(process.env.STAGE!).map((n) => got[n]).find(Boolean);
    if (!k) throw new Error("account Customer.io key not found in SSM");
    return k;
  })
  .catch((e) => { cio = undefined; throw e; }));

export async function sendViaCustomerIo(mail: Mail & { to: string }): Promise<void> {
  const res = await fetch("https://api.customer.io/v1/send/email", {
    method: "POST",
    headers: { authorization: `Bearer ${await appKey()}`, "content-type": "application/json" },
    body: JSON.stringify({ to: mail.to, from: "Open Entity <updates@openentity.org>", subject: mail.subject, body: mail.html, plaintext_body: mail.text, identifiers: { id: "oe_ops_alerts" }, disable_message_retention: true, send_to_unsubscribed: true, tracked: false }), // fixed id: ops mail never joins the newsletter audience (same call shape as account/src/email.ts)
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) throw new Error(`customer.io ${res.status}: ${(await res.text()).slice(0, 200)}`); // throwing makes SNS retry the invocation
}

export const handler = (e: SNSEvent) =>
  makeRelay({ stage: process.env.STAGE!, topicArn: process.env.TOPIC_ARN!, to: process.env.ALERT_EMAIL!, getCert, send: sendViaCustomerIo })(e);

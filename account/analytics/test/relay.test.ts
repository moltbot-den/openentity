import { generateKeyPairSync, createSign } from "node:crypto";
import type { SNSEvent } from "aws-lambda";
import { describe, expect, it, vi } from "vitest";
import { certUrlOk, formatMail, makeRelay, signatureOk, stringToSign } from "../monitoring/relay.ts";

const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const pub = publicKey.export({ type: "spki", format: "pem" }) as string;
const TOPIC = "arn:aws:sns:us-east-1:099705791378:alerts";
const CERT = "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-abc.pem";

type S = Parameters<typeof stringToSign>[0];
const alarm = (state: string, extra: object = {}) => JSON.stringify({ AlarmName: "Rate5xx", NewStateValue: state, OldStateValue: "OK", NewStateReason: "Threshold Crossed", StateChangeTime: "2026-11-12T10:00:00Z", Region: "US East (N. Virginia)", ...extra });
const signed = (over: Partial<S> = {}, v: "1" | "2" = "2"): S => {
  const m = { Type: "Notification", MessageId: "id-1", TopicArn: TOPIC, Subject: 'ALARM: "Rate5xx"', Message: alarm("ALARM"), Timestamp: "2026-11-12T10:00:00.000Z", SignatureVersion: v, SigningCertUrl: CERT, ...over } as S;
  m.Signature = createSign(v === "2" ? "RSA-SHA256" : "RSA-SHA1").update(stringToSign(m), "utf8").sign(privateKey, "base64");
  return m;
};
const ev = (m: S) => ({ Records: [{ Sns: m }] }) as unknown as SNSEvent;

describe("SNS signature", () => {
  it.each(["1", "2"] as const)("accepts a genuine v%s signature", (v) => expect(signatureOk(signed({}, v), pub)).toBe(true));
  it("accepts a message without a Subject", () => expect(signatureOk(signed({ Subject: undefined }), pub)).toBe(true));
  it("rejects a tampered message, subject, topic or timestamp", () => {
    const m = signed();
    for (const over of [{ Message: alarm("OK") }, { Subject: "x" }, { TopicArn: "arn:aws:sns:us-east-1:1:other" }, { Timestamp: "2026-11-12T11:00:00.000Z" }])
      expect(signatureOk({ ...m, ...over }, pub)).toBe(false);
  });
  it("rejects a signature from another key, an unknown version and a non-Notification type", () => {
    const other = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ type: "spki", format: "pem" }) as string;
    expect(signatureOk(signed(), other)).toBe(false);
    expect(signatureOk({ ...signed(), SignatureVersion: "3" }, pub)).toBe(false);
    expect(signatureOk(signed({ Type: "SubscriptionConfirmation" } as Partial<S>), pub)).toBe(false);
  });
  it("only fetches SNS certificates over https from sns.<region>.amazonaws.com", () => {
    expect(certUrlOk(CERT)).toBe(true);
    for (const u of ["http://sns.us-east-1.amazonaws.com/a.pem", "https://evil.example.com/a.pem", "https://sns.us-east-1.amazonaws.com.evil.com/a.pem", "https://sns.us-east-1.amazonaws.com/a.txt", "https://sns.us-east-1.amazonaws.com:8443/a.pem", "https://user@sns.us-east-1.amazonaws.com/a.pem", "not a url"])
      expect(certUrlOk(u), u).toBe(false);
  });
});

describe("formatting", () => {
  it("subject names the alarm, fired or resolved, and the stage", () => {
    expect(formatMail(signed(), "staging").subject).toBe("[OpenEntity staging] FIRED: Rate5xx");
    expect(formatMail(signed({ Message: alarm("OK", { OldStateValue: "ALARM" }) }), "production").subject).toBe("[OpenEntity production] RESOLVED: Rate5xx");
    expect(formatMail(signed({ Message: alarm("INSUFFICIENT_DATA") }), "staging").subject).toBe("[OpenEntity staging] NO DATA: Rate5xx");
  });
  it("body carries state, reason and stage, and escapes HTML", () => {
    const m = formatMail(signed({ Message: alarm("ALARM", { AlarmName: "<b>x</b>" }) }), "staging");
    expect(m.text).toContain("Stage: staging");
    expect(m.text).toContain("Reason: Threshold Crossed");
    expect(m.html).toContain("&lt;b&gt;x&lt;/b&gt;");
    expect(m.html).not.toContain("<b>x</b>");
  });
  it("formats a non-alarm notice instead of failing", () => {
    expect(formatMail(signed({ Message: "plain text", Subject: "hello" }), "staging").subject).toBe("[OpenEntity staging] Notice: hello");
  });
});

describe("relay", () => {
  const deps = (send = vi.fn(async () => {})) => ({ stage: "staging", topicArn: TOPIC, to: "ops@example.com", getCert: async () => pub, send });
  it("emails the ops address for a verified alarm", async () => {
    const send = vi.fn(async () => {});
    await makeRelay(deps(send))(ev(signed()));
    expect(send).toHaveBeenCalledWith(expect.objectContaining({ to: "ops@example.com", subject: "[OpenEntity staging] FIRED: Rate5xx" }));
  });
  it("sends nothing and throws for a forged signature, another topic or a bad cert URL", async () => {
    const send = vi.fn(async () => {});
    const r = makeRelay(deps(send));
    await expect(r(ev({ ...signed(), Message: alarm("OK") }))).rejects.toThrow(/signature/);
    await expect(r(ev(signed({ TopicArn: "arn:aws:sns:us-east-1:1:other" })))).rejects.toThrow(/topic/);
    await expect(r(ev(signed({ SigningCertUrl: "https://evil.example.com/a.pem" })))).rejects.toThrow(/SigningCertUrl/);
    expect(send).not.toHaveBeenCalled();
  });
});

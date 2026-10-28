// Forwards mail for identity@openentity.org to the operator address in the app secret.
// The raw message is already in S3 (the receipt rule's first action); this copies it on as an .eml attachment
// with Reply-To set to the original sender, so a reply from the inbox goes to the sender, not back to identity@.
import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { GetSecretValueCommand, SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import { SESv2Client, SendEmailCommand } from "@aws-sdk/client-sesv2";

const s3 = new S3Client({});
const ses = new SESv2Client({});
const secrets = new SecretsManagerClient({});

interface SesRecord {
  ses: {
    mail: { messageId: string; source: string; commonHeaders: { from?: string[]; subject?: string } };
    receipt: { spamVerdict: { status: string }; virusVerdict: { status: string } };
  };
}

// Header values must not carry line breaks.
const oneLine = (s: string) => s.replace(/[\r\n]+/g, " ").trim();
const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64").replace(/(.{76})/g, "$1\r\n");

export function buildForward(opts: { to: string; from: string; replyTo: string; subject: string; raw: Uint8Array; id: string }): string {
  const b = `oe-${opts.id}`;
  return [
    `From: Open Entity inbox <${opts.from}>`,
    `To: ${opts.to}`,
    `Reply-To: ${oneLine(opts.replyTo)}`,
    `Subject: ${oneLine(`[identity@] ${opts.subject}`)}`,
    "MIME-Version: 1.0",
    `Content-Type: multipart/mixed; boundary="${b}"`,
    "",
    `--${b}`,
    'Content-Type: text/plain; charset="UTF-8"',
    "",
    `Mail to identity@openentity.org from ${oneLine(opts.replyTo)}. The original is attached; reply to answer the sender.`,
    "",
    `--${b}`,
    'Content-Type: message/rfc822; name="original.eml"',
    "Content-Transfer-Encoding: base64",
    'Content-Disposition: attachment; filename="original.eml"',
    "",
    b64(opts.raw),
    `--${b}--`,
    "",
  ].join("\r\n");
}

export async function handler(event: { Records: SesRecord[] }): Promise<void> {
  const secret = JSON.parse(
    (await secrets.send(new GetSecretValueCommand({ SecretId: process.env.APP_SECRET_ARN! }))).SecretString ?? "{}",
  );
  const to: string | undefined = secret.OPERATOR_EMAIL;
  if (!to) throw new Error("OPERATOR_EMAIL missing from the app secret");
  for (const { ses: r } of event.Records) {
    // Spam and viruses stay in S3 (the first rule action) and are not forwarded.
    if (r.receipt.spamVerdict.status === "FAIL" || r.receipt.virusVerdict.status === "FAIL") continue;
    const id = r.mail.messageId;
    const obj = await s3.send(new GetObjectCommand({ Bucket: process.env.MAIL_BUCKET!, Key: `${process.env.MAIL_PREFIX}${id}` }));
    const raw = await obj.Body!.transformToByteArray();
    const data = buildForward({
      to, from: "identity@openentity.org", replyTo: r.mail.commonHeaders.from?.[0] ?? r.mail.source,
      subject: r.mail.commonHeaders.subject ?? "(no subject)", raw, id,
    });
    await ses.send(new SendEmailCommand({
      FromEmailAddress: "identity@openentity.org",
      Destination: { ToAddresses: [to] },
      Content: { Raw: { Data: Buffer.from(data) } },
    }));
  }
}

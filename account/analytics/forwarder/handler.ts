import type { SQSBatchResponse, SQSEvent } from "aws-lambda";
import { GetSecretValueCommand, SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import { validateEvent, type QueuedEvent } from "../src/validate.ts";
import { sendAmplitude, sendGa4, sendPosthog, type Keys } from "./senders.ts";

type Deps = { getKeys: () => Promise<Keys>; fetch: typeof fetch; log: (m: string) => void };

/** Secret `openentity/account` keys: analytics_<thing>_<prod|staging>. */
export function keysFrom(secret: Record<string, string>, env: string): Keys {
  const s = env === "production" ? "prod" : "staging";
  const need = (k: string) => {
    const v = secret[`analytics_${k}_${s}`];
    if (!v) throw new Error(`secret missing analytics_${k}_${s}`);
    return v;
  };
  return {
    amplitudeApiKey: need("amplitude_api_key"),
    amplitudeUrl: secret.analytics_amplitude_url,
    posthogKey: need("posthog_key"),
    posthogHost: secret.analytics_posthog_host,
    ga4MeasurementId: need("ga4_measurement_id"),
    ga4ApiSecret: need("ga4_api_secret"),
  };
}

export function makeHandler(d: Deps) {
  return async (event: SQSEvent): Promise<SQSBatchResponse> => {
    const failed = new Set<string>();
    const valid: { id: string; e: QueuedEvent }[] = [];
    for (const r of event.Records) {
      let parsed: unknown;
      try { parsed = JSON.parse(r.body); } catch { parsed = undefined; }
      const v = validateEvent(parsed);
      if (v.ok) valid.push({ id: r.messageId, e: v.event });
      else { d.log(`invalid event ${r.messageId}: ${v.error}`); failed.add(r.messageId); } // retries, then the DLQ alarm fires
    }
    if (valid.length) {
      const keys = await d.getKeys();
      const events = valid.map((x) => x.e);
      const markAll = (ids: string[]) => ids.forEach((i) => failed.add(i));
      const tasks: Promise<void>[] = [
        sendAmplitude(d.fetch, keys, events).catch((err) => { d.log(`amplitude: ${err}`); markAll(valid.map((x) => x.id)); }),
        sendPosthog(d.fetch, keys, events).catch((err) => { d.log(`posthog: ${err}`); markAll(valid.map((x) => x.id)); }),
      ];
      // GA4: one group per client_id so a failure only retries that client's records.
      const groups = new Map<string, typeof valid>();
      for (const x of valid) {
        const c = x.e.install_id ?? x.e.user_id!;
        groups.set(c, [...(groups.get(c) ?? []), x]);
      }
      for (const g of groups.values())
        tasks.push(sendGa4(d.fetch, keys, g.map((x) => x.e)).catch((err) => { d.log(`ga4: ${err}`); markAll(g.map((x) => x.id)); }));
      await Promise.all(tasks);
    }
    // A retried record is re-sent to all three tools. Amplitude (insert_id) and PostHog (uuid) dedupe; GA4 does not.
    // ponytail: GA4 may double count a retried record; add a per-destination queue if retries become common.
    return { batchItemFailures: [...failed].map((itemIdentifier) => ({ itemIdentifier })) };
  };
}

let cached: Promise<Keys> | undefined;
const sm = new SecretsManagerClient({});
export const handler = makeHandler({
  fetch,
  log: (m) => console.error(m),
  getKeys: () =>
    (cached ??= sm
      .send(new GetSecretValueCommand({ SecretId: process.env.ACCOUNT_SECRET_ID ?? "openentity/account" }))
      .then((r) => keysFrom(JSON.parse(r.SecretString ?? "{}"), process.env.ANALYTICS_ENV ?? "staging"))
      .catch((e) => { cached = undefined; throw e; })),
});

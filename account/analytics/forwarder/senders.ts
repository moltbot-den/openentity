import type { QueuedEvent } from "../src/validate.ts";

/** A tool whose key is absent is not configured, and the handler skips it. */
export type Keys = {
  amplitudeApiKey?: string;
  amplitudeUrl?: string; // default US; EU is https://api.eu.amplitude.com/2/httpapi
  posthogKey?: string;
  posthogHost?: string; // default https://us.i.posthog.com
  ga4MeasurementId?: string;
  ga4ApiSecret?: string;
};
type Fetch = typeof fetch;

export const GA4_MAX_EVENTS = 25;

async function post(f: Fetch, url: string, body: unknown, what: string): Promise<void> {
  const res = await f(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  if (!res.ok) throw new Error(`${what} ${res.status}`); // any non-2xx retries via SQS; 4xx lands in the DLQ after maxReceiveCount
}

const who = (e: QueuedEvent) => e.user_id ?? e.install_id!;

export async function sendAmplitude(f: Fetch, k: Keys, events: QueuedEvent[]): Promise<void> {
  if (!events.length) return;
  await post(f, k.amplitudeUrl ?? "https://api2.amplitude.com/2/httpapi", {
    api_key: k.amplitudeApiKey,
    events: events.map((e) => ({
      event_type: e.event,
      user_id: e.user_id,
      device_id: e.install_id,
      time: e.ts_ms,
      insert_id: e.event_id, // Amplitude dedupes on this for 7 days, so an SQS retry cannot double count
      platform: e.platform,
      app_version: e.app_version,
      event_properties: e.props,
    })),
  }, "amplitude");
}

export async function sendPosthog(f: Fetch, k: Keys, events: QueuedEvent[]): Promise<void> {
  if (!events.length) return;
  await post(f, `${k.posthogHost ?? "https://us.i.posthog.com"}/batch/`, {
    api_key: k.posthogKey,
    batch: events.map((e) => ({
      event: e.event,
      distinct_id: who(e),
      uuid: e.event_id, // PostHog dedupes on uuid
      timestamp: new Date(e.ts_ms).toISOString(),
      properties: { ...e.props, platform: e.platform, app_version: e.app_version, install_id: e.install_id, $process_person_profile: false, $geoip_disable: true },
    })),
  }, "posthog");
}

/** One request per GA4 client_id, at most 25 events each (Measurement Protocol limit). */
export function ga4Requests(events: QueuedEvent[]): { client_id: string; user_id?: string; timestamp_micros: number; events: { name: string; params: Record<string, unknown> }[] }[] {
  const byClient = new Map<string, QueuedEvent[]>();
  for (const e of events) {
    const id = e.install_id ?? e.user_id!;
    byClient.set(id, [...(byClient.get(id) ?? []), e]);
  }
  const out = [];
  for (const [client_id, list] of byClient)
    for (let i = 0; i < list.length; i += GA4_MAX_EVENTS) {
      const chunk = list.slice(i, i + GA4_MAX_EVENTS);
      out.push({
        client_id,
        user_id: chunk[0].user_id,
        timestamp_micros: chunk[0].ts_ms * 1000, // per-event times are not sent: a MP request carries one base time
        events: chunk.map((e) => ({ name: e.event, params: { ...e.props, platform: e.platform, app_version: e.app_version, engagement_time_msec: 1 } })),
      });
    }
  return out;
}

export async function sendGa4(f: Fetch, k: Keys, events: QueuedEvent[]): Promise<void> {
  const url = `https://www.google-analytics.com/mp/collect?measurement_id=${encodeURIComponent(k.ga4MeasurementId!)}&api_secret=${encodeURIComponent(k.ga4ApiSecret!)}`;
  for (const body of ga4Requests(events)) await post(f, url, body, "ga4");
}

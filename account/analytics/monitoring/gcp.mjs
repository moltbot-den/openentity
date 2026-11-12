// Idempotent GCP Cloud Monitoring setup: email channel, Cloud Run dashboard, uptime checks and their alert policies.
//   node gcp.mjs           apply
//   node gcp.mjs --dry-run print what would be created
// Auth: the active gcloud account (claude-ops). Uses the REST API, so no gcloud alpha component is needed.
// Cost: uptime checks run every 5 minutes (about 52k executions each per month; the free quota is 1M per project).
import { execFileSync } from "node:child_process";

const EMAIL = process.env.OPS_EMAIL ?? "will@moltbotden.com"; // the address already on the moltbot-den "Owner" channel
const dry = process.argv.includes("--dry-run");

// Each product project: Cloud Run dashboard title and the uptime checks to own. Existing checks keep their names.
export const PROJECTS = {
  "moltbot-den": {
    dashboard: "Moltbot Den: Cloud Run",
    checks: [
      { name: "API /health", host: "api.moltbotden.com", path: "/health", noPolicy: true }, // existing "API down" policy covers it,
      { name: "Web /", host: "moltbotden.com", path: "/", noPolicy: true },
      { name: "openentity-registry /v1/stats", host: "openentity.org", path: "/v1/stats" },
      { name: "securemyagent-site /", host: "securemyagent.ai", path: "/" }, // ponytail: SMA has no health route yet; swap the path when it ships one
      // account.openentity.org does not resolve yet. Policy stays disabled until the Account lane deploys it.
      { name: "account-service jwks", host: "account.openentity.org", path: "/.well-known/jwks.json", disabled: true },
    ],
  },
  "agent-secret-store": {
    dashboard: "Agent Secret Store: Cloud Run",
    checks: [
      { name: "ass-api-uptime", host: "api.agentsecretstore.com", path: "/v1/health" },
      { name: "ass-frontend-uptime", host: "agentsecretstore.com", path: "/" },
      { name: "ass-mcp-uptime", host: "mcp.agentsecretstore.com", path: "/sse" },
    ],
  },
  clawgrc: {
    dashboard: "ClawGRC: Cloud Run",
    checks: [{ name: "clawgrc-api /health", host: "api.clawgrc.com", path: "/health" }],
  },
};

const token = () => execFileSync("gcloud", ["auth", "print-access-token"], { encoding: "utf8" }).trim();
async function api(method, url, body) {
  const r = await fetch(`https://monitoring.googleapis.com/v3/${url}`, {
    method, headers: { authorization: `Bearer ${token()}`, "content-type": "application/json" }, body: body && JSON.stringify(body),
  });
  const j = await r.json();
  if (!r.ok) throw new Error(`${method} ${url}: ${r.status} ${JSON.stringify(j.error ?? j)}`);
  return j;
}
const list = async (project, kind, key) => (await api("GET", `projects/${project}/${kind}`))[key] ?? [];

const tile = (title, filter, aligner, reducer, unit) => ({
  title,
  xyChart: { dataSets: [{ plotType: "LINE", timeSeriesQuery: { timeSeriesFilter: { filter, aggregation: { alignmentPeriod: "60s", perSeriesAligner: aligner, crossSeriesReducer: reducer, groupByFields: ["resource.label.service_name"] } } } }], yAxis: { label: unit } },
});
export const dashboard = (title) => ({
  displayName: title,
  gridLayout: {
    columns: 2,
    widgets: [
      tile("Request latency p95 (ms)", 'metric.type="run.googleapis.com/request_latencies" resource.type="cloud_run_revision"', "ALIGN_PERCENTILE_95", "REDUCE_PERCENTILE_95", "ms"),
      tile("5xx requests per minute", 'metric.type="run.googleapis.com/request_count" resource.type="cloud_run_revision" metric.label.response_code_class="5xx"', "ALIGN_RATE", "REDUCE_SUM", "req/s"),
      tile("Container instances", 'metric.type="run.googleapis.com/container/instance_count" resource.type="cloud_run_revision"', "ALIGN_MEAN", "REDUCE_SUM", "instances"),
    ].map((w) => ({ ...w })),
  },
});

export const uptimeCheck = (c) => ({
  displayName: c.name, period: "300s", timeout: "10s",
  monitoredResource: { type: "uptime_url", labels: { host: c.host } },
  httpCheck: { path: c.path, port: 443, useSsl: true, validateSsl: true, requestMethod: "GET" },
});
export const policy = (c, checkId, channel) => ({
  displayName: `Uptime: ${c.name}`, combiner: "OR", enabled: !c.disabled, notificationChannels: [channel],
  conditions: [{ displayName: `${c.name} failing`, conditionThreshold: {
    filter: `metric.type="monitoring.googleapis.com/uptime_check/check_passed" AND metric.label.check_id="${checkId}" AND resource.type="uptime_url"`,
    aggregations: [{ alignmentPeriod: "1200s", perSeriesAligner: "ALIGN_NEXT_OLDER", crossSeriesReducer: "REDUCE_COUNT_FALSE", groupByFields: ["resource.label.*"] }],
    comparison: "COMPARISON_GT", thresholdValue: 1, duration: "60s", trigger: { count: 1 } } }],
});

async function ensure(project, kind, key, displayName, make, label) {
  const found = (await list(project, kind, key)).find((x) => x.displayName === displayName);
  if (found) { console.log(`${project}: ${label} "${displayName}" exists`); return found; }
  console.log(`${project}: create ${label} "${displayName}"`);
  return dry ? { name: `${project}/dry`, displayName } : api("POST", `projects/${project}/${kind}`, make());
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  for (const [project, cfg] of Object.entries(PROJECTS)) {
    // Reuse an existing email channel for this address; create one only when the project has none.
    let ch = (await list(project, "notificationChannels", "notificationChannels")).find((c) => c.type === "email" && c.labels?.email_address === EMAIL);
    if (!ch) {
      console.log(`${project}: create email channel`);
      ch = dry ? { name: `${project}/dry` } : await api("POST", `projects/${project}/notificationChannels`, { type: "email", displayName: `Ops email (${EMAIL})`, labels: { email_address: EMAIL } });
    }
    // Dashboards live on the v1 endpoint.
    const dl = await fetch(`https://monitoring.googleapis.com/v1/projects/${project}/dashboards`, { headers: { authorization: `Bearer ${token()}` } }).then((r) => r.json());
    if ((dl.dashboards ?? []).some((d) => d.displayName === cfg.dashboard)) console.log(`${project}: dashboard exists`);
    else if (!dry) {
      const r = await fetch(`https://monitoring.googleapis.com/v1/projects/${project}/dashboards`, { method: "POST", headers: { authorization: `Bearer ${token()}`, "content-type": "application/json" }, body: JSON.stringify(dashboard(cfg.dashboard)) });
      if (!r.ok) throw new Error(`dashboard ${project}: ${await r.text()}`);
      console.log(`${project}: created dashboard`);
    } else console.log(`${project}: create dashboard`);
    for (const c of cfg.checks) {
      const check = await ensure(project, "uptimeCheckConfigs", "uptimeCheckConfigs", c.name, () => uptimeCheck(c), "uptime check");
      const checkId = check.name.split("/").pop();
      if (!c.noPolicy) await ensure(project, "alertPolicies", "alertPolicies", `Uptime: ${c.name}`, () => policy(c, checkId, ch.name), "alert policy");
    }
  }
}

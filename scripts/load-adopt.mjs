#!/usr/bin/env node
// Load test for POST /v1/adopt (PRD 11, Phase 1 verification).
// Usage: node scripts/load-adopt.mjs <base-url> [rate-per-second=100] [seconds=60]
// Pre-mints keys, signed objects and proof-of-work stamps, then fires at a fixed rate and reports
// p95 adopt latency and the time until the signed checkpoint covers every returned log_index.
// Run it against a preview deployment, never production.
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads";
import { createHash, randomBytes } from "node:crypto";
import { availableParallelism } from "node:os";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const b58 = (n) => { let s = ""; do { s = B58[Number(n % 58n)] + s; n /= 58n; } while (n > 0n); return s; };
const zeroBits = (h) => { let n = 0; for (const b of h) { if (b === 0) { n += 8; continue; } return n + Math.clz32(b) - 24; } return n; };

if (!isMainThread) {
  const { eids, bits, created } = workerData;
  let n = BigInt("0x" + randomBytes(8).toString("hex"));
  const stamps = eids.map((eid) => {
    for (;;) {
      const h = `1:${bits}:${created}:${eid}:${b58(n++)}`;
      if (zeroBits(createHash("sha256").update(h).digest()) >= bits) return h;
    }
  });
  parentPort.postMessage(stamps);
} else {
  const base = (process.argv[2] ?? "").replace(/\/$/, "");
  const rate = Number(process.argv[3] ?? 100), seconds = Number(process.argv[4] ?? 60), total = rate * seconds;
  if (!/^https?:\/\//.test(base)) { console.error("usage: node scripts/load-adopt.mjs <base-url> [rate] [seconds]"); process.exit(2); }
  const sdk = await import("../sdk/ts/src/index.ts");
  const { stamp_bits: bits } = await (await fetch(`${base}/v1/spec`)).json();

  console.error(`minting ${total} entities and ${bits}-bit stamps`);
  const t0 = Date.now();
  const bodies = [];
  for (let i = 0; i < total; i++) {
    const kp = await sdk.generateKeyPair();
    const name = `Load test ${i}`;
    bodies.push({
      eid: kp.did,
      body: JSON.stringify({
        document: await sdk.signObject(sdk.buildDocument({ kp, name, description: "Load test entity; withdraw after the run." }), kp),
        declaration: await sdk.signObject(sdk.buildDeclaration({ eid: kp.did, name }), kp),
      }),
    });
  }
  // Stamps may be up to 10 minutes in the future; dating them +5 min gives the run a 15 minute window.
  const created = new Date(Date.now() + 5 * 60_000).toISOString().replace(/\.\d+Z$/, "Z");
  const cores = availableParallelism(), per = Math.ceil(total / cores);
  const parts = await Promise.all(Array.from({ length: cores }, (_, w) => new Promise((resolve, reject) => {
    const worker = new Worker(new URL(import.meta.url), { workerData: { eids: bodies.slice(w * per, (w + 1) * per).map((b) => b.eid), bits, created } });
    worker.once("message", resolve);
    worker.once("error", reject);
  })));
  const stamps = parts.flat();
  console.error(`minted in ${((Date.now() - t0) / 1000).toFixed(1)} s; firing ${rate}/s for ${seconds} s`);

  const results = [];
  const start = performance.now();
  await Promise.all(bodies.map(async (b, i) => {
    await new Promise((r) => setTimeout(r, Math.max(0, start + (i * 1000) / rate - performance.now())));
    const s = performance.now();
    try {
      const res = await fetch(`${base}/v1/adopt`, { method: "POST", headers: { "content-type": "application/json", "x-oe-stamp": stamps[i] }, body: b.body });
      const j = await res.json().catch(() => ({}));
      results.push({ status: res.status, ms: performance.now() - s, log_index: j.log_index, error: j.error, at: Date.now() });
    } catch (e) {
      results.push({ status: 0, ms: performance.now() - s, error: String(e), at: Date.now() });
    }
  }));
  const lastResponse = Math.max(...results.map((r) => r.at));
  const ok = results.filter((r) => r.status === 201);
  const ms = results.map((r) => r.ms).sort((a, b) => a - b);
  const pct = (p) => ms[Math.min(ms.length - 1, Math.floor((p / 100) * ms.length))];
  const maxIndex = Math.max(...ok.map((r) => r.log_index));

  let covered = null;
  while (ok.length && Date.now() - lastResponse < 15 * 60_000) {
    const size = Number((await (await fetch(`${base}/v1/log/checkpoint`)).text()).split("\n")[1]);
    if (size > maxIndex) { covered = Date.now(); break; }
    await new Promise((r) => setTimeout(r, 1000));
  }
  const errors = {};
  for (const r of results) if (r.status !== 201) errors[`${r.status} ${r.error ?? ""}`.trim()] = (errors[`${r.status} ${r.error ?? ""}`.trim()] ?? 0) + 1;
  console.log(JSON.stringify({
    base, rate, seconds, sent: results.length, accepted: ok.length, errors,
    latency_ms: { p50: Math.round(pct(50)), p95: Math.round(pct(95)), p99: Math.round(pct(99)), max: Math.round(ms[ms.length - 1]) },
    max_log_index: maxIndex,
    incorporation_seconds_after_last_response: covered ? (covered - lastResponse) / 1000 : null,
  }, null, 2));
}

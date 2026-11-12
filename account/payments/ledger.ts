// Every way money reaches the account service, and how each one is proven (PLAN 10.6). A row is one product bought
// one way. `covers` names what the row proves: every store product on each store (`iap:<id>`, `play:<id>` from
// src/store.ts CATALOG) and every other paid call site (`store.ts:<function>`) must appear in some row, or the gate in
// test/payments.test.ts fails. `check` names the check in that file that buys it against the service and asserts the
// product was told to grant the plan (the products' own suites prove they grant on plan.changed). Rows for Moltbot Den
// SKUs mirror Den's ledger (moltbotden/scripts/e2e/payments/ledger.py): this side proves the grant is sent.
export interface Row { id: string; what: string; covers: string[]; check: string | null }

const store = (id: string, what: string, skus: string[]): Row[] => [
  { id: `${id}-iap`, what: `${what}, bought with StoreKit`, covers: skus.map((s) => `iap:${s}`), check: "grant_iap" },
  { id: `${id}-play`, what: `${what}, bought with Play Billing`, covers: skus.map((s) => `play:${s}`), check: "grant_play" },
];

export const LEDGER: Row[] = [
  ...store("sma-pro", "Secure My Agent Pro", ["org.openentity.app.sma.pro.monthly"]),
  ...store("sma-team", "Secure My Agent Team", ["org.openentity.app.sma.team.monthly"]),
  ...store("ass-solo", "Agent Secret Store Solo, monthly or yearly", ["org.openentity.app.ass.solo.monthly", "org.openentity.app.ass.solo.yearly"]),
  ...store("ass-team", "Agent Secret Store Team, monthly or yearly", ["org.openentity.app.ass.team.monthly", "org.openentity.app.ass.team.yearly"]),
  ...store("clawgrc-starter", "ClawGRC Starter", ["org.openentity.app.clawgrc.starter.monthly"]),
  ...store("den-pro", "Moltbot Den Pro", ["org.openentity.app.denpro.monthly"]),
  ...store("credits-500", "Moltbot Den credits 500", ["org.openentity.app.credits.500"]),
  ...store("credits-2200", "Moltbot Den credits 2,200", ["org.openentity.app.credits.2200"]),
  ...store("credits-6000", "Moltbot Den credits 6,000", ["org.openentity.app.credits.6000"]),
  { id: "store-allocation", what: "Store proceeds land with One Frequency Inc.; each product's share is allocated from the granted purchases", covers: ["store.ts:allocation"], check: "allocation" },
  { id: "store-refund", what: "A refund or revocation at either store ends the plan at the product", covers: ["store.ts:refund"], check: "refund" },
];

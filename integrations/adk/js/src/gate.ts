// Trust gate: openEntityVerified() for functions and OpenEntityGate for ADK tools.
// It checks the counterparty named in a tool argument (counterpartyArg), or this agent's own EID (a kill switch Claw GRC
// can pull). Reads only registry attestations through trust() and fails closed: any error is a denial.
import { BasePlugin, type BaseTool } from "@google/adk";
import { trust as sdkTrust, type TrustReport } from "@openentity/sdk";
import { Identity } from "@openentity/sdk/node";

export const CLAWGRC = "did:web:api.clawgrc.com";
const SEVERITY: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };
export type Severity = "low" | "medium" | "high" | "critical";

export interface Bar {
  minTier: number;
  requireSma: boolean;
  /** deny when a live custom:clawgrc:violation has this severity or worse; null turns the check off */
  denyOnViolation: Severity | null;
  /** whose trust_tier attestation counts; default did:web:api.clawgrc.com */
  tierIssuer: string;
}
export const DEFAULT_BAR: Bar = { minTier: 2, requireSma: true, denyOnViolation: "high", tierIssuer: CLAWGRC };
type TrustFn = (eid: string) => Promise<TrustReport>;
export type Denial = { error: "open_entity_denied"; denied: true; reason: string; detail: string; eid: string | null; required: Partial<Bar>; observed: object };
/** A DID, a function that returns one, or undefined for this machine's existing identity. */
export type EidSource = string | (() => string | Promise<string>) | undefined;
export type GateOptions = Partial<Bar> & {
  /** name of the tool argument holding the other agent's EID; when set, that agent is checked instead of this one */
  counterpartyArg?: string;
  eid?: EidSource;
  trust?: TrustFn;
};

function checkThreshold(s: unknown) {
  if (s != null && !(String(s) in SEVERITY)) throw new Error(`denyOnViolation must be one of ${Object.keys(SEVERITY).join(", ")} or null, not ${JSON.stringify(s)}`);
}

const denial = (eid: string | null, required: Partial<Bar>, reason: string, detail: string, observed: object = {}): Denial =>
  ({ error: "open_entity_denied", denied: true, reason, detail, eid, required, observed });

/** undefined when `eid` clears the bar, else a denial object the model can read. */
export async function evaluate(eid: string, bar: Partial<Bar> = {}, trust: TrustFn = (e) => sdkTrust(e)): Promise<Denial | undefined> {
  checkThreshold(bar.denyOnViolation);
  const b = { ...DEFAULT_BAR, ...bar };
  const deny = (reason: string, detail: string, observed?: object) => denial(eid, b, reason, detail, observed);
  try {
    const r = await trust(eid);
    if (!r.ok) return deny("trust_unavailable", `Trust could not be established (${r.error}); denied.`);
    if (r.withdrawn) return deny("withdrawn", "The entity withdrew its Declaration.");
    const tier = r.trustTier[b.tierIssuer] ?? 0;
    if (tier < b.minTier) return deny("tier_too_low", `trust_tier ${tier} from ${b.tierIssuer} is below ${b.minTier}.`, { trust_tier: tier });
    if (b.requireSma && !r.securityPosture) return deny("sma_posture_missing", "No live Secure My Agent security_posture attestation.");
    if (b.denyOnViolation) {
      const bar = SEVERITY[b.denyOnViolation];
      const hits = r.violations.filter((v) => (SEVERITY[v.severity] ?? bar) >= bar);
      if (hits.length)
        return deny("violation", `${hits.length} live ${hits[0].issuer} violation(s) at ${b.denyOnViolation} or worse.`,
          { violations: hits.map((v) => ({ severity: v.severity, policy: v.policy, sha256: v.sha256 })) });
    }
  } catch (e: any) {
    return deny("trust_unavailable", `${e?.name ?? "Error"}: ${e?.message}; denied.`);
  }
  return undefined;
}

/** Whose trust to check: the counterparty in `args`, else `eid`, else this machine's existing identity (never created). */
async function check(o: GateOptions, args: Record<string, unknown> | undefined): Promise<Denial | undefined> {
  const { counterpartyArg, eid, trust, ...bar } = o;
  let who: string | null | undefined;
  if (counterpartyArg) {
    const v = args?.[counterpartyArg];
    if (typeof v !== "string" || !v.startsWith("did:"))
      return denial(null, {}, "counterparty_missing", `Tool argument "${counterpartyArg}" must hold the other agent's EID (a DID); denied.`);
    who = v;
  } else {
    try {
      who = typeof eid === "string" ? eid : eid ? await eid() : (await Identity.load())?.did;
    } catch (e: any) {
      return denial(null, {}, "trust_unavailable", `${e?.name ?? "Error"}: ${e?.message}; denied.`);
    }
    if (!who) return denial(null, {}, "no_identity", "This agent has no Open Entity identity yet; denied.");
  }
  return evaluate(who, bar, trust);
}

/** Wrap a tool function. Below the bar it resolves to the denial object instead of running `fn`.
 * With `counterpartyArg`, the EID is read from that property of the first argument (an ADK tool's input object). */
export function openEntityVerified<A extends unknown[], R>(fn: (...args: A) => R | Promise<R>, opts: GateOptions = {}): (...args: A) => Promise<R | Denial> {
  checkThreshold(opts.denyOnViolation);
  return async (...args) => (await check(opts, args[0] as Record<string, unknown> | undefined)) ?? fn(...args);
}

/** Pass in `new InMemoryRunner({agent, appName, plugins: [...]})`. Tools named in `highRiskTools` run only if the subject
 * clears the bar: the EID in the tool argument `counterpartyArg` when set, else `eid` or this machine's existing identity. */
export class OpenEntityGate extends BasePlugin {
  readonly highRisk: Set<string>;
  private opts: GateOptions;
  constructor(highRiskTools: Iterable<string>, opts: GateOptions = {}) {
    super("openentity_gate");
    checkThreshold(opts.denyOnViolation);
    this.highRisk = new Set(highRiskTools);
    this.opts = opts;
  }
  override async beforeToolCallback({ tool, toolArgs }: { tool: BaseTool; toolArgs: Record<string, unknown>; toolContext: unknown }) {
    if (!this.highRisk.has(tool.name)) return undefined;
    return (await check(this.opts, toolArgs)) as Record<string, unknown> | undefined;
  }
}

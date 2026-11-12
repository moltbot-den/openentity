import { describe, expect, it } from "vitest";
import { SCHEMA } from "../generated/ts/events.ts";

// Every event named in PLAN 13.2, with its source. Adding to events.yaml needs a PLAN change first.
const PLAN: Record<string, "client" | "server" | "web"> = {
  app_first_opened: "client", onboarding_viewed: "client",
  sign_in_started: "client", sign_in_completed: "server", sign_in_failed: "server", new_device_sign_in_notified: "server",
  sign_in_method_linked: "server", sign_in_method_removed: "server", passkey_created: "server", owner_key_log_created: "server",
  approver_added: "server", backup_added: "server", recovery_started: "server", recovery_cancelled: "server", recovery_completed: "server",
  root_replace_started: "server", root_replaced: "server", push_permission_answered: "client", account_deleted: "server",
  pair_code_created: "server", pair_page_viewed: "web", pair_requested: "server", pair_confirmed: "server", pair_failed: "server",
  pair_code_expired: "server", product_provisioned: "server", agent_first_status: "server",
  approval_requested: "server", approval_push_sent: "server", approval_push_opened: "client", approval_viewed: "client",
  approval_decided: "server", approval_expired: "server", approval_rejected_by_verifier: "server", legacy_approval_attempted: "server", agent_auto_muted: "server",
  agent_message_sent: "server", owner_message_sent: "server", agent_status_reported: "server", command_sent: "server",
  agent_paused: "server", agent_pause_enforced: "server", agent_resumed: "server", live_activity_started: "client",
  plans_viewed: "client", purchase_started: "client", purchase_completed: "server", purchase_failed: "client", purchase_restored: "server",
  subscription_renewed: "server", subscription_cancelled: "server", subscription_refunded: "server", plan_granted: "server",
  credits_reserved: "server", credits_insufficient: "server",
  app_opened: "client",
  entity_viewed: "client", attestation_verified: "client", checkup_completed: "server", secret_added: "server", token_revoked: "server",
  evidence_filed: "server", exception_decided: "server", post_created: "server", contract_milestone_approved: "server",
  intent_invoked: "client", glasses_ask_completed: "client",
};

describe("events.yaml matches PLAN 13.2", () => {
  it("has exactly the planned events with the planned sources", () => {
    const got = Object.fromEntries(Object.entries(SCHEMA.events).map(([k, v]) => [k, v.source]));
    expect(got).toEqual(PLAN);
  });
  it("names fit GA4 (40 chars, letter first, a-z0-9_)", () => {
    for (const n of Object.keys(SCHEMA.events)) expect(n).toMatch(/^[a-z][a-z0-9_]{0,39}$/);
  });
});

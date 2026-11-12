// The SSM parameters the account function reads: /openentity/account/<name> (both stages) and <name>_<prod|staging>
// (this stage's value wins). lambda.ts reads exactly these and account-stack.ts grants exactly these, so the role
// cannot read any other parameter (the forwarder's pattern, account/analytics/forwarder/params.ts).
export const CORE_PARAMS = ["code_pepper", "cio_app_api_key", "apple_siwa_services_id", "google_oauth_ios_client_id", "google_oauth_web_client_id", "android_cert_sha256", "product_apis"];
/** The web lane's names (web/config.ts reads them). */
export const WEB_PARAMS = [
  "apns_auth_key", "apns_key_id", "apns_team_id",
  "apple_siwa_key_id", "apple_siwa_private_key",
  "turnstile_site_key", "turnstile_secret",
  "app_review_email", "app_review_code", "app_review_open",
  "test_idp_key", "test_product_keys",
  "play_push_audience", "play_push_service_account",
];
export const PARAM_NAMES = [...CORE_PARAMS, ...WEB_PARAMS];

export type Stage = "production" | "staging";
export const STAGE_SUFFIX: Record<Stage, string> = { production: "prod", staging: "staging" };
/** Both names for each parameter, under this stage's suffix only. */
export const paramNames = (stage: Stage) => PARAM_NAMES.flatMap((n) => [n, `${n}_${STAGE_SUFFIX[stage]}`]);

/** The stage a function runs as. Anything else stops it from starting: an unknown STAGE must never act as staging. */
export function stageOf(v: string | undefined): Stage {
  if (v === "production" || v === "staging") return v;
  throw new Error(`STAGE must be production or staging, not ${JSON.stringify(v)}`);
}

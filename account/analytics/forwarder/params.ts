/** The only SSM parameters the forwarder may read. The role is granted exactly these ARNs, for its own stage. */
export const SSM_PREFIX = "/openentity/account/";
const THINGS = ["amplitude_api_key", "posthog_key", "ga4_measurement_id", "ga4_api_secret"] as const;
const SHARED = ["analytics_amplitude_url", "analytics_posthog_host"] as const; // optional, no stage suffix

export const analyticsParamNames = (env: string): string[] => {
  const s = env === "production" ? "prod" : "staging";
  return [...THINGS.map((t) => `analytics_${t}_${s}`), ...SHARED];
};

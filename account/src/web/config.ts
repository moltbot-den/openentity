// Web lane settings: the SSM parameter names its modules read (lambda.ts loads them with the core names) and the
// WebConfig built from them, which reaches every module as Deps.web.
export const WEB_PARAMS: string[] = [];

export type WebConfig = Record<string, unknown>;

/** Builds the WebConfig from the SSM values by name (the stage-suffixed value already wins). */
export const webConfig = (_params: Record<string, string | undefined>): WebConfig => ({});

/** An error the API answers as JSON {error, message} with this status (openapi.yaml, Error). */
export class HttpError extends Error {
  constructor(public status: number, public code: string, message: string, public extra: Record<string, unknown> = {}) { super(message); }
}
export const fail = (status: number, code: string, message: string, extra?: Record<string, unknown>): never => { throw new HttpError(status, code, message, extra); };

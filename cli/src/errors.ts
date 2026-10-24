export const EXIT = { OK: 0, USAGE: 1, NETWORK: 2, VERIFY: 3, REJECTED: 4, STATE: 5 } as const;

export class CliError extends Error {
  constructor(public code: number, message: string) {
    super(message);
  }
}

export const usage = (m: string) => new CliError(EXIT.USAGE, m);
export const stateErr = (m: string) => new CliError(EXIT.STATE, m);

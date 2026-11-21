/**
 * A runtime session failure. `retryable` marks failures that a fresh session
 * can plausibly overcome, such as a provider error or a malformed answer, as
 * opposed to an exhausted turn budget or deadline.
 */
export class AuditSessionError extends Error {
  constructor(
    message: string,
    readonly retryable: boolean,
  ) {
    super(message);
    this.name = "AuditSessionError";
  }
}

export function isRetryable(error: unknown): boolean {
  return !(error instanceof AuditSessionError) || error.retryable;
}

// @ts-check

/** Error with a stable machine code and an HTTP status. Messages are safe to show to clients. */
export class AuthError extends Error {
  /**
   * @param {string} code
   * @param {number} status
   * @param {string} [message]
   * @param {Record<string, unknown>} [details]
   */
  constructor(code, status, message, details) {
    super(message || code);
    this.name = 'AuthError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export const errors = {
  invalidCredentials: () => new AuthError('invalid_credentials', 401, 'Invalid email or password'),
  locked: (/** @type {number} */ retryAfterSec) =>
    new AuthError('account_locked', 423, 'Too many failed attempts. Try again later.', { retryAfterSec }),
  unauthenticated: (/** @type {string} */ code = 'unauthenticated', /** @type {string} */ message = 'Authentication required') =>
    new AuthError(code, 401, message),
  forbidden: (/** @type {string} */ message = 'You do not have permission to do this', /** @type {Record<string, unknown>} */ details) =>
    new AuthError('forbidden', 403, message, details),
  notFound: (/** @type {string} */ what = 'Resource') => new AuthError('not_found', 404, `${what} not found`),
  conflict: (/** @type {string} */ code, /** @type {string} */ message) => new AuthError(code, 409, message),
  invalid: (/** @type {string} */ message, /** @type {Record<string, unknown>} */ details) =>
    new AuthError('invalid_request', 400, message, details),
};

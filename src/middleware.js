// @ts-check
import { AuthError, errors } from './errors.js';

/**
 * Express middleware bound to an AuthService.
 *
 *   const auth = createAuth(service);
 *   app.get('/invoices', auth.authenticate(), auth.authorize('billing:read'), handler);
 *   app.patch('/projects/:id', auth.authenticate(),
 *     auth.authorize('projects:update', (req) => db.projects.get(req.params.id)), handler);
 *   app.get('/admin', auth.authenticate(), auth.requireRole('admin'), handler);
 *
 * req.auth = { id, tenantId, role, teamId, email, sessionId, tokenId, expiresAt }
 *
 * @param {import('./service.js').AuthService} service
 */
export function createAuth(service) {
  /** @param {{optional?:boolean}} [o] */
  function authenticate(o = {}) {
    return function authenticateMw(/** @type {any} */ req, /** @type {any} */ _res, /** @type {any} */ next) {
      const h = req.headers?.authorization;
      if (!h) {
        if (o.optional) return next();
        return next(errors.unauthenticated('unauthenticated', 'Missing Authorization: Bearer <token> header'));
      }
      const m = /^Bearer\s+(\S+)$/i.exec(h);
      if (!m) return next(errors.unauthenticated('token_malformed', 'Authorization header must be "Bearer <token>"'));
      try {
        req.auth = service.authenticate(m[1]);
        next();
      } catch (e) {
        next(e);
      }
    };
  }

  /**
   * Require "resource:action". The optional resolver loads the target object (sync or async) so
   * own / team / tenant scopes are enforced against it; it may return null -> 404.
   * The decision is stored on req.authz = { allowed, scope, reason }.
   * @param {string} permission
   * @param {(req:any) => any} [resolveTarget]
   */
  function authorize(permission, resolveTarget) {
    return async function authorizeMw(/** @type {any} */ req, /** @type {any} */ _res, /** @type {any} */ next) {
      try {
        if (!req.auth) throw errors.unauthenticated();
        let target;
        if (resolveTarget) {
          target = await resolveTarget(req);
          if (target == null) throw errors.notFound();
          if (target.tenantId && target.tenantId !== req.auth.tenantId) throw errors.notFound();
          req.target = target;
        }
        req.authz = service.assert(req.auth, permission, target, { ip: req.ip });
        next();
      } catch (e) {
        next(e);
      }
    };
  }

  /** Require a minimum role level (e.g. requireRole('manager') lets managers and admins through). */
  function requireRole(/** @type {string} */ role) {
    if (!service.policy.hasRole(role)) throw new Error(`requireRole: unknown role "${role}"`);
    const min = service.policy.level(role);
    return function requireRoleMw(/** @type {any} */ req, /** @type {any} */ _res, /** @type {any} */ next) {
      if (!req.auth) return next(errors.unauthenticated());
      if (service.policy.level(req.auth.role) < min) return next(errors.forbidden(`Requires role ${role} or higher`, { reason: 'role_level' }));
      next();
    };
  }

  return { authenticate, authorize, requireRole };
}

/** JSON error handler: { error: { code, message, details? } }. Unknown errors become 500 without leaking internals. */
export function errorHandler(/** @type {{log?: (e:unknown)=>void}} */ o = {}) {
  return function authzErrorHandler(/** @type {any} */ err, /** @type {any} */ _req, /** @type {any} */ res, /** @type {any} */ _next) {
    if (err?.type === 'entity.parse.failed') err = errors.invalid('Request body is not valid JSON');
    if (err?.type === 'entity.too.large') err = new AuthError('payload_too_large', 413, 'Request body too large');
    if (!(err instanceof AuthError)) {
      (o.log || console.error)(err);
      return res.status(500).json({ error: { code: 'internal_error', message: 'Internal server error' } });
    }
    if (err.status === 401) res.set('WWW-Authenticate', `Bearer error="invalid_token", error_description="${err.code}"`);
    if (err.code === 'account_locked' && err.details?.retryAfterSec) res.set('Retry-After', String(err.details.retryAfterSec));
    const body = { error: { code: err.code, message: err.message, ...(err.details ? { details: err.details } : {}) } };
    res.status(err.status).json(body);
  };
}

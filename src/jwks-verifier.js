// @ts-check
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { AuthError } from './errors.js';
import { ACCESS_TYP } from './tokens.js';
import { Policy, DEFAULT_POLICY } from './policy.js';

/**
 * Verify access tokens in ANOTHER service (billing API, worker, microservice) using only the public
 * JWKS of the auth server - no database and no signing secret needed.
 *
 *   const verifier = createJwksVerifier({ jwksUri: 'https://auth.acme.com/.well-known/jwks.json', issuer: 'https://auth.acme.com', audience: 'saas-api' });
 *   app.use('/api', verifier.middleware());
 *   app.get('/api/reports', verifier.authorize('reports:read'), handler);
 *
 * Trade-off: this is stateless, so a revoked token is accepted until it expires (max access TTL,
 * 15 min by default). Endpoints that must react instantly (money, deletes) should call the auth
 * server or use the engine's own authenticate().
 *
 * @param {{jwksUri:string, issuer:string, audience:string, algorithms?:string[], cacheSec?:number, minRefetchSec?:number, policy?:import('./policy.js').PolicyDoc, fetch?:typeof fetch, clockToleranceSec?:number}} o
 */
export function createJwksVerifier(o) {
  const algorithms = o.algorithms || ['ES256', 'RS256'];
  const cacheMs = (o.cacheSec ?? 600) * 1000;
  const minRefetchMs = (o.minRefetchSec ?? 5) * 1000;
  const doFetch = o.fetch || fetch;
  const policy = new Policy(o.policy || DEFAULT_POLICY);
  /** @type {Map<string, {key:crypto.KeyObject, alg:string}>} */
  let keys = new Map();
  let fetchedAt = 0;
  /** @type {Promise<void>|null} */
  let inflight = null;

  async function refresh() {
    if (!inflight) {
      inflight = (async () => {
        const res = await doFetch(o.jwksUri, { signal: AbortSignal.timeout(5000) });
        if (!res.ok) throw new Error(`JWKS fetch failed: HTTP ${res.status}`);
        const body = /** @type {any} */ (await res.json());
        const next = new Map();
        for (const k of body.keys || []) {
          if (!k.kid || !algorithms.includes(k.alg)) continue;
          next.set(k.kid, { key: crypto.createPublicKey({ key: k, format: 'jwk' }), alg: k.alg });
        }
        keys = next;
        fetchedAt = Date.now();
      })().finally(() => {
        inflight = null;
      });
    }
    return inflight;
  }

  /** @param {string} token */
  async function verify(token) {
    const d = jwt.decode(String(token || ''), { complete: true });
    if (!d || typeof d.payload !== 'object') throw new AuthError('token_malformed', 401, 'Malformed token');
    if (d.header.typ !== ACCESS_TYP) throw new AuthError('token_invalid', 401, 'Not an access token');
    const kid = d.header.kid || '';
    // unknown kid -> the auth server may have rotated: refetch, but at most every minRefetchSec
    // so tokens with random kids cannot turn this service into a JWKS request flood
    if (Date.now() - fetchedAt > cacheMs || (!keys.has(kid) && Date.now() - fetchedAt >= minRefetchMs)) await refresh();
    const k = keys.get(kid);
    if (!k || k.alg !== d.header.alg) throw new AuthError('token_invalid', 401, 'Token signed with an unknown key');
    try {
      return /** @type {any} */ (jwt.verify(token, k.key, { algorithms: [/** @type {jwt.Algorithm} */ (k.alg)], issuer: o.issuer, audience: o.audience, clockTolerance: o.clockToleranceSec ?? 5 }));
    } catch (e) {
      if (e instanceof jwt.TokenExpiredError) throw new AuthError('token_expired', 401, 'Token expired');
      throw new AuthError('token_invalid', 401, 'Invalid token');
    }
  }

  return {
    verify,
    /** Express middleware: sets req.auth = { id, tenantId, role, teamId, sessionId } from the token claims. */
    middleware() {
      return async (/** @type {any} */ req, /** @type {any} */ _res, /** @type {any} */ next) => {
        try {
          const m = /^Bearer\s+(\S+)$/i.exec(req.headers.authorization || '');
          if (!m) throw new AuthError('unauthenticated', 401, 'Missing Authorization: Bearer <token> header');
          const c = await verify(m[1]);
          req.auth = { id: c.sub, tenantId: c.tid, role: c.role, teamId: c.team ?? null, sessionId: c.sid };
          next();
        } catch (e) {
          next(e);
        }
      };
    },
    /** Same rules as the engine's authorize(), evaluated locally from the role claim. */
    authorize(/** @type {string} */ permission, /** @type {(req:any)=>any} */ resolveTarget) {
      return async (/** @type {any} */ req, /** @type {any} */ _res, /** @type {any} */ next) => {
        try {
          if (!req.auth) throw new AuthError('unauthenticated', 401, 'Authentication required');
          const target = resolveTarget ? await resolveTarget(req) : undefined;
          if (resolveTarget && (target == null || (target.tenantId && target.tenantId !== req.auth.tenantId))) throw new AuthError('not_found', 404, 'Resource not found');
          const d = policy.check(req.auth, permission, target);
          if (!d.allowed) throw new AuthError('forbidden', 403, 'You do not have permission to do this', { permission, reason: d.reason });
          req.authz = d;
          next();
        } catch (e) {
          next(e);
        }
      };
    },
  };
}

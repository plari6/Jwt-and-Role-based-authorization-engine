// @ts-check
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { AuthError } from './errors.js';

export const ACCESS_TYP = 'at+jwt';

/**
 * Access tokens: short-lived signed JWTs.
 * Claims: iss, aud, sub (user id), tid (tenant), role, team, tv (token version), sid (session), jti, iat, exp.
 * Verification pins the algorithm, the key id, issuer, audience and the "at+jwt" type, so tokens forged
 * with alg=none, HS256-with-public-key, a foreign issuer or another API's audience are all rejected.
 */
export class TokenService {
  /**
   * @param {{keys: import('./keys.js').KeyStore, issuer:string, audience:string, accessTtlSec:number, clockToleranceSec?:number}} opts
   */
  constructor(opts) {
    this.keys = opts.keys;
    this.issuer = opts.issuer;
    this.audience = opts.audience;
    this.ttl = opts.accessTtlSec;
    this.tolerance = opts.clockToleranceSec ?? 5;
    this.alg = /** @type {jwt.Algorithm} */ (opts.keys.alg);
  }

  /**
   * @param {{id:string, tenantId:string, role:string, teamId?:string|null, tokenVersion:number}} user
   * @param {{sessionId:string}} ctx
   */
  signAccess(user, ctx) {
    const { kid, key } = this.keys.signingKey();
    const payload = { tid: user.tenantId, role: user.role, team: user.teamId || undefined, tv: user.tokenVersion, sid: ctx.sessionId };
    const token = jwt.sign(payload, key, {
      algorithm: this.alg,
      keyid: kid,
      issuer: this.issuer,
      audience: this.audience,
      subject: user.id,
      expiresIn: this.ttl,
      jwtid: crypto.randomUUID(),
      header: { alg: this.alg, typ: ACCESS_TYP, kid },
    });
    return { token, expiresIn: this.ttl };
  }

  /**
   * Cryptographic + claim verification only (no database). Throws AuthError.
   * @param {string} token
   * @returns {{sub:string, tid:string, role:string, team?:string, tv:number, sid:string, jti:string, iat:number, exp:number, iss:string, aud:string}}
   */
  verifyAccess(token) {
    if (typeof token !== 'string' || token.length > 8192 || token.split('.').length !== 3) throw new AuthError('token_malformed', 401, 'Malformed token');
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || typeof decoded.payload !== 'object') throw new AuthError('token_malformed', 401, 'Malformed token');
    const h = decoded.header;
    if (h.alg !== this.alg) throw new AuthError('token_invalid', 401, `Token algorithm ${h.alg} is not accepted`);
    if (h.typ !== ACCESS_TYP) throw new AuthError('token_invalid', 401, 'Not an access token');
    const key = this.keys.verifyKey(h.kid);
    if (!key) throw new AuthError('token_invalid', 401, 'Token signed with an unknown key');
    try {
      const p = /** @type {any} */ (
        jwt.verify(token, key, { algorithms: [this.alg], issuer: this.issuer, audience: this.audience, clockTolerance: this.tolerance })
      );
      if (!p.sub || !p.tid || !p.role || typeof p.tv !== 'number' || !p.sid) throw new AuthError('token_invalid', 401, 'Token is missing required claims');
      return p;
    } catch (e) {
      if (e instanceof AuthError) throw e;
      if (e instanceof jwt.TokenExpiredError) throw new AuthError('token_expired', 401, 'Token expired');
      if (e instanceof jwt.NotBeforeError) throw new AuthError('token_invalid', 401, 'Token not yet valid');
      throw new AuthError('token_invalid', 401, 'Invalid token');
    }
  }
}

/** Opaque refresh token: 256 random bits. Only its SHA-256 is stored. */
export function newRefreshToken() {
  const token = 'rt_' + crypto.randomBytes(32).toString('base64url');
  return { token, hash: hashRefreshToken(token) };
}

export function hashRefreshToken(/** @type {string} */ token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

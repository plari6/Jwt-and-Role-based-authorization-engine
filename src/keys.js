// @ts-check
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

/**
 * Signing key store with rotation.
 * keys/keyset.json holds private JWKs - never commit it, never serve it.
 *   active    signs new tokens
 *   retiring  no longer signs, still verifies tokens issued before rotation
 * Public keys are published as JWKS so other services verify tokens without any secret.
 */

/** @typedef {{kid:string, alg:'ES256'|'RS256', status:'active'|'retiring', createdAt:string, retiredAt?:string, privateJwk:crypto.JsonWebKey, publicJwk:crypto.JsonWebKey}} StoredKey */

export class KeyStore {
  /**
   * @param {{alg:'ES256'|'RS256'|'HS256', dir?:string, hsSecret?:string, memory?:boolean}} opts
   */
  constructor(opts) {
    this.alg = opts.alg;
    this.dir = opts.dir;
    this.memory = Boolean(opts.memory) || !opts.dir;
    /** @type {StoredKey[]} */
    this.keys = [];
    /** @type {Map<string, {private?:crypto.KeyObject, public:crypto.KeyObject}>} */
    this.cache = new Map();
    this.lastCheck = 0;
    /** @type {number|undefined} */
    this.mtime = undefined;
    if (this.alg === 'HS256') {
      const secret = opts.hsSecret || process.env.AUTHZ_HS_SECRET || '';
      if (Buffer.byteLength(secret) < 32) throw new Error('HS256 needs AUTHZ_HS_SECRET of at least 32 bytes (openssl rand -base64 48)');
      const key = crypto.createSecretKey(Buffer.from(secret, 'utf8'));
      this.hsKid = 'hs-' + crypto.createHash('sha256').update(secret).digest('base64url').slice(0, 8);
      this.cache.set(this.hsKid, { private: key, public: key });
    }
  }

  get file() {
    return this.dir ? path.join(this.dir, 'keyset.json') : '';
  }

  /** Load keys from disk; create the first key when none exist (asymmetric algorithms only). */
  load({ create = true } = {}) {
    if (this.alg === 'HS256') return this;
    if (!this.memory && fs.existsSync(this.file)) {
      const data = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      this.keys = data.keys || [];
      this.mtime = fs.statSync(this.file).mtimeMs;
    }
    this.keys = this.keys.filter((k) => k.alg === this.alg);
    if (!this.keys.some((k) => k.status === 'active')) {
      if (!create) throw new Error(`No active ${this.alg} signing key in ${this.file || 'memory'} - run "authz keys rotate"`);
      this.rotate();
    }
    this.cache.clear();
    return this;
  }

  #save() {
    if (this.memory) return;
    fs.mkdirSync(/** @type {string} */ (this.dir), { recursive: true });
    const tmp = this.file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify({ alg: this.alg, keys: this.keys }, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
    this.mtime = fs.statSync(this.file).mtimeMs;
  }

  /** Create a new active key; the old active key becomes "retiring" so its tokens keep verifying. */
  rotate() {
    if (this.alg === 'HS256') throw new Error('HS256 keys come from AUTHZ_HS_SECRET; rotate by changing the secret (all sessions must log in again)');
    const pair =
      this.alg === 'ES256'
        ? crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
        : crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const publicJwk = pair.publicKey.export({ format: 'jwk' });
    const kid = crypto.createHash('sha256').update(JSON.stringify(publicJwk)).digest('base64url').slice(0, 16);
    const now = new Date().toISOString();
    for (const k of this.keys) if (k.status === 'active') Object.assign(k, { status: 'retiring', retiredAt: now });
    this.keys.push({ kid, alg: /** @type {'ES256'|'RS256'} */ (this.alg), status: 'active', createdAt: now, privateJwk: pair.privateKey.export({ format: 'jwk' }), publicJwk });
    this.cache.clear();
    this.#save();
    return kid;
  }

  /** Remove retiring keys older than maxAgeSec (default: they can no longer have live access tokens). */
  prune(/** @type {number} */ maxAgeSec) {
    const cutoff = Date.now() - maxAgeSec * 1000;
    const before = this.keys.length;
    this.keys = this.keys.filter((k) => k.status === 'active' || !k.retiredAt || Date.parse(k.retiredAt) > cutoff);
    this.cache.clear();
    this.#save();
    return before - this.keys.length;
  }

  /**
   * Pick up `authz keys rotate` from another process (CLI, other replicas sharing the keys folder)
   * without a restart: re-read keyset.json when its mtime changes, checked at most every 5 s.
   */
  #maybeReload() {
    if (this.memory || this.alg === 'HS256') return;
    const t = Date.now();
    if (this.lastCheck && t - this.lastCheck < 5000) return;
    this.lastCheck = t;
    try {
      const m = fs.statSync(this.file).mtimeMs;
      if (this.mtime === undefined) this.mtime = m;
      else if (m !== this.mtime) {
        const data = JSON.parse(fs.readFileSync(this.file, 'utf8'));
        const keys = (data.keys || []).filter((/** @type {StoredKey} */ k) => k.alg === this.alg);
        if (keys.some((/** @type {StoredKey} */ k) => k.status === 'active')) {
          this.keys = keys;
          this.cache.clear();
        }
        this.mtime = m;
      }
    } catch {
      /* keep the keys already in memory */
    }
  }

  /** @returns {{kid:string, key:crypto.KeyObject}} */
  signingKey() {
    this.#maybeReload();
    if (this.alg === 'HS256') return { kid: /** @type {string} */ (this.hsKid), key: /** @type {crypto.KeyObject} */ (this.cache.get(/** @type {string} */ (this.hsKid))?.private) };
    const k = this.keys.find((x) => x.status === 'active');
    if (!k) throw new Error('no active signing key');
    return { kid: k.kid, key: this.#objects(k).private };
  }

  /** Verification key for a kid, or null for unknown kids. */
  verifyKey(/** @type {string|undefined} */ kid) {
    if (!kid) return null;
    this.#maybeReload();
    if (this.alg === 'HS256') return kid === this.hsKid ? this.cache.get(kid)?.public ?? null : null;
    const k = this.keys.find((x) => x.kid === kid);
    return k ? this.#objects(k).public : null;
  }

  /** @param {StoredKey} k */
  #objects(k) {
    let o = this.cache.get(k.kid);
    if (!o) {
      o = {
        private: crypto.createPrivateKey({ key: /** @type {any} */ (k.privateJwk), format: 'jwk' }),
        public: crypto.createPublicKey({ key: /** @type {any} */ (k.publicJwk), format: 'jwk' }),
      };
      this.cache.set(k.kid, o);
    }
    return /** @type {{private:crypto.KeyObject, public:crypto.KeyObject}} */ (o);
  }

  /** Public JWKS document (safe to publish). Empty for HS256. */
  jwks() {
    this.#maybeReload();
    return {
      keys: this.keys.map((k) => ({ ...k.publicJwk, kid: k.kid, alg: k.alg, use: 'sig' })),
    };
  }

  list() {
    if (this.alg === 'HS256') return [{ kid: this.hsKid, alg: 'HS256', status: 'active', createdAt: '-' }];
    return this.keys.map(({ kid, alg, status, createdAt, retiredAt }) => ({ kid, alg, status, createdAt, retiredAt: retiredAt || '' }));
  }
}

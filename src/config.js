// @ts-check
import fs from 'node:fs';
import path from 'node:path';

/**
 * @typedef {object} Config
 * @property {string} issuer
 * @property {string} audience
 * @property {'ES256'|'RS256'|'HS256'} algorithm
 * @property {number} accessTtlSec
 * @property {number} refreshTtlDays
 * @property {number} refreshIdleDays   refresh token unused this long -> session expires
 * @property {string} dbPath
 * @property {string} keysDir
 * @property {string} policyFile
 * @property {number} bcryptRounds
 * @property {string} pepper
 * @property {{minLength:number, maxLength:number, blockCommon:boolean, requireClasses:number}} passwordPolicy
 * @property {{maxAttempts:number, lockMinutes:number}} lockout
 * @property {{loginPerIpPerMin:number, trustProxy:number|false, port:number, allowSignup:boolean, corsOrigins:string[]}} server
 * @property {number} clockToleranceSec
 * @property {string} baseDir
 */

export const DEFAULTS = Object.freeze({
  issuer: 'http://localhost:4000',
  audience: 'saas-api',
  algorithm: 'ES256',
  accessTtlSec: 900,
  refreshTtlDays: 30,
  refreshIdleDays: 7,
  dbPath: './data/authz.db',
  keysDir: './keys',
  policyFile: './policy.json',
  bcryptRounds: 12,
  pepper: '',
  passwordPolicy: { minLength: 10, maxLength: 128, blockCommon: true, requireClasses: 2 },
  lockout: { maxAttempts: 5, lockMinutes: 15 },
  server: { loginPerIpPerMin: 20, trustProxy: false, port: 4000, allowSignup: false, corsOrigins: [] },
  clockToleranceSec: 5,
});

/** Parse "15m", "1h", "900", "7d" into seconds. */
export function parseDuration(/** @type {string|number} */ v) {
  if (typeof v === 'number') return v;
  const m = /^(\d+)\s*(s|m|h|d)?$/i.exec(String(v).trim());
  if (!m) throw new Error(`Invalid duration "${v}" (use e.g. 900, 15m, 1h, 7d)`);
  const n = Number(m[1]);
  const unit = (m[2] || 's').toLowerCase();
  return n * { s: 1, m: 60, h: 3600, d: 86400 }[/** @type {'s'|'m'|'h'|'d'} */ (unit)];
}

/**
 * Load config: defaults <- authz.config.json <- environment <- overrides.
 * Relative paths resolve against the config file's folder (or cwd).
 * `isolated: true` ignores authz.config.json and the environment (tests, demo).
 * @param {{file?: string, overrides?: Partial<Config> & Record<string, any>, env?: NodeJS.ProcessEnv, isolated?: boolean}} [opts]
 * @returns {Config}
 */
export function loadConfig(opts = {}) {
  const env = opts.isolated ? {} : opts.env || process.env;
  const file = opts.isolated ? '\0none' : opts.file || env.AUTHZ_CONFIG || 'authz.config.json';
  const abs = opts.isolated ? '' : path.resolve(file);
  /** @type {Record<string, any>} */
  let fromFile = {};
  if (abs && fs.existsSync(abs)) {
    try {
      fromFile = JSON.parse(fs.readFileSync(abs, 'utf8'));
    } catch (e) {
      throw new Error(`Cannot parse ${abs}: ${/** @type {Error} */ (e).message}`);
    }
  } else if (opts.file) {
    throw new Error(`Config file not found: ${abs}`);
  }
  const baseDir = abs && fs.existsSync(abs) ? path.dirname(abs) : process.cwd();

  /** @type {Record<string, any>} */
  const fromEnv = {};
  if (env.AUTHZ_ISSUER) fromEnv.issuer = env.AUTHZ_ISSUER;
  if (env.AUTHZ_AUDIENCE) fromEnv.audience = env.AUTHZ_AUDIENCE;
  if (env.AUTHZ_ALGORITHM) fromEnv.algorithm = env.AUTHZ_ALGORITHM;
  if (env.AUTHZ_ACCESS_TTL) fromEnv.accessTtlSec = parseDuration(env.AUTHZ_ACCESS_TTL);
  if (env.AUTHZ_DB) fromEnv.dbPath = env.AUTHZ_DB;
  if (env.AUTHZ_KEYS_DIR) fromEnv.keysDir = env.AUTHZ_KEYS_DIR;
  if (env.AUTHZ_POLICY) fromEnv.policyFile = env.AUTHZ_POLICY;
  if (env.AUTHZ_PEPPER) fromEnv.pepper = env.AUTHZ_PEPPER;
  if (env.AUTHZ_BCRYPT_ROUNDS) fromEnv.bcryptRounds = Number(env.AUTHZ_BCRYPT_ROUNDS);
  const server = {};
  if (env.PORT) /** @type {any} */ (server).port = Number(env.PORT);
  if (env.AUTHZ_TRUST_PROXY) /** @type {any} */ (server).trustProxy = Number(env.AUTHZ_TRUST_PROXY);
  if (env.AUTHZ_ALLOW_SIGNUP) /** @type {any} */ (server).allowSignup = env.AUTHZ_ALLOW_SIGNUP === 'true';
  if (env.AUTHZ_CORS_ORIGINS) /** @type {any} */ (server).corsOrigins = env.AUTHZ_CORS_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean);

  const o = opts.overrides || {};
  /** @type {any} */
  const c = {
    ...DEFAULTS,
    ...fromFile,
    ...fromEnv,
    ...o,
    passwordPolicy: { ...DEFAULTS.passwordPolicy, ...fromFile.passwordPolicy, ...o.passwordPolicy },
    lockout: { ...DEFAULTS.lockout, ...fromFile.lockout, ...o.lockout },
    server: { ...DEFAULTS.server, ...fromFile.server, ...server, ...o.server },
    baseDir,
  };
  if (fromFile.accessTtl && !fromEnv.accessTtlSec && !o.accessTtlSec) c.accessTtlSec = parseDuration(fromFile.accessTtl);

  const resolve = (/** @type {string} */ p) => (p === ':memory:' || path.isAbsolute(p) ? p : path.resolve(baseDir, p));
  c.dbPath = resolve(c.dbPath);
  c.keysDir = resolve(c.keysDir);
  c.policyFile = resolve(c.policyFile);
  validateConfig(c);
  return c;
}

/** @param {Config} c */
export function validateConfig(c) {
  const problems = [];
  if (!['ES256', 'RS256', 'HS256'].includes(c.algorithm)) problems.push(`algorithm must be ES256, RS256 or HS256 (got ${c.algorithm})`);
  if (!(c.accessTtlSec >= 30 && c.accessTtlSec <= 86400)) problems.push('accessTtlSec must be between 30 and 86400');
  if (!(c.refreshTtlDays >= 1 && c.refreshTtlDays <= 365)) problems.push('refreshTtlDays must be between 1 and 365');
  if (!(c.bcryptRounds >= 4 && c.bcryptRounds <= 15)) problems.push('bcryptRounds must be between 4 and 15');
  if (!c.issuer) problems.push('issuer is required');
  if (!c.audience) problems.push('audience is required');
  if (problems.length) throw new Error(`Invalid config:\n - ${problems.join('\n - ')}`);
}

/** Warnings that do not stop the engine but matter in production. */
export function configWarnings(/** @type {Config} */ c, /** @type {NodeJS.ProcessEnv} */ env = process.env) {
  const w = [];
  if (c.bcryptRounds < 10) w.push(`bcryptRounds=${c.bcryptRounds} is weak for production (use 12)`);
  if (c.accessTtlSec > 3600) w.push(`access tokens live ${c.accessTtlSec}s - keep them short (5-15 min); refresh tokens handle long sessions`);
  if (c.algorithm === 'HS256') w.push('HS256 means every service that verifies tokens holds the signing secret; prefer ES256 + JWKS');
  if (c.issuer.startsWith('http://') && !/localhost|127\.0\.0\.1/.test(c.issuer)) w.push('issuer uses http:// - serve the API over HTTPS');
  if (!c.pepper) w.push('no AUTHZ_PEPPER set - a pepper keeps leaked DB hashes useless without the server secret');
  if (env.NODE_ENV === 'production' && c.server.trustProxy === false) w.push('NODE_ENV=production but trustProxy is off - behind a load balancer every client shares one IP for rate limits');
  return w;
}

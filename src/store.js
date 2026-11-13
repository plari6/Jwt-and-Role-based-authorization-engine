// @ts-check
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

/**
 * SQLite storage (built into Node 22.13+, no native add-on).
 * Tables: tenants, users, sessions (one row per refresh-token family), refresh_tokens, projects (example
 * protected resource), audit.
 */

/** @typedef {{id:string, tenantId:string, email:string, name:string, passwordHash:string, role:string, teamId:string|null, status:'active'|'disabled', tokenVersion:number, failedAttempts:number, lockedUntil:number, lastLoginAt:string|null, createdAt:string, updatedAt:string}} UserRow */

const SCHEMA = `
CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL,
  team_id TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  token_version INTEGER NOT NULL DEFAULT 1,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  last_login_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, email)
);
CREATE INDEX IF NOT EXISTS users_email ON users(email);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tenant_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_used_at TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at TEXT,
  revoke_reason TEXT,
  ip TEXT,
  user_agent TEXT
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  hash TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER
);
CREATE INDEX IF NOT EXISTS refresh_session ON refresh_tokens(session_id);
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  owner_id TEXT NOT NULL,
  team_id TEXT,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS projects_tenant ON projects(tenant_id);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  tenant_id TEXT,
  actor_id TEXT,
  action TEXT NOT NULL,
  target_id TEXT,
  outcome TEXT NOT NULL,
  ip TEXT,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS audit_tenant_at ON audit(tenant_id, at);
`;

const now = () => new Date().toISOString();

/** @param {any} r @returns {UserRow|null} */
function mapUser(r) {
  if (!r) return null;
  return {
    id: r.id,
    tenantId: r.tenant_id,
    email: r.email,
    name: r.name,
    passwordHash: r.password_hash,
    role: r.role,
    teamId: r.team_id ?? null,
    status: r.status,
    tokenVersion: r.token_version,
    failedAttempts: r.failed_attempts,
    lockedUntil: r.locked_until,
    lastLoginAt: r.last_login_at ?? null,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

/** @param {any} r */
function mapProject(r) {
  return r ? { id: r.id, tenantId: r.tenant_id, ownerId: r.owner_id, teamId: r.team_id ?? null, name: r.name, createdAt: r.created_at, updatedAt: r.updated_at } : null;
}

export class Store {
  /** @param {string} file path or ":memory:" */
  constructor(file) {
    if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
    this.db = new DatabaseSync(file);
    this.db.exec('PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
    if (file !== ':memory:') this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec(SCHEMA);
    /** @type {Map<string, import('node:sqlite').StatementSync>} */
    this.stmts = new Map();
  }

  /** Cached prepared statement. */
  q(/** @type {string} */ sql) {
    let s = this.stmts.get(sql);
    if (!s) {
      s = this.db.prepare(sql);
      this.stmts.set(sql, s);
    }
    return s;
  }

  /** Run fn inside a transaction (synchronous fn only). */
  tx(/** @type {() => any} */ fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const out = fn();
      this.db.exec('COMMIT');
      return out;
    } catch (e) {
      this.db.exec('ROLLBACK');
      throw e;
    }
  }

  close() {
    this.db.close();
  }

  // ---- tenants
  createTenant(/** @type {{slug:string, name:string}} */ t) {
    const row = { id: crypto.randomUUID(), slug: t.slug, name: t.name, created_at: now() };
    this.q('INSERT INTO tenants (id, slug, name, created_at) VALUES (?, ?, ?, ?)').run(row.id, row.slug, row.name, row.created_at);
    return { id: row.id, slug: row.slug, name: row.name, createdAt: row.created_at };
  }
  tenantBySlug(/** @type {string} */ slug) {
    const r = /** @type {any} */ (this.q('SELECT * FROM tenants WHERE slug = ?').get(slug));
    return r ? { id: r.id, slug: r.slug, name: r.name, createdAt: r.created_at } : null;
  }
  tenantById(/** @type {string} */ id) {
    const r = /** @type {any} */ (this.q('SELECT * FROM tenants WHERE id = ?').get(id));
    return r ? { id: r.id, slug: r.slug, name: r.name, createdAt: r.created_at } : null;
  }
  listTenants() {
    return /** @type {any[]} */ (
      this.q('SELECT t.id, t.slug, t.name, t.created_at AS createdAt, COUNT(u.id) AS users FROM tenants t LEFT JOIN users u ON u.tenant_id = t.id GROUP BY t.id ORDER BY t.created_at').all()
    );
  }

  // ---- users
  /** @param {{tenantId:string, email:string, name?:string, passwordHash:string, role:string, teamId?:string|null}} u */
  createUser(u) {
    const id = crypto.randomUUID();
    const t = now();
    this.q(
      'INSERT INTO users (id, tenant_id, email, name, password_hash, role, team_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    ).run(id, u.tenantId, u.email, u.name || '', u.passwordHash, u.role, u.teamId ?? null, t, t);
    return /** @type {UserRow} */ (this.userById(id));
  }
  userById(/** @type {string} */ id) {
    return mapUser(this.q('SELECT * FROM users WHERE id = ?').get(id));
  }
  userByEmail(/** @type {string} */ tenantId, /** @type {string} */ email) {
    return mapUser(this.q('SELECT * FROM users WHERE tenant_id = ? AND email = ?').get(tenantId, email));
  }
  /** All accounts with this email across tenants (login without tenant slug). */
  usersByEmail(/** @type {string} */ email) {
    return /** @type {UserRow[]} */ (this.q('SELECT * FROM users WHERE email = ?').all(email).map(mapUser));
  }
  /** @param {string} tenantId @param {{teamId?:string|null, role?:string, status?:string}} [f] */
  listUsers(tenantId, f = {}) {
    let sql = 'SELECT * FROM users WHERE tenant_id = ?';
    /** @type {any[]} */
    const args = [tenantId];
    if (f.teamId !== undefined) {
      sql += ' AND team_id IS ?';
      args.push(f.teamId);
    }
    if (f.role) {
      sql += ' AND role = ?';
      args.push(f.role);
    }
    if (f.status) {
      sql += ' AND status = ?';
      args.push(f.status);
    }
    return /** @type {UserRow[]} */ (this.q(sql + ' ORDER BY created_at').all(...args).map(mapUser));
  }
  countActiveWithRoles(/** @type {string} */ tenantId, /** @type {string[]} */ roles) {
    if (!roles.length) return 0;
    const r = /** @type {any} */ (
      this.db.prepare(`SELECT COUNT(*) AS n FROM users WHERE tenant_id = ? AND status = 'active' AND role IN (${roles.map(() => '?').join(',')})`).get(tenantId, ...roles)
    );
    return r.n;
  }
  /** @param {string} id @param {Partial<{name:string, role:string, teamId:string|null, status:string, passwordHash:string}>} patch @param {{bumpTokenVersion?:boolean}} [o] */
  updateUser(id, patch, o = {}) {
    const cols = { name: 'name', role: 'role', teamId: 'team_id', status: 'status', passwordHash: 'password_hash' };
    const sets = [];
    /** @type {any[]} */
    const args = [];
    for (const [k, col] of Object.entries(cols)) {
      if (Object.hasOwn(patch, k)) {
        sets.push(`${col} = ?`);
        args.push(/** @type {any} */ (patch)[k] ?? null);
      }
    }
    if (o.bumpTokenVersion) sets.push('token_version = token_version + 1');
    sets.push('updated_at = ?');
    args.push(now(), id);
    this.db.prepare(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`).run(...args);
    return this.userById(id);
  }
  recordFailedLogin(/** @type {string} */ id, /** @type {number} */ maxAttempts, /** @type {number} */ lockMs) {
    const u = this.userById(id);
    if (!u) return null;
    const attempts = u.failedAttempts + 1;
    const lockedUntil = attempts >= maxAttempts ? Date.now() + lockMs * Math.min(8, 2 ** Math.floor((attempts - maxAttempts) / maxAttempts)) : u.lockedUntil;
    this.q('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?').run(attempts, lockedUntil, id);
    return { attempts, lockedUntil };
  }
  recordSuccessfulLogin(/** @type {string} */ id) {
    this.q('UPDATE users SET failed_attempts = 0, locked_until = 0, last_login_at = ? WHERE id = ?').run(now(), id);
  }
  unlockUser(/** @type {string} */ id) {
    this.q('UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?').run(id);
  }
  deleteUser(/** @type {string} */ id) {
    this.q('DELETE FROM users WHERE id = ?').run(id);
  }

  // ---- sessions & refresh tokens
  /** @param {{userId:string, tenantId:string, expiresAt:number, ip?:string|null, userAgent?:string|null}} s */
  createSession(s) {
    const id = crypto.randomUUID();
    const t = now();
    this.q('INSERT INTO sessions (id, user_id, tenant_id, created_at, last_used_at, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(
      id, s.userId, s.tenantId, t, t, s.expiresAt, s.ip ?? null, (s.userAgent ?? '').slice(0, 200) || null,
    );
    return id;
  }
  sessionById(/** @type {string} */ id) {
    const r = /** @type {any} */ (this.q('SELECT * FROM sessions WHERE id = ?').get(id));
    return r
      ? { id: r.id, userId: r.user_id, tenantId: r.tenant_id, createdAt: r.created_at, lastUsedAt: r.last_used_at, expiresAt: r.expires_at, revokedAt: r.revoked_at, revokeReason: r.revoke_reason, ip: r.ip, userAgent: r.user_agent }
      : null;
  }
  listSessions(/** @type {string} */ userId, { includeRevoked = false } = {}) {
    const sql = includeRevoked
      ? 'SELECT * FROM sessions WHERE user_id = ? ORDER BY last_used_at DESC'
      : 'SELECT * FROM sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ? ORDER BY last_used_at DESC';
    const rows = includeRevoked ? this.q(sql).all(userId) : this.q(sql).all(userId, Date.now());
    return rows.map((r) => this.sessionById(/** @type {any} */ (r).id));
  }
  touchSession(/** @type {string} */ id) {
    this.q('UPDATE sessions SET last_used_at = ? WHERE id = ?').run(now(), id);
  }
  revokeSession(/** @type {string} */ id, /** @type {string} */ reason) {
    this.q('UPDATE sessions SET revoked_at = ?, revoke_reason = ? WHERE id = ? AND revoked_at IS NULL').run(now(), reason, id);
  }
  revokeUserSessions(/** @type {string} */ userId, /** @type {string} */ reason) {
    return Number(this.q('UPDATE sessions SET revoked_at = ?, revoke_reason = ? WHERE user_id = ? AND revoked_at IS NULL').run(now(), reason, userId).changes);
  }
  addRefreshToken(/** @type {{hash:string, sessionId:string, expiresAt:number}} */ t) {
    this.q('INSERT INTO refresh_tokens (hash, session_id, created_at, expires_at) VALUES (?, ?, ?, ?)').run(t.hash, t.sessionId, Date.now(), t.expiresAt);
  }
  refreshToken(/** @type {string} */ hash) {
    const r = /** @type {any} */ (this.q('SELECT * FROM refresh_tokens WHERE hash = ?').get(hash));
    return r ? { hash: r.hash, sessionId: r.session_id, createdAt: r.created_at, expiresAt: r.expires_at, usedAt: r.used_at ?? null } : null;
  }
  /** Mark used; returns false when another request used it first (concurrent rotation). */
  markRefreshUsed(/** @type {string} */ hash) {
    return Number(this.q('UPDATE refresh_tokens SET used_at = ? WHERE hash = ? AND used_at IS NULL').run(Date.now(), hash).changes) === 1;
  }
  /** Delete expired refresh tokens and sessions dead for more than 30 days. */
  purgeExpired() {
    const t = Date.now();
    const a = this.q('DELETE FROM refresh_tokens WHERE expires_at < ?').run(t).changes;
    const b = this.q('DELETE FROM sessions WHERE expires_at < ?').run(t - 30 * 86400_000).changes;
    return { refreshTokens: Number(a), sessions: Number(b) };
  }

  // ---- projects (example protected resource)
  createProject(/** @type {{tenantId:string, ownerId:string, teamId?:string|null, name:string}} */ p) {
    const id = crypto.randomUUID();
    const t = now();
    this.q('INSERT INTO projects (id, tenant_id, owner_id, team_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(id, p.tenantId, p.ownerId, p.teamId ?? null, p.name, t, t);
    return this.projectById(id);
  }
  projectById(/** @type {string} */ id) {
    return mapProject(this.q('SELECT * FROM projects WHERE id = ?').get(id));
  }
  listProjects(/** @type {string} */ tenantId) {
    return this.q('SELECT * FROM projects WHERE tenant_id = ? ORDER BY created_at').all(tenantId).map(mapProject);
  }
  updateProject(/** @type {string} */ id, /** @type {{name:string}} */ patch) {
    this.q('UPDATE projects SET name = ?, updated_at = ? WHERE id = ?').run(patch.name, now(), id);
    return this.projectById(id);
  }
  deleteProject(/** @type {string} */ id) {
    this.q('DELETE FROM projects WHERE id = ?').run(id);
  }

  // ---- audit
  /** @param {{tenantId?:string|null, actorId?:string|null, action:string, targetId?:string|null, outcome:'ok'|'denied'|'failed'|'alert', ip?:string|null, detail?:any}} e */
  audit(e) {
    this.q('INSERT INTO audit (at, tenant_id, actor_id, action, target_id, outcome, ip, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(
      now(), e.tenantId ?? null, e.actorId ?? null, e.action, e.targetId ?? null, e.outcome, e.ip ?? null, e.detail === undefined ? null : JSON.stringify(e.detail),
    );
  }
  /** @param {{tenantId?:string, action?:string, outcome?:string, since?:string, limit?:number}} f */
  listAudit(f = {}) {
    const where = [];
    /** @type {any[]} */
    const args = [];
    if (f.tenantId) (where.push('tenant_id = ?'), args.push(f.tenantId));
    if (f.action) (where.push('action LIKE ?'), args.push(f.action.replace(/\*/g, '%')));
    if (f.outcome) (where.push('outcome = ?'), args.push(f.outcome));
    if (f.since) (where.push('at >= ?'), args.push(f.since));
    const sql = `SELECT * FROM audit ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY id DESC LIMIT ?`;
    args.push(Math.min(Math.max(1, f.limit || 50), 1000));
    return this.db.prepare(sql).all(...args).map((/** @type {any} */ r) => ({
      id: r.id, at: r.at, tenantId: r.tenant_id, actorId: r.actor_id, action: r.action, targetId: r.target_id, outcome: r.outcome, ip: r.ip, detail: r.detail ? JSON.parse(r.detail) : null,
    }));
  }
}

// @ts-check
import { AuthError, errors } from './errors.js';
import { loadConfig } from './config.js';
import { loadPolicy, Policy } from './policy.js';
import { KeyStore } from './keys.js';
import { TokenService, newRefreshToken, hashRefreshToken } from './tokens.js';
import { Store } from './store.js';
import { hashPassword, verifyPassword, checkPasswordPolicy, generatePassword } from './passwords.js';

/**
 * The operator (CLI with direct database access). Passes permission checks but still obeys the
 * invariants: valid roles, password policy, last-admin protection, tenant boundaries on lookups.
 */
export const SYSTEM = Object.freeze({ system: true, id: 'system', tenantId: '', role: 'system', teamId: null });

/** @typedef {{id:string, tenantId:string, role:string, teamId:string|null, email?:string, sessionId?:string, tokenId?:string, expiresAt?:number, system?:false}} Principal */
/** @typedef {Principal | typeof SYSTEM} Actor */
/** @typedef {{ip?:string|null, userAgent?:string|null}} ReqCtx */

const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$/;
const SLUG_RE = /^[a-z0-9][a-z0-9-]{1,40}[a-z0-9]$/;
const TEAM_RE = /^[A-Za-z0-9][A-Za-z0-9 _.-]{0,39}$/;

export function normalizeEmail(/** @type {unknown} */ email) {
  const e = String(email ?? '').trim().toLowerCase();
  if (!EMAIL_RE.test(e) || e.length > 254) throw errors.invalid('A valid email is required', { field: 'email' });
  return e;
}

function cleanTeam(/** @type {unknown} */ team) {
  if (team === undefined) return undefined;
  if (team === null || team === '') return null;
  const t = String(team).trim();
  if (!TEAM_RE.test(t)) throw errors.invalid('team must be 1-40 letters, digits, space, _ . -', { field: 'teamId' });
  return t;
}

/** Public view of a user - never includes the password hash. */
export function publicUser(/** @type {import('./store.js').UserRow} */ u) {
  return {
    id: u.id,
    tenantId: u.tenantId,
    email: u.email,
    name: u.name,
    role: u.role,
    teamId: u.teamId,
    status: u.status,
    locked: u.lockedUntil > Date.now(),
    lastLoginAt: u.lastLoginAt,
    createdAt: u.createdAt,
  };
}

export class AuthService {
  /**
   * @param {{config: import('./config.js').Config, store: Store, policy: Policy, keys: KeyStore}} deps
   */
  constructor({ config, store, policy, keys }) {
    this.config = config;
    this.store = store;
    this.policy = policy;
    this.keys = keys;
    this.tokens = new TokenService({ keys, issuer: config.issuer, audience: config.audience, accessTtlSec: config.accessTtlSec, clockToleranceSec: config.clockToleranceSec });
    this.pw = { rounds: config.bcryptRounds, pepper: config.pepper };
  }

  /**
   * Build a ready service from config (file + env). `memory: true` = in-memory DB and keys (tests, demo).
   * `isolated: true` ignores authz.config.json/env and uses the built-in policy unless `policy` is given.
   * @param {{configFile?:string, overrides?:Record<string, any>, memory?:boolean, isolated?:boolean, policy?:import('./policy.js').PolicyDoc, createKeys?:boolean}} [o]
   */
  static open(o = {}) {
    const overrides = { ...(o.overrides || {}) };
    if (o.memory) overrides.dbPath = ':memory:';
    const config = loadConfig({ file: o.configFile, overrides, isolated: o.isolated });
    const policy = o.policy ? new Policy(o.policy) : o.isolated ? loadPolicy(undefined) : loadPolicy(config.policyFile);
    const keys = new KeyStore({ alg: config.algorithm, dir: o.memory ? undefined : config.keysDir, memory: o.memory }).load({ create: o.createKeys ?? true });
    const store = new Store(config.dbPath);
    return new AuthService({ config, store, policy, keys });
  }

  close() {
    this.store.close();
  }

  // ------------------------------------------------------------------ helpers

  /** @param {string} password @param {string} [email] */
  #assertPassword(password, email) {
    const problems = checkPasswordPolicy(password, this.config.passwordPolicy, { email });
    if (problems.length) throw errors.invalid(`Password ${problems.join('; ')}`, { field: 'password', problems });
  }

  /** @param {Actor} actor */
  #isSystem(actor) {
    return Boolean(/** @type {any} */ (actor).system);
  }

  /**
   * Throw 403 unless actor may do permission on target. Denials are audited.
   * @param {Actor} actor @param {string} permission @param {import('./policy.js').ResourceRef} [target] @param {ReqCtx} [ctx]
   */
  assert(actor, permission, target, ctx) {
    if (this.#isSystem(actor)) return { allowed: true, scope: /** @type {const} */ ('any'), reason: 'system operator' };
    const d = this.policy.check(/** @type {Principal} */ (actor), permission, target);
    if (!d.allowed) {
      this.store.audit({ tenantId: actor.tenantId, actorId: actor.id, action: `authz.deny:${permission}`, targetId: target?.id ?? null, outcome: 'denied', ip: ctx?.ip, detail: { role: actor.role, reason: d.reason } });
      throw errors.forbidden(undefined, { permission, reason: d.reason });
    }
    return d;
  }

  /** Non-throwing check for UI menus and feature flags. */
  can(/** @type {Actor} */ actor, /** @type {string} */ permission, /** @type {import('./policy.js').ResourceRef} */ target) {
    if (this.#isSystem(actor)) return { allowed: true, scope: 'any', reason: 'system operator' };
    return this.policy.check(/** @type {Principal} */ (actor), permission, target);
  }

  /** Load a user the actor is allowed to know exists (other tenants look like 404). */
  #target(/** @type {Actor} */ actor, /** @type {string} */ userId) {
    const u = this.store.userById(String(userId || ''));
    if (!u || (!this.#isSystem(actor) && u.tenantId !== actor.tenantId)) throw errors.notFound('User');
    return u;
  }

  /** Actor must be allowed to manage users holding `role` (prevents a manager touching an admin). */
  #assertManagesRole(/** @type {Actor} */ actor, /** @type {string} */ role, /** @type {string} */ what) {
    if (this.#isSystem(actor)) return;
    if (!this.policy.canAssign(actor.role, role)) throw errors.forbidden(`A ${actor.role} cannot ${what} a ${role}`, { reason: 'role_hierarchy' });
  }

  /** Refuse to remove the last active top-level role (admin) of a tenant. */
  #assertNotLastAdmin(/** @type {import('./store.js').UserRow} */ target, /** @type {{newRole?:string, disabling?:boolean, deleting?:boolean}} */ change) {
    const top = this.policy.topRoles();
    if (!top.includes(target.role) || target.status !== 'active') return;
    const losesTop = change.deleting || change.disabling || (change.newRole !== undefined && !top.includes(change.newRole));
    if (losesTop && this.store.countActiveWithRoles(target.tenantId, top) <= 1)
      throw errors.conflict('last_admin', `This is the last active ${target.role} of the organisation; promote someone else first`);
  }

  // ------------------------------------------------------------------ tenants

  /** @param {{slug:string, name?:string}} t */
  createTenant(t) {
    const slug = String(t.slug || '').trim().toLowerCase();
    if (!SLUG_RE.test(slug)) throw errors.invalid('tenant slug must be 3-42 chars: a-z, 0-9, -', { field: 'slug' });
    if (this.store.tenantBySlug(slug)) throw errors.conflict('tenant_exists', `Tenant "${slug}" already exists`);
    const tenant = this.store.createTenant({ slug, name: String(t.name || slug).slice(0, 100) });
    this.store.audit({ tenantId: tenant.id, action: 'tenant.create', targetId: tenant.id, outcome: 'ok', detail: { slug } });
    return tenant;
  }

  /** @param {string} slug */
  tenant(slug) {
    const t = this.store.tenantBySlug(String(slug || '').toLowerCase());
    if (!t) throw errors.notFound('Tenant');
    return t;
  }

  /**
   * Create a tenant (if missing) and its first admin. Refuses when the tenant already has an active admin.
   * @param {{tenant:string, tenantName?:string, email:string, password?:string, name?:string}} o
   */
  async bootstrap(o) {
    const tenant = this.store.tenantBySlug(String(o.tenant || '').toLowerCase()) || this.createTenant({ slug: o.tenant, name: o.tenantName });
    const top = this.policy.topRoles()[0];
    if (this.store.countActiveWithRoles(tenant.id, this.policy.topRoles()) > 0) throw errors.conflict('already_bootstrapped', `Tenant "${tenant.slug}" already has an active ${top}`);
    const res = await this.createUser(SYSTEM, { tenant: tenant.slug, email: o.email, password: o.password, name: o.name, role: top });
    return { tenant, ...res };
  }

  // ------------------------------------------------------------------ login / tokens

  /**
   * @param {{tenant?:string, email:string, password:string}} creds @param {ReqCtx} [ctx]
   */
  async login(creds, ctx = {}) {
    const email = normalizeEmail(creds.email);
    const password = String(creds.password ?? '');
    if (!password || password.length > 1024) throw errors.invalidCredentials();
    /** @type {import('./store.js').UserRow[]} */
    let candidates;
    if (creds.tenant) {
      const t = this.store.tenantBySlug(String(creds.tenant).toLowerCase());
      const u = t ? this.store.userByEmail(t.id, email) : null;
      candidates = u ? [u] : [];
    } else {
      candidates = this.store.usersByEmail(email).slice(0, 5);
    }

    const now = Date.now();
    const locked = candidates.filter((u) => u.lockedUntil > now);
    if (candidates.length && locked.length === candidates.length) {
      await verifyPassword(password, null, this.pw); // same cost as a real attempt
      const retry = Math.ceil((Math.min(...locked.map((u) => u.lockedUntil)) - now) / 1000);
      this.store.audit({ tenantId: locked[0].tenantId, actorId: locked[0].id, action: 'auth.login', outcome: 'denied', ip: ctx.ip, detail: { reason: 'locked' } });
      throw errors.locked(retry);
    }

    /** @type {import('./store.js').UserRow[]} */
    const matched = [];
    if (!candidates.length) await verifyPassword(password, null, this.pw);
    for (const u of candidates) {
      if (u.lockedUntil > now) continue;
      const r = await verifyPassword(password, u.passwordHash, this.pw);
      if (r.ok) {
        matched.push(u);
        if (r.needsRehash) this.store.updateUser(u.id, { passwordHash: await hashPassword(password, this.pw) });
      }
    }
    if (!matched.length) {
      for (const u of candidates) {
        if (u.lockedUntil > now) continue;
        const f = this.store.recordFailedLogin(u.id, this.config.lockout.maxAttempts, this.config.lockout.lockMinutes * 60_000);
        this.store.audit({ tenantId: u.tenantId, actorId: u.id, action: 'auth.login', outcome: 'failed', ip: ctx.ip, detail: { attempts: f?.attempts, locked: (f?.lockedUntil ?? 0) > now } });
      }
      if (!candidates.length) this.store.audit({ action: 'auth.login', outcome: 'failed', ip: ctx.ip, detail: { reason: 'unknown_email', tenant: creds.tenant || null } });
      throw errors.invalidCredentials();
    }
    if (matched.length > 1) {
      throw new AuthError('tenant_required', 400, 'This email belongs to several organisations - choose one', {
        tenants: matched.map((u) => this.store.tenantById(u.tenantId)?.slug),
      });
    }
    const user = matched[0];
    if (user.status !== 'active') {
      this.store.audit({ tenantId: user.tenantId, actorId: user.id, action: 'auth.login', outcome: 'denied', ip: ctx.ip, detail: { reason: 'disabled' } });
      throw new AuthError('account_disabled', 403, 'This account is disabled');
    }
    this.store.recordSuccessfulLogin(user.id);
    const sessionId = this.store.createSession({ userId: user.id, tenantId: user.tenantId, expiresAt: now + this.config.refreshTtlDays * 86400_000, ip: ctx.ip, userAgent: ctx.userAgent });
    this.store.audit({ tenantId: user.tenantId, actorId: user.id, action: 'auth.login', outcome: 'ok', ip: ctx.ip, detail: { sessionId } });
    const fresh = /** @type {import('./store.js').UserRow} */ (this.store.userById(user.id));
    return { ...this.#issue(fresh, sessionId), user: publicUser(fresh), tenant: this.store.tenantById(user.tenantId)?.slug };
  }

  /** Access token + a new refresh token in the session's rotation chain. */
  #issue(/** @type {import('./store.js').UserRow} */ user, /** @type {string} */ sessionId) {
    const session = this.store.sessionById(sessionId);
    const access = this.tokens.signAccess(user, { sessionId });
    const rt = newRefreshToken();
    const idleExpiry = Date.now() + this.config.refreshIdleDays * 86400_000;
    const refreshExpiresAt = Math.min(session?.expiresAt ?? idleExpiry, idleExpiry);
    this.store.addRefreshToken({ hash: rt.hash, sessionId, expiresAt: refreshExpiresAt });
    return { tokenType: 'Bearer', accessToken: access.token, expiresIn: access.expiresIn, refreshToken: rt.token, refreshExpiresAt: new Date(refreshExpiresAt).toISOString(), sessionId };
  }

  /**
   * Rotate a refresh token. A refresh token used twice means it was stolen (or replayed):
   * the whole session is revoked, so both the thief and the victim must log in again.
   * @param {{refreshToken:string}} body @param {ReqCtx} [ctx]
   */
  refresh(body, ctx = {}) {
    const raw = String(body?.refreshToken ?? '');
    if (!raw.startsWith('rt_') || raw.length > 200) throw errors.unauthenticated('refresh_invalid', 'Invalid refresh token');
    const hash = hashRefreshToken(raw);
    const row = this.store.refreshToken(hash);
    if (!row) throw errors.unauthenticated('refresh_invalid', 'Invalid refresh token');
    const session = this.store.sessionById(row.sessionId);
    if (!session) throw errors.unauthenticated('refresh_invalid', 'Invalid refresh token');
    if (session.revokedAt) throw errors.unauthenticated('session_revoked', 'Session has been signed out');
    if (row.usedAt !== null || !this.store.markRefreshUsed(hash)) {
      this.store.revokeSession(session.id, 'refresh_token_reuse');
      this.store.audit({ tenantId: session.tenantId, actorId: session.userId, action: 'auth.refresh_reuse', targetId: session.id, outcome: 'alert', ip: ctx.ip, detail: { originalIp: session.ip } });
      throw errors.unauthenticated('refresh_reused', 'Refresh token was already used - session revoked for safety');
    }
    const now = Date.now();
    if (row.expiresAt < now || session.expiresAt < now) {
      this.store.revokeSession(session.id, 'expired');
      throw errors.unauthenticated('refresh_expired', 'Session expired - please log in again');
    }
    const user = this.store.userById(session.userId);
    if (!user || user.status !== 'active') {
      this.store.revokeSession(session.id, 'user_inactive');
      throw errors.unauthenticated('account_disabled', 'Account is no longer active');
    }
    this.store.touchSession(session.id);
    return { ...this.#issue(user, session.id), user: publicUser(user) };
  }

  /** Sign out one session by refresh token or by the principal's own session. */
  logout(/** @type {{refreshToken?:string, principal?:Principal}} */ o, /** @type {ReqCtx} */ ctx = {}) {
    let sessionId = o.principal?.sessionId;
    if (!sessionId && o.refreshToken) sessionId = this.store.refreshToken(hashRefreshToken(String(o.refreshToken)))?.sessionId;
    if (!sessionId) return { revoked: 0 };
    const s = this.store.sessionById(sessionId);
    if (!s) return { revoked: 0 };
    this.store.revokeSession(sessionId, 'logout');
    this.store.audit({ tenantId: s.tenantId, actorId: s.userId, action: 'auth.logout', targetId: sessionId, outcome: 'ok', ip: ctx.ip });
    return { revoked: 1 };
  }

  /**
   * Verify an access token AND the live account state. Role changes, password resets, disabling and
   * logout take effect on the very next request, not when the token expires.
   * @param {string} token @returns {Principal}
   */
  authenticate(token) {
    const c = this.tokens.verifyAccess(token);
    const user = this.store.userById(c.sub);
    if (!user || user.tenantId !== c.tid) throw errors.unauthenticated('token_revoked', 'Token no longer valid');
    if (user.status !== 'active') throw errors.unauthenticated('account_disabled', 'Account is disabled');
    if (user.tokenVersion !== c.tv) throw errors.unauthenticated('token_revoked', 'Token no longer valid - please refresh or log in again');
    const s = this.store.sessionById(c.sid);
    if (!s || s.revokedAt || s.userId !== user.id) throw errors.unauthenticated('session_revoked', 'Session has been signed out');
    return { id: user.id, tenantId: user.tenantId, role: user.role, teamId: user.teamId, email: user.email, sessionId: c.sid, tokenId: c.jti, expiresAt: c.exp };
  }

  // ------------------------------------------------------------------ self service

  me(/** @type {Principal} */ p) {
    const u = this.#target(p, p.id);
    const t = this.store.tenantById(u.tenantId);
    return { user: publicUser(u), tenant: t && { id: t.id, slug: t.slug, name: t.name }, permissions: this.policy.permissionsOf(u.role) };
  }

  /** @param {{tenant:string, email:string, password:string, name?:string}} o @param {ReqCtx} [ctx] */
  async register(o, ctx = {}) {
    if (!this.config.server.allowSignup) throw errors.forbidden('Self sign-up is disabled - ask an admin for an invite');
    const tenant = this.tenant(o.tenant);
    const res = await this.createUser(SYSTEM, { tenant: tenant.slug, email: o.email, password: o.password, name: o.name, role: this.policy.defaultRole }, ctx);
    return res.user;
  }

  /** @param {Principal} p @param {{currentPassword:string, newPassword:string}} o @param {ReqCtx} [ctx] */
  async changePassword(p, o, ctx = {}) {
    const u = this.#target(p, p.id);
    const ok = (await verifyPassword(String(o.currentPassword ?? ''), u.passwordHash, this.pw)).ok;
    if (!ok) throw errors.invalidCredentials();
    this.#assertPassword(String(o.newPassword ?? ''), u.email);
    if (o.newPassword === o.currentPassword) throw errors.invalid('New password must differ from the current one');
    const updated = /** @type {import('./store.js').UserRow} */ (this.store.updateUser(u.id, { passwordHash: await hashPassword(o.newPassword, this.pw) }, { bumpTokenVersion: true }));
    // sign out every other device; keep (and re-issue) the current session
    for (const s of this.store.listSessions(u.id)) if (s && s.id !== p.sessionId) this.store.revokeSession(s.id, 'password_changed');
    this.store.audit({ tenantId: u.tenantId, actorId: u.id, action: 'user.password_change', targetId: u.id, outcome: 'ok', ip: ctx.ip });
    // old access tokens died with the version bump; the current session keeps its refresh token
    if (!p.sessionId) return { ok: true };
    const access = this.tokens.signAccess(updated, { sessionId: p.sessionId });
    return { ok: true, tokenType: 'Bearer', accessToken: access.token, expiresIn: access.expiresIn };
  }

  // ------------------------------------------------------------------ user management

  /** @param {Actor} actor @param {{tenant?:string, role?:string, status?:string, teamId?:string}} [f] */
  listUsers(actor, f = {}) {
    let tenantId = actor.tenantId;
    if (this.#isSystem(actor)) {
      if (!f.tenant) throw errors.invalid('tenant is required');
      tenantId = this.tenant(f.tenant).id;
      return this.store.listUsers(tenantId, { role: f.role, status: f.status, teamId: f.teamId }).map(publicUser);
    }
    const scope = this.assert(actor, 'users:read').scope;
    if (scope === 'own') return [publicUser(this.#target(actor, actor.id))];
    let teamId = f.teamId;
    if (scope === 'team') {
      if (!actor.teamId) return [publicUser(this.#target(actor, actor.id))];
      teamId = actor.teamId;
    }
    return this.store.listUsers(tenantId, { role: f.role, status: f.status, teamId }).map(publicUser);
  }

  getUser(/** @type {Actor} */ actor, /** @type {string} */ id, /** @type {ReqCtx} */ ctx = {}) {
    const u = this.#target(actor, id);
    if (u.id !== actor.id) this.assert(actor, 'users:read', { id: u.id, tenantId: u.tenantId, teamId: u.teamId }, ctx);
    return publicUser(u);
  }

  /**
   * Invite/create a user. Managers can only create users in their own team with roles they may assign.
   * When no password is given a strong temporary one is generated and returned once.
   * @param {Actor} actor
   * @param {{tenant?:string, email:string, name?:string, role?:string, teamId?:string|null, password?:string}} o
   * @param {ReqCtx} [ctx]
   */
  async createUser(actor, o, ctx = {}) {
    const email = normalizeEmail(o.email);
    const role = o.role || this.policy.defaultRole;
    if (!this.policy.hasRole(role)) throw errors.invalid(`Unknown role "${role}". Roles: ${this.policy.roles.join(', ')}`, { field: 'role' });
    let teamId = cleanTeam(o.teamId) ?? null;
    let tenantId = actor.tenantId;
    if (this.#isSystem(actor)) {
      tenantId = this.tenant(/** @type {string} */ (o.tenant)).id;
    } else {
      if (o.teamId === undefined && actor.teamId) teamId = actor.teamId;
      this.assert(actor, 'users:create', { tenantId, teamId, ownerId: null }, ctx);
      this.#assertManagesRole(actor, role, 'create');
    }
    const generated = !o.password;
    const password = o.password || generatePassword();
    this.#assertPassword(password, email);
    if (this.store.userByEmail(tenantId, email)) throw errors.conflict('email_taken', 'A user with this email already exists in this organisation');
    const passwordHash = await hashPassword(password, this.pw);
    let user;
    try {
      user = this.store.createUser({ tenantId, email, name: String(o.name || '').slice(0, 100), passwordHash, role, teamId });
    } catch (e) {
      if (/UNIQUE/i.test(String(/** @type {Error} */ (e).message))) throw errors.conflict('email_taken', 'A user with this email already exists in this organisation');
      throw e;
    }
    this.store.audit({ tenantId, actorId: actor.id, action: 'user.create', targetId: user.id, outcome: 'ok', ip: ctx.ip, detail: { email, role, teamId } });
    return { user: publicUser(user), temporaryPassword: generated ? password : undefined };
  }

  /** Update name / team. Moving someone to another team needs tenant-wide users:update. */
  updateUser(/** @type {Actor} */ actor, /** @type {string} */ id, /** @type {{name?:string, teamId?:string|null}} */ patch, /** @type {ReqCtx} */ ctx = {}) {
    const u = this.#target(actor, id);
    /** @type {{name?:string, teamId?:string|null}} */
    const p = {};
    if (patch.name !== undefined) p.name = String(patch.name).slice(0, 100);
    const team = cleanTeam(patch.teamId);
    if (team !== undefined && team !== u.teamId) p.teamId = team;
    if (!Object.keys(p).length) return publicUser(u);
    if (!this.#isSystem(actor)) {
      if (u.id === actor.id && p.teamId === undefined) this.assert(actor, 'profile:update', { id: u.id, tenantId: u.tenantId }, ctx);
      else {
        this.assert(actor, 'users:update', { id: u.id, tenantId: u.tenantId, teamId: u.teamId }, ctx);
        if (u.id !== actor.id) this.#assertManagesRole(actor, u.role, 'edit');
        if (p.teamId !== undefined) this.assert(actor, 'users:update', { tenantId: u.tenantId, teamId: p.teamId }, ctx);
      }
    }
    const bump = p.teamId !== undefined; // team is a claim in the token
    const updated = /** @type {import('./store.js').UserRow} */ (this.store.updateUser(u.id, p, { bumpTokenVersion: bump }));
    this.store.audit({ tenantId: u.tenantId, actorId: actor.id, action: 'user.update', targetId: u.id, outcome: 'ok', ip: ctx.ip, detail: p });
    return publicUser(updated);
  }

  /** Change a user's role. Old access tokens stop working immediately (token version bump). */
  changeRole(/** @type {Actor} */ actor, /** @type {string} */ id, /** @type {string} */ role, /** @type {ReqCtx} */ ctx = {}) {
    const u = this.#target(actor, id);
    if (!this.policy.hasRole(role)) throw errors.invalid(`Unknown role "${role}". Roles: ${this.policy.roles.join(', ')}`, { field: 'role' });
    if (!this.#isSystem(actor)) {
      if (u.id === actor.id) throw errors.forbidden('You cannot change your own role', { reason: 'self_role_change' });
      this.assert(actor, 'users:update', { id: u.id, tenantId: u.tenantId, teamId: u.teamId }, ctx);
      this.#assertManagesRole(actor, u.role, 'change the role of');
      this.#assertManagesRole(actor, role, 'grant the role');
    }
    if (u.role === role) return publicUser(u);
    this.#assertNotLastAdmin(u, { newRole: role });
    const updated = /** @type {import('./store.js').UserRow} */ (this.store.updateUser(u.id, { role }, { bumpTokenVersion: true }));
    this.store.audit({ tenantId: u.tenantId, actorId: actor.id, action: 'user.role_change', targetId: u.id, outcome: 'ok', ip: ctx.ip, detail: { from: u.role, to: role } });
    return publicUser(updated);
  }

  /** Disable (instant sign-out everywhere) or re-enable a user. */
  setStatus(/** @type {Actor} */ actor, /** @type {string} */ id, /** @type {'active'|'disabled'} */ status, /** @type {ReqCtx} */ ctx = {}) {
    if (status !== 'active' && status !== 'disabled') throw errors.invalid('status must be active or disabled');
    const u = this.#target(actor, id);
    if (!this.#isSystem(actor)) {
      if (u.id === actor.id) throw errors.forbidden('You cannot disable yourself', { reason: 'self_disable' });
      this.assert(actor, 'users:disable', { id: u.id, tenantId: u.tenantId, teamId: u.teamId }, ctx);
      this.#assertManagesRole(actor, u.role, status === 'disabled' ? 'disable' : 'enable');
    }
    if (u.status === status) return publicUser(u);
    if (status === 'disabled') this.#assertNotLastAdmin(u, { disabling: true });
    const updated = /** @type {import('./store.js').UserRow} */ (this.store.updateUser(u.id, { status }, { bumpTokenVersion: true }));
    if (status === 'disabled') this.store.revokeUserSessions(u.id, 'disabled');
    else this.store.unlockUser(u.id);
    this.store.audit({ tenantId: u.tenantId, actorId: actor.id, action: status === 'disabled' ? 'user.disable' : 'user.enable', targetId: u.id, outcome: 'ok', ip: ctx.ip });
    return publicUser(updated);
  }

  /** Admin password reset: sets a new (or generated) password, unlocks, signs out everywhere. */
  async resetPassword(/** @type {Actor} */ actor, /** @type {string} */ id, /** @type {string|undefined} */ newPassword, /** @type {ReqCtx} */ ctx = {}) {
    const u = this.#target(actor, id);
    if (!this.#isSystem(actor)) {
      if (u.id === actor.id) throw errors.forbidden('Use change-password for your own account', { reason: 'self_reset' });
      this.assert(actor, 'users:update', { id: u.id, tenantId: u.tenantId, teamId: u.teamId }, ctx);
      this.#assertManagesRole(actor, u.role, 'reset the password of');
    }
    const generated = !newPassword;
    const password = newPassword || generatePassword();
    this.#assertPassword(password, u.email);
    this.store.updateUser(u.id, { passwordHash: await hashPassword(password, this.pw) }, { bumpTokenVersion: true });
    this.store.unlockUser(u.id);
    const revoked = this.store.revokeUserSessions(u.id, 'password_reset');
    this.store.audit({ tenantId: u.tenantId, actorId: actor.id, action: 'user.password_reset', targetId: u.id, outcome: 'ok', ip: ctx.ip, detail: { sessionsRevoked: revoked } });
    return { user: publicUser(/** @type {any} */ (this.store.userById(u.id))), temporaryPassword: generated ? password : undefined, sessionsRevoked: revoked };
  }

  unlock(/** @type {Actor} */ actor, /** @type {string} */ id, /** @type {ReqCtx} */ ctx = {}) {
    const u = this.#target(actor, id);
    if (!this.#isSystem(actor)) {
      this.assert(actor, 'users:update', { id: u.id, tenantId: u.tenantId, teamId: u.teamId }, ctx);
      this.#assertManagesRole(actor, u.role, 'unlock');
    }
    this.store.unlockUser(u.id);
    this.store.audit({ tenantId: u.tenantId, actorId: actor.id, action: 'user.unlock', targetId: u.id, outcome: 'ok', ip: ctx.ip });
    return publicUser(/** @type {any} */ (this.store.userById(u.id)));
  }

  deleteUser(/** @type {Actor} */ actor, /** @type {string} */ id, /** @type {ReqCtx} */ ctx = {}) {
    const u = this.#target(actor, id);
    if (!this.#isSystem(actor)) {
      if (u.id === actor.id) throw errors.forbidden('You cannot delete yourself', { reason: 'self_delete' });
      this.assert(actor, 'users:delete', { id: u.id, tenantId: u.tenantId, teamId: u.teamId }, ctx);
      this.#assertManagesRole(actor, u.role, 'delete');
    }
    this.#assertNotLastAdmin(u, { deleting: true });
    this.store.deleteUser(u.id);
    this.store.audit({ tenantId: u.tenantId, actorId: actor.id, action: 'user.delete', targetId: u.id, outcome: 'ok', ip: ctx.ip, detail: { email: u.email, role: u.role } });
    return { deleted: true };
  }

  // ------------------------------------------------------------------ sessions

  listSessions(/** @type {Actor} */ actor, /** @type {string} */ userId) {
    const u = this.#target(actor, userId);
    if (u.id !== actor.id) this.assert(actor, 'sessions:read', { id: u.id, tenantId: u.tenantId, teamId: u.teamId });
    return this.store.listSessions(u.id).map((s) => s && { id: s.id, createdAt: s.createdAt, lastUsedAt: s.lastUsedAt, ip: s.ip, userAgent: s.userAgent, current: s.id === /** @type {any} */ (actor).sessionId });
  }

  revokeSession(/** @type {Actor} */ actor, /** @type {string} */ sessionId, /** @type {ReqCtx} */ ctx = {}) {
    const s = this.store.sessionById(String(sessionId || ''));
    if (!s || (!this.#isSystem(actor) && s.tenantId !== actor.tenantId)) throw errors.notFound('Session');
    const owner = this.#target(actor, s.userId);
    if (owner.id !== actor.id) {
      this.assert(actor, 'sessions:revoke', { id: owner.id, tenantId: owner.tenantId, teamId: owner.teamId }, ctx);
      this.#assertManagesRole(actor, owner.role, 'sign out');
    }
    this.store.revokeSession(s.id, 'revoked');
    this.store.audit({ tenantId: s.tenantId, actorId: actor.id, action: 'session.revoke', targetId: s.id, outcome: 'ok', ip: ctx.ip });
    return { revoked: 1 };
  }

  /** Sign a user out of every device and kill all their access tokens now. */
  logoutAll(/** @type {Actor} */ actor, /** @type {string} */ userId, /** @type {ReqCtx} */ ctx = {}) {
    const u = this.#target(actor, userId);
    if (u.id !== actor.id) {
      this.assert(actor, 'sessions:revoke', { id: u.id, tenantId: u.tenantId, teamId: u.teamId }, ctx);
      this.#assertManagesRole(actor, u.role, 'sign out');
    }
    this.store.updateUser(u.id, {}, { bumpTokenVersion: true });
    const revoked = this.store.revokeUserSessions(u.id, 'logout_all');
    this.store.audit({ tenantId: u.tenantId, actorId: actor.id, action: 'auth.logout_all', targetId: u.id, outcome: 'ok', ip: ctx.ip, detail: { revoked } });
    return { revoked };
  }

  // ------------------------------------------------------------------ audit

  auditLog(/** @type {Actor} */ actor, /** @type {{tenant?:string, action?:string, outcome?:string, since?:string, limit?:number}} */ f = {}) {
    if (this.#isSystem(actor)) return this.store.listAudit({ ...f, tenantId: f.tenant ? this.tenant(f.tenant).id : undefined });
    this.assert(actor, 'audit:read', { tenantId: actor.tenantId });
    return this.store.listAudit({ ...f, tenantId: actor.tenantId });
  }

  // ------------------------------------------------------------------ example resource: projects
  // Shows how to protect any business object with own / team / tenant scopes.

  listProjects(/** @type {Principal} */ actor) {
    this.assert(actor, 'projects:read');
    return this.store.listProjects(actor.tenantId).filter((p) => p && this.policy.check(actor, 'projects:read', p).allowed);
  }

  createProject(/** @type {Principal} */ actor, /** @type {{name:string}} */ o, /** @type {ReqCtx} */ ctx = {}) {
    const name = String(o?.name || '').trim().slice(0, 120);
    if (!name) throw errors.invalid('name is required', { field: 'name' });
    this.assert(actor, 'projects:create', { tenantId: actor.tenantId, ownerId: actor.id, teamId: actor.teamId }, ctx);
    return this.store.createProject({ tenantId: actor.tenantId, ownerId: actor.id, teamId: actor.teamId, name });
  }

  #project(/** @type {Principal} */ actor, /** @type {string} */ id) {
    const p = this.store.projectById(String(id || ''));
    if (!p || p.tenantId !== actor.tenantId) throw errors.notFound('Project');
    return p;
  }

  getProject(/** @type {Principal} */ actor, /** @type {string} */ id, /** @type {ReqCtx} */ ctx = {}) {
    const p = this.#project(actor, id);
    this.assert(actor, 'projects:read', p, ctx);
    return p;
  }

  updateProject(/** @type {Principal} */ actor, /** @type {string} */ id, /** @type {{name:string}} */ o, /** @type {ReqCtx} */ ctx = {}) {
    const p = this.#project(actor, id);
    this.assert(actor, 'projects:update', p, ctx);
    const name = String(o?.name || '').trim().slice(0, 120);
    if (!name) throw errors.invalid('name is required', { field: 'name' });
    return this.store.updateProject(p.id, { name });
  }

  deleteProject(/** @type {Principal} */ actor, /** @type {string} */ id, /** @type {ReqCtx} */ ctx = {}) {
    const p = this.#project(actor, id);
    this.assert(actor, 'projects:delete', p, ctx);
    this.store.deleteProject(p.id);
    return { deleted: true };
  }
}

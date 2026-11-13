// @ts-check
import fs from 'node:fs';

/**
 * Permission grammar:  resource:action:scope
 *   resource  e.g. users, projects, billing, or *
 *   action    e.g. read, create, update, delete, invite, or *
 *   scope     own < team < tenant < any
 *     own     the actor owns the resource (resource.ownerId === actor.id)
 *     team    same team inside the same tenant
 *     tenant  anything inside the actor's tenant (organisation)
 *     any     cross-tenant (platform staff only - avoid in client policies)
 */
export const SCOPES = /** @type {const} */ (['own', 'team', 'tenant', 'any']);
const SCOPE_RANK = { own: 1, team: 2, tenant: 3, any: 4 };
const PERM_RE = /^([a-z][a-z0-9_-]*|\*):([a-z][a-z0-9_-]*|\*):(own|team|tenant|any)$/;

/** @typedef {'own'|'team'|'tenant'|'any'} Scope */
/** @typedef {{level:number, inherits?:string[], permissions?:string[], description?:string}} RoleDef */
/** @typedef {{roles: Record<string, RoleDef>, defaultRole: string, assignable: Record<string, string[]>}} PolicyDoc */
/** @typedef {{id?:string, tenantId?:string|null, teamId?:string|null, ownerId?:string|null}} ResourceRef */
/** @typedef {{id:string, tenantId:string, teamId?:string|null, role:string}} Actor */

export const DEFAULT_POLICY = /** @type {PolicyDoc} */ ({
  roles: {
    user: {
      level: 10,
      description: 'Regular member: manages own profile and own resources',
      permissions: [
        'profile:read:own',
        'profile:update:own',
        'projects:read:own',
        'projects:create:own',
        'projects:update:own',
        'projects:delete:own',
      ],
    },
    manager: {
      level: 50,
      inherits: ['user'],
      description: 'Team lead: sees and manages the users and resources of their team',
      permissions: [
        'users:read:team',
        'users:create:team',
        'users:update:team',
        'users:disable:team',
        'projects:read:team',
        'projects:update:team',
        'reports:read:team',
      ],
    },
    admin: {
      level: 100,
      inherits: ['manager'],
      description: 'Organisation admin: full control inside their own tenant',
      permissions: [
        'users:*:tenant',
        'projects:*:tenant',
        'reports:*:tenant',
        'billing:*:tenant',
        'settings:*:tenant',
        'audit:read:tenant',
        'sessions:*:tenant',
      ],
    },
  },
  defaultRole: 'user',
  // Which roles each role may give to (or take from) other users.
  assignable: {
    admin: ['admin', 'manager', 'user'],
    manager: ['user'],
  },
});

/**
 * Validate a policy document. Returns a list of problems (empty = valid).
 * Catches cycles, unknown roles, bad permission strings and privilege-escalation paths.
 * @param {any} doc
 */
export function validatePolicy(doc) {
  const problems = [];
  if (!doc || typeof doc !== 'object' || !doc.roles || typeof doc.roles !== 'object') return ['policy must have a "roles" object'];
  const names = Object.keys(doc.roles);
  if (!names.length) problems.push('policy defines no roles');
  for (const [name, r] of Object.entries(doc.roles)) {
    if (!/^[a-z][a-z0-9_-]{0,31}$/.test(name)) problems.push(`role name "${name}" must be lowercase letters/digits/-/_`);
    if (!r || typeof r.level !== 'number' || r.level < 0) problems.push(`role "${name}" needs a numeric level >= 0`);
    for (const p of r?.permissions || []) if (!PERM_RE.test(p)) problems.push(`role "${name}": bad permission "${p}" (expected resource:action:scope)`);
    for (const parent of r?.inherits || []) {
      if (!doc.roles[parent]) problems.push(`role "${name}" inherits unknown role "${parent}"`);
      else if (doc.roles[parent].level >= r.level) problems.push(`role "${name}" (level ${r.level}) inherits "${parent}" which is not lower (level ${doc.roles[parent].level})`);
    }
  }
  // cycles
  const visiting = new Set();
  const done = new Set();
  const visit = (/** @type {string} */ n, /** @type {string[]} */ trail) => {
    if (done.has(n) || !doc.roles[n]) return;
    if (visiting.has(n)) {
      problems.push(`inheritance cycle: ${[...trail, n].join(' -> ')}`);
      return;
    }
    visiting.add(n);
    for (const p of doc.roles[n].inherits || []) visit(p, [...trail, n]);
    visiting.delete(n);
    done.add(n);
  };
  for (const n of names) visit(n, []);

  if (!doc.defaultRole || !doc.roles[doc.defaultRole]) problems.push(`defaultRole "${doc.defaultRole}" is not a defined role`);
  for (const [by, list] of Object.entries(doc.assignable || {})) {
    if (!doc.roles[by]) problems.push(`assignable: unknown role "${by}"`);
    for (const target of /** @type {string[]} */ (list)) {
      if (!doc.roles[target]) problems.push(`assignable.${by}: unknown role "${target}"`);
      else if (doc.roles[by] && doc.roles[target].level > doc.roles[by].level)
        problems.push(`assignable.${by}: "${by}" (level ${doc.roles[by].level}) could grant higher role "${target}" (level ${doc.roles[target].level}) - privilege escalation`);
    }
  }
  return problems;
}

/** Load and compile the policy file, or the default policy when the file does not exist. */
export function loadPolicy(/** @type {string|undefined} */ file) {
  if (file && fs.existsSync(file)) {
    let doc;
    try {
      doc = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (e) {
      throw new Error(`Cannot parse policy ${file}: ${/** @type {Error} */ (e).message}`);
    }
    return new Policy(doc);
  }
  return new Policy(DEFAULT_POLICY);
}

export class Policy {
  /** @param {PolicyDoc} doc */
  constructor(doc) {
    const problems = validatePolicy(doc);
    if (problems.length) throw new Error(`Invalid policy:\n - ${problems.join('\n - ')}`);
    this.doc = doc;
    this.defaultRole = doc.defaultRole;
    /** @type {Map<string, {resource:string, action:string, scope:Scope}[]>} */
    this.effective = new Map();
    for (const name of Object.keys(doc.roles)) this.effective.set(name, this.#collect(name));
    this.maxLevel = Math.max(...Object.values(doc.roles).map((r) => r.level));
  }

  /** @param {string} name */
  #collect(name, seen = new Set()) {
    if (seen.has(name)) return [];
    seen.add(name);
    const role = this.doc.roles[name];
    const own = (role.permissions || []).map((p) => {
      const [resource, action, scope] = p.split(':');
      return { resource, action, scope: /** @type {Scope} */ (scope) };
    });
    const inherited = (role.inherits || []).flatMap((p) => this.#collect(p, seen));
    return [...inherited, ...own];
  }

  get roles() {
    return Object.keys(this.doc.roles).sort((a, b) => this.level(a) - this.level(b));
  }

  hasRole(/** @type {string} */ role) {
    return Object.hasOwn(this.doc.roles, role);
  }

  level(/** @type {string} */ role) {
    return this.doc.roles[role]?.level ?? -1;
  }

  /** Roles at the highest level (they guard the "last admin" rule). */
  topRoles() {
    return this.roles.filter((r) => this.level(r) === this.maxLevel);
  }

  /**
   * Widest scope a role holds for resource:action, or null.
   * @param {string} role @param {string} resource @param {string} action
   * @returns {Scope|null}
   */
  grantedScope(role, resource, action) {
    let best = null;
    for (const g of this.effective.get(role) || []) {
      if ((g.resource === '*' || g.resource === resource) && (g.action === '*' || g.action === action)) {
        if (!best || SCOPE_RANK[g.scope] > SCOPE_RANK[best]) best = g.scope;
      }
    }
    return best;
  }

  /**
   * Decide whether an actor may perform "resource:action" on a target resource.
   * Without a target, the question is "may this role ever do this" (list endpoints, menus).
   * @param {Actor} actor
   * @param {string} permission  "resource:action"
   * @param {ResourceRef} [target]
   * @returns {{allowed:boolean, scope:Scope|null, reason:string}}
   */
  check(actor, permission, target) {
    const [resource, action] = permission.split(':');
    if (!resource || !action) return { allowed: false, scope: null, reason: `malformed permission "${permission}"` };
    if (!this.hasRole(actor.role)) return { allowed: false, scope: null, reason: `unknown role "${actor.role}"` };
    const scope = this.grantedScope(actor.role, resource, action);
    if (!scope) return { allowed: false, scope: null, reason: `role "${actor.role}" has no ${resource}:${action} permission` };
    if (!target) return { allowed: true, scope, reason: `role "${actor.role}" holds ${resource}:${action}:${scope}` };
    const r = scopeCovers(scope, actor, target);
    return { allowed: r.ok, scope, reason: r.ok ? `${scope} scope covers target` : r.reason };
  }

  /** Can `byRole` give/take `role`? */
  canAssign(/** @type {string} */ byRole, /** @type {string} */ role) {
    return (this.doc.assignable?.[byRole] || []).includes(role);
  }

  /** Effective permissions of a role as strings (inherited included, de-duplicated). */
  permissionsOf(/** @type {string} */ role) {
    return [...new Set((this.effective.get(role) || []).map((g) => `${g.resource}:${g.action}:${g.scope}`))];
  }

  /** Matrix of resource:action -> {role: scope|null} for docs and the CLI. */
  matrix() {
    const keys = new Set();
    for (const list of this.effective.values()) for (const g of list) keys.add(`${g.resource}:${g.action}`);
    const rows = [];
    for (const key of [...keys].sort()) {
      const [res, act] = key.split(':');
      /** @type {Record<string, string>} */
      const row = { permission: key };
      for (const role of this.roles) row[role] = this.grantedScope(role, res, act) || '-';
      rows.push(row);
    }
    return rows;
  }
}

/**
 * @param {Scope} scope @param {Actor} actor @param {ResourceRef} target
 * @returns {{ok:boolean, reason:string}}
 */
export function scopeCovers(scope, actor, target) {
  if (scope === 'any') return { ok: true, reason: '' };
  // Every scope below "any" is confined to the actor's tenant. A target without a tenant is never covered.
  if (!target.tenantId || target.tenantId !== actor.tenantId) return { ok: false, reason: 'target belongs to another tenant' };
  if (scope === 'tenant') return { ok: true, reason: '' };
  if (scope === 'team') {
    if (target.ownerId && target.ownerId === actor.id) return { ok: true, reason: '' };
    if (target.id && target.id === actor.id) return { ok: true, reason: '' };
    if (actor.teamId && target.teamId && target.teamId === actor.teamId) return { ok: true, reason: '' };
    return { ok: false, reason: 'target is outside your team' };
  }
  // own
  const ownerId = target.ownerId ?? target.id;
  if (ownerId && ownerId === actor.id) return { ok: true, reason: '' };
  return { ok: false, reason: 'you can only act on your own resources' };
}

import test from 'node:test';
import assert from 'node:assert/strict';
import { Policy, DEFAULT_POLICY, validatePolicy } from '../src/index.js';

const p = new Policy(DEFAULT_POLICY);
const actor = (role, extra = {}) => ({ id: 'a1', tenantId: 't1', teamId: 'sales', role, ...extra });

test('default policy is valid and ordered by level', () => {
  assert.deepEqual(validatePolicy(DEFAULT_POLICY), []);
  assert.deepEqual(p.roles, ['user', 'manager', 'admin']);
  assert.deepEqual(p.topRoles(), ['admin']);
});

test('inheritance: manager gets user permissions, admin gets both', () => {
  assert.ok(p.permissionsOf('manager').includes('projects:create:own'));
  assert.equal(p.grantedScope('admin', 'projects', 'read'), 'tenant');
  assert.equal(p.grantedScope('manager', 'projects', 'read'), 'team');
  assert.equal(p.grantedScope('user', 'users', 'read'), null);
});

test('wildcards match any action', () => {
  assert.equal(p.grantedScope('admin', 'billing', 'refund'), 'tenant');
  assert.equal(p.grantedScope('manager', 'billing', 'read'), null);
});

test('own / team / tenant scopes against a target', () => {
  const own = { tenantId: 't1', ownerId: 'a1', teamId: 'sales' };
  const teammate = { tenantId: 't1', ownerId: 'b2', teamId: 'sales' };
  const otherTeam = { tenantId: 't1', ownerId: 'c3', teamId: 'support' };
  const otherTenant = { tenantId: 't2', ownerId: 'a1', teamId: 'sales' };
  assert.equal(p.check(actor('user'), 'projects:update', own).allowed, true);
  assert.equal(p.check(actor('user'), 'projects:update', teammate).allowed, false);
  assert.equal(p.check(actor('manager'), 'projects:update', teammate).allowed, true);
  assert.equal(p.check(actor('manager'), 'projects:update', otherTeam).allowed, false);
  assert.equal(p.check(actor('admin'), 'projects:update', otherTeam).allowed, true);
  assert.equal(p.check(actor('admin'), 'projects:update', otherTenant).allowed, false, 'tenant scope never crosses tenants');
  assert.equal(p.check(actor('admin'), 'projects:update', { ownerId: 'x' }).allowed, false, 'target without tenant is denied');
});

test('manager without a team only covers own resources at team scope', () => {
  const r = p.check(actor('manager', { teamId: null }), 'projects:read', { tenantId: 't1', ownerId: 'z', teamId: null });
  assert.equal(r.allowed, false);
});

test('unknown role and malformed permission are denied', () => {
  assert.equal(p.check(actor('ghost'), 'projects:read').allowed, false);
  assert.equal(p.check(actor('admin'), 'projects').allowed, false);
});

test('assignable roles', () => {
  assert.equal(p.canAssign('admin', 'admin'), true);
  assert.equal(p.canAssign('manager', 'user'), true);
  assert.equal(p.canAssign('manager', 'manager'), false);
  assert.equal(p.canAssign('user', 'user'), false);
});

test('validation catches cycles, unknown roles, bad permissions and escalation paths', () => {
  const bad = {
    defaultRole: 'nobody',
    roles: {
      a: { level: 10, inherits: ['b'], permissions: ['x:y'] },
      b: { level: 20, inherits: ['a'] },
      c: { level: 5, inherits: ['ghost'] },
    },
    assignable: { c: ['b'] },
  };
  const problems = validatePolicy(bad).join('\n');
  assert.match(problems, /cycle/);
  assert.match(problems, /bad permission "x:y"/);
  assert.match(problems, /unknown role "ghost"/);
  assert.match(problems, /defaultRole/);
  assert.match(problems, /privilege escalation/);
  assert.throws(() => new Policy(bad), /Invalid policy/);
});

test('custom policy with extra role works', () => {
  const doc = structuredClone(DEFAULT_POLICY);
  doc.roles.viewer = { level: 5, permissions: ['reports:read:tenant'] };
  doc.assignable.admin.push('viewer');
  const cp = new Policy(doc);
  assert.equal(cp.check({ id: 'v', tenantId: 't', role: 'viewer' }, 'reports:read', { tenantId: 't' }).allowed, true);
  assert.equal(cp.check({ id: 'v', tenantId: 't', role: 'viewer' }, 'projects:read').allowed, false);
});

test('matrix lists every permission per role', () => {
  const row = p.matrix().find((r) => r.permission === 'users:read');
  assert.deepEqual(row, { permission: 'users:read', user: '-', manager: 'team', admin: 'tenant' });
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { SYSTEM } from '../src/index.js';
import { seeded, rejects, PW } from './helpers.js';

test('login returns tokens; wrong password and unknown email give the same error', async () => {
  const { s, login } = await seeded();
  const r = await login('user@acme.test');
  assert.ok(r.accessToken && r.refreshToken.startsWith('rt_'));
  assert.equal(r.user.role, 'user');
  assert.equal(r.user.passwordHash, undefined, 'hash never leaves the engine');
  const a = await rejects(login('user@acme.test', 'acme', 'Wrong-Pass-1'), 'invalid_credentials');
  const b = await rejects(login('ghost@acme.test', 'acme', 'Wrong-Pass-1'), 'invalid_credentials');
  assert.equal(a.message, b.message);
  await rejects(login('user@acme.test', 'nope'), 'invalid_credentials');
  s.close();
});

test('email login is case-insensitive; email in two tenants requires the tenant', async () => {
  const { s, login } = await seeded();
  assert.equal((await login('USER@Acme.test')).user.email, 'user@acme.test');
  s.createTenant({ slug: 'globex' });
  await s.createUser(SYSTEM, { tenant: 'globex', email: 'user@acme.test', password: PW });
  const e = await rejects(s.login({ email: 'user@acme.test', password: PW }), 'tenant_required');
  assert.deepEqual(e.details.tenants.sort(), ['acme', 'globex']);
  assert.equal((await s.login({ tenant: 'globex', email: 'user@acme.test', password: PW })).tenant, 'globex');
  s.close();
});

test('lockout after max attempts, unlock by admin', async () => {
  const { s, u, login } = await seeded({ lockout: { maxAttempts: 3, lockMinutes: 15 } });
  for (let i = 0; i < 3; i++) await rejects(login('user@acme.test', 'acme', 'Wrong-Pass-1'), 'invalid_credentials');
  const e = await rejects(login('user@acme.test'), 'account_locked');
  assert.ok(e.details.retryAfterSec > 0);
  s.unlock(SYSTEM, u.user.id);
  assert.ok((await login('user@acme.test')).accessToken);
  s.close();
});

test('refresh rotates; reuse of an old refresh token revokes the session', async () => {
  const { s, login } = await seeded();
  const r1 = await login('user@acme.test');
  const r2 = s.refresh({ refreshToken: r1.refreshToken });
  assert.notEqual(r2.refreshToken, r1.refreshToken);
  assert.equal(r2.sessionId, r1.sessionId);
  await rejects(() => s.refresh({ refreshToken: r1.refreshToken }), 'refresh_reused');
  await rejects(() => s.refresh({ refreshToken: r2.refreshToken }), 'session_revoked');
  await rejects(() => s.authenticate(r2.accessToken), 'session_revoked');
  await rejects(() => s.refresh({ refreshToken: 'rt_garbage' }), 'refresh_invalid');
  assert.ok(s.store.listAudit({ action: 'auth.refresh_reuse' }).length === 1);
  s.close();
});

test('expired refresh token is rejected', async () => {
  const { s, login } = await seeded();
  const r = await login('user@acme.test');
  s.store.db.prepare('UPDATE refresh_tokens SET expires_at = 1').run();
  await rejects(() => s.refresh({ refreshToken: r.refreshToken }), 'refresh_expired');
  s.close();
});

test('role change, disable and logout-all revoke live access tokens immediately', async () => {
  const { s, u, login } = await seeded();
  const t = (await login('user@acme.test')).accessToken;
  s.changeRole(SYSTEM, u.user.id, 'manager');
  await rejects(() => s.authenticate(t), 'token_revoked');
  const t2 = (await login('user@acme.test')).accessToken;
  assert.equal(s.authenticate(t2).role, 'manager');
  s.setStatus(SYSTEM, u.user.id, 'disabled');
  await rejects(() => s.authenticate(t2), 'account_disabled');
  await rejects(login('user@acme.test'), 'account_disabled');
  s.setStatus(SYSTEM, u.user.id, 'active');
  const t3 = (await login('user@acme.test')).accessToken;
  s.logoutAll(SYSTEM, u.user.id);
  await rejects(() => s.authenticate(t3), 'token_revoked');
  s.close();
});

test('manager: team-only visibility and no escalation', async () => {
  const { s, u, principal } = await seeded();
  const m = await principal('manager@acme.test');
  assert.deepEqual(s.listUsers(m).map((x) => x.email).sort(), ['manager@acme.test', 'user@acme.test']);
  assert.equal(s.getUser(m, u.user.id).email, 'user@acme.test');
  await rejects(() => s.getUser(m, u.other.id), 'forbidden');
  await rejects(() => s.changeRole(m, u.user.id, 'admin'), 'forbidden');
  await rejects(() => s.changeRole(m, u.user.id, 'manager'), 'forbidden');
  await rejects(() => s.changeRole(m, m.id, 'admin'), 'forbidden');
  await rejects(() => s.setStatus(m, u.admin.id, 'disabled'), 'forbidden');
  await rejects(() => s.resetPassword(m, u.admin.id), 'forbidden');
  await rejects(() => s.updateUser(m, u.user.id, { teamId: 'support' }), 'forbidden');
  await rejects(s.createUser(m, { email: 'x@acme.test', role: 'manager' }), 'forbidden');
  await rejects(s.createUser(m, { email: 'x@acme.test', teamId: 'support' }), 'forbidden');
  const created = await s.createUser(m, { email: 'rep@acme.test' });
  assert.equal(created.user.teamId, 'sales');
  assert.ok(created.temporaryPassword);
  assert.equal(s.setStatus(m, u.user.id, 'disabled').status, 'disabled');
  s.close();
});

test('user: only own profile and resources', async () => {
  const { s, u, principal } = await seeded();
  const p = await principal('user@acme.test');
  await rejects(() => s.listUsers(p), 'forbidden');
  assert.equal(s.getUser(p, p.id).email, 'user@acme.test');
  await rejects(() => s.getUser(p, u.other.id), 'forbidden');
  assert.equal(s.updateUser(p, p.id, { name: 'Ursula' }).name, 'Ursula');
  await rejects(() => s.updateUser(p, p.id, { teamId: 'support' }), 'forbidden');
  await rejects(() => s.auditLog(p), 'forbidden');
  assert.ok(s.store.listAudit({ outcome: 'denied' }).length >= 1, 'denials are audited');
  s.close();
});

test('admin: tenant-wide control but never across tenants', async () => {
  const { s, u, principal } = await seeded();
  await s.bootstrap({ tenant: 'globex', email: 'g@globex.test', password: PW });
  const a = await principal('admin@acme.test');
  const g = await principal('g@globex.test', 'globex');
  assert.equal(s.listUsers(a).length, 4);
  assert.equal(s.changeRole(a, u.other.id, 'manager').role, 'manager');
  await rejects(() => s.getUser(g, u.user.id), 'not_found');
  await rejects(() => s.changeRole(g, u.user.id, 'admin'), 'not_found');
  await rejects(() => s.deleteUser(g, u.user.id), 'not_found');
  assert.equal(s.listUsers(g).length, 1);
  s.close();
});

test('last admin cannot be demoted, disabled or deleted - even by the operator', async () => {
  const { s, u, principal } = await seeded();
  await rejects(() => s.changeRole(SYSTEM, u.admin.id, 'user'), 'last_admin');
  await rejects(() => s.setStatus(SYSTEM, u.admin.id, 'disabled'), 'last_admin');
  await rejects(() => s.deleteUser(SYSTEM, u.admin.id), 'last_admin');
  // with a second admin it works
  s.changeRole(SYSTEM, u.manager.id, 'admin');
  const a2 = await principal('manager@acme.test');
  assert.equal(s.changeRole(a2, u.admin.id, 'user').role, 'user');
  s.close();
});

test('bootstrap refuses a tenant that already has an admin', async () => {
  const { s } = await seeded();
  await rejects(s.bootstrap({ tenant: 'acme', email: 'x@acme.test', password: PW }), 'already_bootstrapped');
  s.close();
});

test('password policy enforced on create, reset and change; change keeps current session only', async () => {
  const { s, u, login } = await seeded();
  await rejects(s.createUser(SYSTEM, { tenant: 'acme', email: 'w@acme.test', password: 'password123' }), 'invalid_request');
  const other = await login('user@acme.test');
  const cur = await login('user@acme.test');
  const p = s.authenticate(cur.accessToken);
  await rejects(s.changePassword(p, { currentPassword: 'Wrong-Pass-1', newPassword: 'New-Passw0rd!y' }), 'invalid_credentials');
  await rejects(s.changePassword(p, { currentPassword: PW, newPassword: 'short' }), 'invalid_request');
  const r = await s.changePassword(p, { currentPassword: PW, newPassword: 'New-Passw0rd!y' });
  assert.ok(s.authenticate(r.accessToken));
  await rejects(() => s.authenticate(cur.accessToken), 'token_revoked');
  await rejects(() => s.refresh({ refreshToken: other.refreshToken }), 'session_revoked');
  assert.ok(s.refresh({ refreshToken: cur.refreshToken }).accessToken, 'current device stays signed in');
  await rejects(login('user@acme.test'), 'invalid_credentials');
  assert.ok((await login('user@acme.test', 'acme', 'New-Passw0rd!y')).accessToken);
  const reset = await s.resetPassword(SYSTEM, u.user.id);
  assert.ok((await login('user@acme.test', 'acme', reset.temporaryPassword)).accessToken);
  s.close();
});

test('duplicate email, bad email, unknown role and bad tenant slug are rejected', async () => {
  const { s } = await seeded();
  await rejects(s.createUser(SYSTEM, { tenant: 'acme', email: 'user@acme.test', password: PW }), 'email_taken');
  await rejects(s.createUser(SYSTEM, { tenant: 'acme', email: 'not-an-email', password: PW }), 'invalid_request');
  await rejects(s.createUser(SYSTEM, { tenant: 'acme', email: 'n@acme.test', password: PW, role: 'root' }), 'invalid_request');
  await rejects(() => s.createTenant({ slug: 'Bad Slug!' }), 'invalid_request');
  await rejects(() => s.createTenant({ slug: 'acme' }), 'tenant_exists');
  s.close();
});

test('projects: own / team / tenant scopes on a real resource', async () => {
  const { s, principal } = await seeded();
  const user = await principal('user@acme.test');
  const other = await principal('other@acme.test');
  const mgr = await principal('manager@acme.test');
  const admin = await principal('admin@acme.test');
  const p1 = s.createProject(user, { name: 'Mine' });
  const p2 = s.createProject(other, { name: 'Support' });
  assert.deepEqual(s.listProjects(user).map((p) => p.id), [p1.id]);
  assert.deepEqual(s.listProjects(mgr).map((p) => p.id), [p1.id]);
  assert.equal(s.listProjects(admin).length, 2);
  await rejects(() => s.updateProject(user, p2.id, { name: 'x' }), 'forbidden');
  await rejects(() => s.updateProject(mgr, p2.id, { name: 'x' }), 'forbidden');
  await rejects(() => s.deleteProject(mgr, p1.id), 'forbidden');
  assert.equal(s.updateProject(mgr, p1.id, { name: 'Reviewed' }).name, 'Reviewed');
  assert.deepEqual(s.deleteProject(admin, p2.id), { deleted: true });
  s.close();
});

test('sessions: list own, revoke own; manager cannot sign out admin', async () => {
  const { s, u, login } = await seeded();
  const a = await login('user@acme.test');
  await login('user@acme.test');
  const p = s.authenticate(a.accessToken);
  const list = s.listSessions(p, p.id);
  assert.equal(list.length, 2);
  assert.equal(list.filter((x) => x.current).length, 1);
  const other = list.find((x) => !x.current);
  s.revokeSession(p, other.id);
  assert.equal(s.listSessions(p, p.id).length, 1);
  const m = s.authenticate((await login('manager@acme.test')).accessToken);
  await rejects(() => s.logoutAll(m, u.admin.id), 'forbidden');
  s.close();
});

import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { createAuth, errorHandler, startServer, runDemo } from '../src/index.js';
import { seeded, PW } from './helpers.js';

async function listen(app) {
  return new Promise((resolve) => {
    const srv = app.listen(0, '127.0.0.1', () => resolve({ url: `http://127.0.0.1:${srv.address().port}`, close: () => new Promise((r) => srv.close(r)) }));
  });
}

test('middleware protects an existing Express app (authorize with resolver, requireRole)', async () => {
  const { s, u, login } = await seeded();
  const auth = createAuth(s);
  const invoices = new Map([
    ['inv1', { id: 'inv1', tenantId: u.user.tenantId, ownerId: u.user.id, teamId: 'sales' }],
    ['inv2', { id: 'inv2', tenantId: u.other.tenantId, ownerId: u.other.id, teamId: 'support' }],
    ['inv3', { id: 'inv3', tenantId: 'another-tenant', ownerId: 'x', teamId: 'sales' }],
  ]);
  const app = express();
  app.get('/invoices/:id', auth.authenticate(), auth.authorize('projects:read', (req) => invoices.get(req.params.id)), (req, res) => res.json({ id: req.target.id, scope: req.authz.scope }));
  app.get('/billing', auth.authenticate(), auth.authorize('billing:read'), (_req, res) => res.json({ ok: true }));
  app.get('/team', auth.authenticate(), auth.requireRole('manager'), (_req, res) => res.json({ ok: true }));
  app.use(errorHandler({ log: () => {} }));
  const srv = await listen(app);
  const get = async (path, token) => {
    const r = await fetch(srv.url + path, { headers: token ? { authorization: `Bearer ${token}` } : {} });
    return { status: r.status, body: await r.json(), www: r.headers.get('www-authenticate') };
  };
  try {
    const user = (await login('user@acme.test')).accessToken;
    const mgr = (await login('manager@acme.test')).accessToken;
    const admin = (await login('admin@acme.test')).accessToken;
    assert.equal((await get('/invoices/inv1')).status, 401);
    assert.match((await get('/invoices/inv1')).www, /Bearer/);
    assert.equal((await get('/invoices/inv1', 'Basic abc')).status, 401);
    assert.deepEqual((await get('/invoices/inv1', user)).body, { id: 'inv1', scope: 'own' });
    assert.equal((await get('/invoices/inv2', user)).status, 403);
    assert.equal((await get('/invoices/inv3', admin)).status, 404, 'other tenant looks like not found');
    assert.equal((await get('/invoices/missing', admin)).status, 404);
    assert.equal((await get('/billing', mgr)).status, 403);
    assert.equal((await get('/billing', admin)).status, 200);
    assert.equal((await get('/team', user)).status, 403);
    assert.equal((await get('/team', mgr)).status, 200);
  } finally {
    await srv.close();
    s.close();
  }
});

test('REST API: per-IP login rate limit, JSON errors, signup off by default, discovery', async () => {
  const { s } = await seeded({ server: { loginPerIpPerMin: 3, trustProxy: false, port: 0, allowSignup: false, corsOrigins: ['https://app.test'] } });
  const srv = await startServer(s, { port: 0, host: '127.0.0.1', log: () => {} });
  const post = (path, body, headers = {}) => fetch(srv.url + path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body });
  try {
    const statuses = [];
    for (let i = 0; i < 4; i++) statuses.push((await post('/auth/login', JSON.stringify({ tenant: 'acme', email: 'user@acme.test', password: 'Wrong-pass-1' }))).status);
    assert.deepEqual(statuses, [401, 401, 401, 429]);
    const bad = await post('/auth/refresh', '{not json');
    assert.equal(bad.status, 400);
    assert.equal((await bad.json()).error.code, 'invalid_request');
    assert.equal((await post('/auth/register', JSON.stringify({ tenant: 'acme', email: 'n@acme.test', password: PW }))).status, 429, 'register shares the login throttle');
    const oidc = await (await fetch(srv.url + '/.well-known/openid-configuration')).json();
    assert.match(oidc.jwks_uri, /jwks\.json$/);
    const r404 = await fetch(srv.url + '/nope');
    assert.equal(r404.status, 404);
    assert.equal(r404.headers.get('x-powered-by'), null);
    const cors = await fetch(srv.url + '/healthz', { method: 'OPTIONS', headers: { origin: 'https://app.test' } });
    assert.equal(cors.headers.get('access-control-allow-origin'), 'https://app.test');
    const noCors = await fetch(srv.url + '/healthz', { headers: { origin: 'https://evil.test' } });
    assert.equal(noCors.headers.get('access-control-allow-origin'), null);
  } finally {
    await srv.close();
    s.close();
  }
});

test('self sign-up when enabled creates the default role', async () => {
  const { s } = await seeded({ server: { loginPerIpPerMin: 100, trustProxy: false, port: 0, allowSignup: true, corsOrigins: [] } });
  const srv = await startServer(s, { port: 0, host: '127.0.0.1', log: () => {} });
  try {
    const r = await fetch(srv.url + '/auth/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ tenant: 'acme', email: 'new@acme.test', password: PW, role: 'admin' }) });
    assert.equal(r.status, 201);
    assert.equal((await r.json()).user.role, 'user', 'role in the body is ignored');
  } finally {
    await srv.close();
    s.close();
  }
});

for (const algorithm of ['ES256', 'RS256', 'HS256']) {
  test(`full attack/permission demo passes with ${algorithm}`, async () => {
    const r = await runDemo({ algorithm, bcryptRounds: 4 });
    assert.equal(r.failed, 0, JSON.stringify(r.results.filter((x) => !x.ok), null, 2));
    assert.ok(r.passed >= 55);
  });
}

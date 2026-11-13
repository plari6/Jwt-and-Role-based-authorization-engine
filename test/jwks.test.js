import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { createJwksVerifier, startServer, errorHandler } from '../src/index.js';
import { seeded } from './helpers.js';

test('another service verifies tokens with only the public JWKS, and follows key rotation', async () => {
  const { s, login } = await seeded({ issuer: 'http://auth.test', audience: 'test-api' });
  const auth = await startServer(s, { port: 0, host: '127.0.0.1', log: () => {} });
  let fetches = 0;
  const verifier = createJwksVerifier({
    jwksUri: `${auth.url}/.well-known/jwks.json`,
    issuer: 'http://auth.test',
    audience: 'test-api',
    minRefetchSec: 0,
    fetch: (...a) => {
      fetches++;
      return fetch(...a);
    },
  });
  const app = express();
  app.get('/reports', verifier.middleware(), verifier.authorize('reports:read'), (req, res) => res.json({ role: req.auth.role, scope: req.authz.scope }));
  app.use(errorHandler({ log: () => {} }));
  const api = await new Promise((r) => {
    const srv = app.listen(0, '127.0.0.1', () => r({ url: `http://127.0.0.1:${srv.address().port}`, close: () => new Promise((x) => srv.close(x)) }));
  });
  const get = async (token) => (await fetch(api.url + '/reports', { headers: token ? { authorization: `Bearer ${token}` } : {} })).status;
  try {
    const admin = (await login('admin@acme.test')).accessToken;
    const user = (await login('user@acme.test')).accessToken;
    assert.equal(await get(admin), 200);
    assert.equal(await get(user), 403);
    assert.equal(await get(null), 401);
    assert.equal(await get(admin.slice(0, -4) + 'AAAA'), 401);
    assert.equal(fetches, 1, 'JWKS is cached');
    s.keys.rotate();
    const fresh = (await login('admin@acme.test')).accessToken;
    assert.equal(await get(fresh), 200, 'unknown kid triggers a JWKS refetch');
    assert.equal(fetches, 2);
    assert.equal(await get(admin), 200, 'token signed with the retiring key still verifies');
  } finally {
    await api.close();
    await auth.close();
    s.close();
  }
});

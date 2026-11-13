import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { KeyStore, TokenService } from '../src/index.js';

const user = { id: 'u1', tenantId: 't1', role: 'manager', teamId: 'sales', tokenVersion: 1 };
const svc = (keys, o = {}) => new TokenService({ keys, issuer: 'https://auth.test', audience: 'api', accessTtlSec: 900, ...o });

for (const alg of ['ES256', 'RS256', 'HS256']) {
  test(`${alg}: sign and verify round trip`, () => {
    const keys = new KeyStore({ alg, hsSecret: 'x'.repeat(48), memory: true }).load();
    const t = svc(keys);
    const { token } = t.signAccess(user, { sessionId: 's1' });
    const c = t.verifyAccess(token);
    assert.equal(c.sub, 'u1');
    assert.equal(c.role, 'manager');
    assert.equal(c.team, 'sales');
    assert.equal(c.sid, 's1');
    assert.equal(jwt.decode(token, { complete: true }).header.typ, 'at+jwt');
  });
}

test('HS256 requires a long secret', () => {
  assert.throws(() => new KeyStore({ alg: 'HS256', hsSecret: 'short', memory: true }), /32 bytes/);
});

test('rejects wrong audience, issuer and algorithm', () => {
  const keys = new KeyStore({ alg: 'ES256', memory: true }).load();
  const { token } = svc(keys).signAccess(user, { sessionId: 's1' });
  assert.throws(() => svc(keys, { audience: 'other' }).verifyAccess(token), (e) => e.code === 'token_invalid');
  assert.throws(() => svc(keys, { issuer: 'https://evil' }).verifyAccess(token), (e) => e.code === 'token_invalid');
  const none = `${Buffer.from('{"alg":"none","typ":"at+jwt"}').toString('base64url')}.${token.split('.')[1]}.`;
  assert.throws(() => svc(keys).verifyAccess(none), (e) => e.code === 'token_invalid');
  assert.throws(() => svc(keys).verifyAccess('abc'), (e) => e.code === 'token_malformed');
});

test('expired token gives token_expired', () => {
  const keys = new KeyStore({ alg: 'ES256', memory: true }).load();
  const t = svc(keys, { clockToleranceSec: 0 });
  const { kid, key } = keys.signingKey();
  const now = Math.floor(Date.now() / 1000);
  const tok = jwt.sign({ tid: 't1', role: 'user', tv: 1, sid: 's', iat: now - 100, exp: now - 10 }, key, { algorithm: 'ES256', issuer: 'https://auth.test', audience: 'api', subject: 'u1', header: { alg: 'ES256', typ: 'at+jwt', kid } });
  assert.throws(() => t.verifyAccess(tok), (e) => e.code === 'token_expired');
});

test('rotation: old tokens keep verifying until the old key is pruned', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'authz-keys-'));
  try {
    const keys = new KeyStore({ alg: 'ES256', dir }).load();
    const t = svc(keys);
    const old = t.signAccess(user, { sessionId: 's1' }).token;
    const newKid = keys.rotate();
    const fresh = t.signAccess(user, { sessionId: 's1' }).token;
    assert.equal(jwt.decode(fresh, { complete: true }).header.kid, newKid);
    assert.equal(t.verifyAccess(old).sub, 'u1');
    assert.equal(keys.jwks().keys.length, 2);
    assert.equal(keys.prune(-1), 1);
    assert.throws(() => t.verifyAccess(old), (e) => e.code === 'token_invalid');
    assert.equal(t.verifyAccess(fresh).sub, 'u1');
    // persisted with private keys, JWKS without them
    const saved = JSON.parse(fs.readFileSync(path.join(dir, 'keyset.json'), 'utf8'));
    assert.ok(saved.keys[0].privateJwk.d);
    assert.ok(keys.jwks().keys.every((k) => !k.d));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a running server picks up a rotation made by another process', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'authz-keys-'));
  try {
    const server = new KeyStore({ alg: 'ES256', dir }).load();
    const before = server.signingKey().kid;
    const cli = new KeyStore({ alg: 'ES256', dir }).load({ create: false });
    const newKid = cli.rotate();
    fs.utimesSync(path.join(dir, 'keyset.json'), new Date(), new Date(Date.now() + 2000)); // make mtime differ on coarse filesystems
    server.lastCheck = 0;
    assert.equal(server.signingKey().kid, newKid);
    assert.ok(server.verifyKey(before), 'old key still verifies');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('refresh tokens are random and only hashes are comparable', async () => {
  const { newRefreshToken, hashRefreshToken } = await import('../src/index.js');
  const a = newRefreshToken();
  const b = newRefreshToken();
  assert.notEqual(a.token, b.token);
  assert.equal(hashRefreshToken(a.token), a.hash);
  assert.equal(a.hash, crypto.createHash('sha256').update(a.token).digest('hex'));
});

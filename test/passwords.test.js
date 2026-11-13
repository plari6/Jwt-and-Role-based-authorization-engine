import test from 'node:test';
import assert from 'node:assert/strict';
import { hashPassword, verifyPassword, checkPasswordPolicy, generatePassword, DEFAULTS } from '../src/index.js';

const opts = { rounds: 4, pepper: 'pepper-1' };

test('hash and verify', async () => {
  const h = await hashPassword('Correct-Horse-9', opts);
  assert.match(h, /^\$2[aby]\$04\$/);
  assert.deepEqual(await verifyPassword('Correct-Horse-9', h, opts), { ok: true, needsRehash: false });
  assert.equal((await verifyPassword('correct-horse-9', h, opts)).ok, false);
});

test('pepper is required to verify (stolen DB alone is useless)', async () => {
  const h = await hashPassword('Correct-Horse-9', opts);
  assert.equal((await verifyPassword('Correct-Horse-9', h, { ...opts, pepper: 'other' })).ok, false);
});

test('no 72-byte truncation: long passwords differing at the end are different', async () => {
  const base = 'A1!' + 'x'.repeat(80);
  const h = await hashPassword(base + 'one', opts);
  assert.equal((await verifyPassword(base + 'two', h, opts)).ok, false);
  assert.equal((await verifyPassword(base + 'one', h, opts)).ok, true);
});

test('needsRehash when cost factor changes', async () => {
  const h = await hashPassword('Correct-Horse-9', opts);
  assert.equal((await verifyPassword('Correct-Horse-9', h, { ...opts, rounds: 5 })).needsRehash, true);
});

test('unknown user path never succeeds', async () => {
  assert.deepEqual(await verifyPassword('anything', null, opts), { ok: false, needsRehash: false });
});

test('password policy', () => {
  const pol = DEFAULTS.passwordPolicy;
  assert.deepEqual(checkPasswordPolicy('Tr0ub4dor&3x', pol), []);
  assert.ok(checkPasswordPolicy('short1A', pol).some((p) => p.includes('at least 10')));
  assert.ok(checkPasswordPolicy('password123', pol).some((p) => p.includes('commonly used')));
  assert.ok(checkPasswordPolicy('Password123!', pol).some((p) => p.includes('commonly used')));
  assert.ok(checkPasswordPolicy('alllowercaseletters', pol).some((p) => p.includes('mix')));
  assert.ok(checkPasswordPolicy('Jonathan-2024!', pol, { email: 'jonathan@x.com' }).some((p) => p.includes('email')));
});

test('generated passwords always pass the policy', () => {
  for (let i = 0; i < 200; i++) assert.deepEqual(checkPasswordPolicy(generatePassword(), DEFAULTS.passwordPolicy), []);
});

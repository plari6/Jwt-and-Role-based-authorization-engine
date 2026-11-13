import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const BIN = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'authz.js');
const PW = 'Cli-Passw0rd!x';

function cli(cwd, args, env = {}) {
  const r = spawnSync(process.execPath, [BIN, ...args], { cwd, env: { ...process.env, AUTHZ_CONFIG: '', CLI_PW: PW, ...env }, encoding: 'utf8' });
  return { code: r.status, out: r.stdout, err: r.stderr, json: () => JSON.parse(r.stdout) };
}

test('CLI: init, users, roles, can, login, verify, keys, policy, audit', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'authz-cli-'));
  try {
    let r = cli(dir, ['--json', 'init', '--tenant', 'acme', '--email', 'boss@acme.test', '--password-env', 'CLI_PW']);
    assert.equal(r.code, 0, r.err);
    for (const f of ['authz.config.json', 'policy.json', '.env', 'keys/keyset.json', 'data/authz.db']) assert.ok(fs.existsSync(path.join(dir, f)), f);
    assert.match(fs.readFileSync(path.join(dir, '.env'), 'utf8'), /^AUTHZ_PEPPER=.{40,}/m);
    // lower bcrypt cost to keep the test fast
    const cfgPath = path.join(dir, 'authz.config.json');
    fs.writeFileSync(cfgPath, JSON.stringify({ ...JSON.parse(fs.readFileSync(cfgPath, 'utf8')), bcryptRounds: 4 }));

    r = cli(dir, ['init']);
    assert.match(r.out, /nothing overwritten/);

    assert.equal(cli(dir, ['user', 'add', '-t', 'acme', '--email', 'mark@acme.test', '--role', 'manager', '--team', 'sales', '--password-env', 'CLI_PW']).code, 0);
    r = cli(dir, ['--json', 'user', 'add', '-t', 'acme', '--email', 'sam@acme.test', '--team', 'support']);
    assert.ok(r.json().temporaryPassword);
    assert.equal(cli(dir, ['--json', 'user', 'list', '-t', 'acme']).json().length, 3);

    r = cli(dir, ['can', 'mark@acme.test', 'projects:update', '-t', 'acme', '--owner', 'sam@acme.test']);
    assert.equal(r.code, 2);
    assert.match(r.out, /DENY.*outside your team/);
    r = cli(dir, ['can', 'boss@acme.test', 'users:delete', '-t', 'acme', '--target-user', 'sam@acme.test']);
    assert.equal(r.code, 0);
    assert.match(r.out, /ALLOW/);

    r = cli(dir, ['user', 'role', 'boss@acme.test', 'user', '-t', 'acme']);
    assert.equal(r.code, 3);
    assert.match(r.err, /last active admin/);

    r = cli(dir, ['--json', 'login', '-t', 'acme', '--email', 'mark@acme.test', '--password-env', 'CLI_PW']);
    assert.equal(r.code, 0, r.err);
    const token = r.json().accessToken;
    r = cli(dir, ['--json', 'token', 'verify', token]);
    assert.equal(r.json().state, 'valid');
    assert.equal(r.json().claims.role, 'manager');

    r = cli(dir, ['--json', 'keys', 'rotate']);
    assert.equal(r.code, 0);
    assert.equal(cli(dir, ['--json', 'keys', 'list']).json().length, 2);
    assert.equal(cli(dir, ['--json', 'token', 'verify', token]).json().state, 'valid', 'old token verifies after rotation');

    cli(dir, ['user', 'role', 'mark@acme.test', 'user', '-t', 'acme']);
    r = cli(dir, ['--json', 'token', 'verify', token]);
    assert.equal(r.json().state, 'token_revoked');
    assert.equal(r.code, 1);

    assert.equal(cli(dir, ['user', 'disable', 'sam@acme.test', '-t', 'acme']).code, 0);
    assert.equal(cli(dir, ['--json', 'user', 'list', '-t', 'acme', '--status', 'disabled']).json().length, 1);

    assert.equal(cli(dir, ['policy', 'check']).code, 0);
    fs.writeFileSync(path.join(dir, 'bad.json'), JSON.stringify({ defaultRole: 'user', roles: { user: { level: 1 }, boss: { level: 9 } }, assignable: { user: ['boss'] } }));
    r = cli(dir, ['policy', 'check', 'bad.json']);
    assert.equal(r.code, 1);
    assert.match(r.out, /privilege escalation/);
    assert.match(cli(dir, ['policy', 'show']).out, /users:read\s+-\s+team\s+tenant/);

    const audit = cli(dir, ['--json', 'audit', '-t', 'acme', '--action', 'user.*']).json();
    assert.ok(audit.some((e) => e.action === 'user.role_change'));
    assert.ok(audit.some((e) => e.action === 'user.disable'));

    r = cli(dir, ['--json', 'check']);
    assert.equal(r.json().ok, true);
    assert.equal(JSON.stringify(r.json()).includes(fs.readFileSync(path.join(dir, '.env'), 'utf8').match(/AUTHZ_PEPPER=(.*)/)[1]), false, 'check never prints the pepper');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

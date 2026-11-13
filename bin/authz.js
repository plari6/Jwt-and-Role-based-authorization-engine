#!/usr/bin/env node
// @ts-check
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { Command, Option } from 'commander';
import jwt from 'jsonwebtoken';
import { AuthService, SYSTEM } from '../src/service.js';
import { DEFAULT_POLICY, loadPolicy, validatePolicy } from '../src/policy.js';
import { configWarnings, loadConfig, parseDuration } from '../src/config.js';
import { KeyStore } from '../src/keys.js';
import { startServer } from '../src/server.js';
import { runDemo } from '../src/demo.js';
import { AuthError } from '../src/errors.js';

/** Apply an option preset to a command: cmd.with(fn). */
// @ts-ignore
Command.prototype.with = function (/** @type {(c: Command) => any} */ fn) {
  fn(this);
  return this;
};

const program = new Command();
program
  .name('authz')
  .description('JWT & role-based authorization engine (Admin / Manager / User) for multi-tenant SaaS apps')
  .version('1.0.0')
  .option('-c, --config <file>', 'config file (default: ./authz.config.json if present)')
  .option('--env-file <file>', 'env file to load (default: ./.env if present)')
  .option('--json', 'machine-readable JSON output');

// ------------------------------------------------------------------ helpers
const g = () => program.opts();
function loadEnv() {
  const f = g().envFile || '.env';
  if (fs.existsSync(f)) process.loadEnvFile(f);
  else if (g().envFile) throw new Error(`env file not found: ${f}`);
}
/** @param {{createKeys?:boolean}} [o] */
function open(o = {}) {
  loadEnv();
  return AuthService.open({ configFile: g().config, createKeys: o.createKeys ?? false });
}
function out(/** @type {any} */ data, /** @type {() => void} */ human) {
  if (g().json) console.log(JSON.stringify(data, null, 2));
  else human();
}
function table(/** @type {Record<string, any>[]} */ rows, /** @type {string[]} */ cols) {
  if (!rows.length) return console.log('(none)');
  const w = cols.map((c) => Math.min(48, Math.max(c.length, ...rows.map((r) => String(r[c] ?? '').length))));
  const line = (/** @type {any[]} */ vals) => vals.map((v, i) => String(v ?? '').slice(0, w[i]).padEnd(w[i])).join('  ');
  console.log(line(cols));
  console.log(w.map((n) => '-'.repeat(n)).join('  '));
  for (const r of rows) console.log(line(cols.map((c) => r[c])));
}
/** Password from --password-env VAR, or --password (discouraged: shell history). */
function readPassword(/** @type {any} */ opts) {
  if (opts.passwordEnv) {
    const v = process.env[opts.passwordEnv];
    if (!v) throw new Error(`environment variable ${opts.passwordEnv} is empty`);
    return v;
  }
  if (opts.password) {
    if (!g().json) console.error('warning: --password ends up in shell history; prefer --password-env VAR');
    return opts.password;
  }
  return undefined;
}
function userByEmail(/** @type {AuthService} */ s, /** @type {string} */ tenant, /** @type {string} */ email) {
  const t = s.tenant(tenant);
  const u = s.store.userByEmail(t.id, String(email).trim().toLowerCase());
  if (!u) throw new AuthError('not_found', 404, `No user ${email} in tenant ${tenant}`);
  return u;
}
/** Run an action with an opened service, close it, map errors to exit codes. */
function action(/** @type {(s:AuthService, ...args:any[]) => any} */ fn, /** @type {{createKeys?:boolean}} */ o = {}) {
  return async (/** @type {any[]} */ ...args) => {
    const s = open(o);
    try {
      await fn(s, ...args);
    } finally {
      s.close();
    }
  };
}
const pwOpts = (/** @type {Command} */ c) =>
  c.option('--password-env <VAR>', 'read the password from this environment variable').addOption(new Option('--password <pw>', 'password (visible in shell history)').hideHelp());
const tenantOpt = (/** @type {Command} */ c) => c.requiredOption('-t, --tenant <slug>', 'tenant (organisation) slug');

// ------------------------------------------------------------------ init / check
program
  .command('init')
  .description('create authz.config.json, policy.json, .env (pepper), signing keys and the database; optionally the first tenant + admin')
  .option('--tenant <slug>', 'first tenant slug, e.g. acme')
  .option('--tenant-name <name>', 'tenant display name')
  .option('--email <email>', 'first admin email')
  .option('--name <name>', 'first admin name')
  .addOption(new Option('--alg <alg>', 'signing algorithm').choices(['ES256', 'RS256', 'HS256']).default('ES256'))
  .option('--issuer <url>', 'token issuer (your auth API base URL)', 'http://localhost:4000')
  .option('--audience <aud>', 'token audience (your API name)', 'saas-api')
  .with(pwOpts)
  .action(async (o) => {
    const cfgFile = g().config || 'authz.config.json';
    const created = [];
    if (!fs.existsSync(cfgFile)) {
      const cfg = {
        issuer: o.issuer,
        audience: o.audience,
        algorithm: o.alg,
        accessTtl: '15m',
        refreshTtlDays: 30,
        refreshIdleDays: 7,
        dbPath: './data/authz.db',
        keysDir: './keys',
        policyFile: './policy.json',
        bcryptRounds: 12,
        passwordPolicy: { minLength: 10, maxLength: 128, blockCommon: true, requireClasses: 2 },
        lockout: { maxAttempts: 5, lockMinutes: 15 },
        server: { port: 4000, trustProxy: false, loginPerIpPerMin: 20, allowSignup: false, corsOrigins: [] },
      };
      fs.writeFileSync(cfgFile, JSON.stringify(cfg, null, 2) + '\n');
      created.push(cfgFile);
    }
    const dir = path.dirname(path.resolve(cfgFile));
    const policyPath = path.join(dir, 'policy.json');
    if (!fs.existsSync(policyPath)) {
      fs.writeFileSync(policyPath, JSON.stringify(DEFAULT_POLICY, null, 2) + '\n');
      created.push('policy.json');
    }
    const envPath = g().envFile || path.join(dir, '.env');
    const envText = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf8') : '';
    const add = [];
    if (!/^AUTHZ_PEPPER=/m.test(envText)) add.push(`AUTHZ_PEPPER=${crypto.randomBytes(32).toString('base64url')}`);
    if (o.alg === 'HS256' && !/^AUTHZ_HS_SECRET=/m.test(envText)) add.push(`AUTHZ_HS_SECRET=${crypto.randomBytes(48).toString('base64url')}`);
    if (add.length) {
      fs.appendFileSync(envPath, (envText && !envText.endsWith('\n') ? '\n' : '') + `# jwt-rbac-engine secrets - never commit, never change after users exist\n${add.join('\n')}\n`, { mode: 0o600 });
      created.push(`${path.basename(envPath)} (${add.map((l) => l.split('=')[0]).join(', ')})`);
    }
    const s = open({ createKeys: true });
    try {
      /** @type {any} */
      let boot = null;
      if (o.tenant && o.email) boot = await s.bootstrap({ tenant: o.tenant, tenantName: o.tenantName, email: o.email, name: o.name, password: readPassword(o) });
      else if (o.tenant) boot = { tenant: s.store.tenantBySlug(o.tenant) || s.createTenant({ slug: o.tenant, name: o.tenantName }) };
      out({ created, keys: s.keys.list(), db: s.config.dbPath, bootstrap: boot }, () => {
        console.log(created.length ? `Created: ${created.join(', ')}` : 'Config already present - nothing overwritten');
        console.log(`Keys: ${s.keys.list().map((k) => `${k.kid} (${k.alg}, ${k.status})`).join(', ')}`);
        console.log(`Database: ${s.config.dbPath}`);
        if (boot?.user) {
          console.log(`Tenant "${boot.tenant.slug}" with admin ${boot.user.email}`);
          if (boot.temporaryPassword) console.log(`Temporary password (shown once): ${boot.temporaryPassword}`);
        } else if (boot?.tenant) console.log(`Tenant "${boot.tenant.slug}" ready - add an admin with: authz user add -t ${boot.tenant.slug} --email you@x.com --role admin`);
        console.log('Next: authz check, then authz serve');
      });
    } finally {
      s.close();
    }
  });

program
  .command('check')
  .description('validate config, policy, keys and database; print production warnings')
  .action(() => {
    loadEnv();
    const cfg = loadConfig({ file: g().config });
    const warnings = configWarnings(cfg);
    const policyDoc = fs.existsSync(cfg.policyFile) ? JSON.parse(fs.readFileSync(cfg.policyFile, 'utf8')) : DEFAULT_POLICY;
    const policyProblems = validatePolicy(policyDoc);
    /** @type {any} */
    let keys = null;
    let keyError = '';
    try {
      keys = new KeyStore({ alg: cfg.algorithm, dir: cfg.keysDir }).load({ create: false }).list();
    } catch (e) {
      keyError = /** @type {Error} */ (e).message;
    }
    /** @type {any} */
    let tenants = [];
    if (fs.existsSync(cfg.dbPath)) {
      const s = AuthService.open({ configFile: g().config, createKeys: false });
      tenants = s.store.listTenants();
      for (const t of tenants) if (s.store.countActiveWithRoles(t.id, s.policy.topRoles()) === 0) warnings.push(`tenant "${t.slug}" has no active admin`);
      s.close();
    } else warnings.push(`database ${cfg.dbPath} does not exist yet (run authz init)`);
    const ok = !policyProblems.length && !keyError;
    out({ ok, config: { ...cfg, pepper: cfg.pepper ? '(set)' : '' }, policyProblems, keyError, keys, tenants, warnings }, () => {
      console.log(`Issuer ${cfg.issuer} | audience ${cfg.audience} | ${cfg.algorithm} | access ${cfg.accessTtlSec}s | refresh ${cfg.refreshTtlDays}d (idle ${cfg.refreshIdleDays}d) | bcrypt ${cfg.bcryptRounds}`);
      console.log(`Policy ${fs.existsSync(cfg.policyFile) ? cfg.policyFile : '(built-in default)'}: ${policyProblems.length ? 'INVALID' : 'ok'}`);
      for (const p of policyProblems) console.log(`  x ${p}`);
      console.log(`Keys: ${keyError ? 'ERROR ' + keyError : keys.map((/** @type {any} */ k) => `${k.kid} ${k.status}`).join(', ')}`);
      console.log(`Tenants: ${tenants.map((/** @type {any} */ t) => `${t.slug} (${t.users} users)`).join(', ') || '(none)'}`);
      for (const w of warnings) console.log(`  ! ${w}`);
      console.log(ok ? 'OK' : 'NOT OK');
    });
    if (!ok) process.exitCode = 1;
  });

// ------------------------------------------------------------------ tenants
const tenant = program.command('tenant').description('manage tenants (organisations)');
tenant
  .command('create <slug>')
  .option('--name <name>', 'display name')
  .action(action((s, slug, o) => out(s.createTenant({ slug, name: o.name }), () => console.log(`Created tenant ${slug}`))));
tenant.command('list').action(action((s) => out(s.store.listTenants(), () => table(s.store.listTenants(), ['slug', 'name', 'users', 'createdAt']))));

// ------------------------------------------------------------------ users
const user = program.command('user').description('manage users (operator access - bypasses role checks, keeps safety rails)');
user
  .command('add')
  .with(tenantOpt)
  .requiredOption('--email <email>')
  .option('--name <name>')
  .option('--role <role>', 'role (default: policy defaultRole)')
  .option('--team <team>', 'team id, e.g. sales')
  .with(pwOpts)
  .action(action(async (s, o) => {
    const r = await s.createUser(SYSTEM, { tenant: o.tenant, email: o.email, name: o.name, role: o.role, teamId: o.team, password: readPassword(o) });
    out(r, () => {
      console.log(`Created ${r.user.email} (${r.user.role}${r.user.teamId ? ', team ' + r.user.teamId : ''}) id=${r.user.id}`);
      if (r.temporaryPassword) console.log(`Temporary password (shown once): ${r.temporaryPassword}`);
    });
  }));
user
  .command('list')
  .with(tenantOpt)
  .option('--role <role>')
  .option('--status <status>', 'active | disabled')
  .option('--team <team>')
  .action(action((s, o) => {
    const rows = s.listUsers(SYSTEM, { tenant: o.tenant, role: o.role, status: o.status, teamId: o.team });
    out(rows, () => table(rows.map((u) => ({ ...u, locked: u.locked ? 'LOCKED' : '' })), ['email', 'name', 'role', 'teamId', 'status', 'locked', 'lastLoginAt', 'id']));
  }));
user
  .command('role <email> <role>')
  .description('change role (instantly invalidates the user\'s access tokens)')
  .with(tenantOpt)
  .action(action((s, email, role, o) => {
    const u = s.changeRole(SYSTEM, userByEmail(s, o.tenant, email).id, role);
    out(u, () => console.log(`${u.email} is now ${u.role}`));
  }));
user
  .command('team <email> <team>')
  .description('move a user to a team ("none" removes the team)')
  .with(tenantOpt)
  .action(action((s, email, team, o) => {
    const u = s.updateUser(SYSTEM, userByEmail(s, o.tenant, email).id, { teamId: team === 'none' ? null : team });
    out(u, () => console.log(`${u.email} team: ${u.teamId ?? '(none)'}`));
  }));
for (const [cmd, desc] of /** @type {const} */ ([['disable', 'disable and sign out everywhere'], ['enable', 're-enable'], ['unlock', 'clear failed-login lockout'], ['delete', 'delete permanently'], ['logout-all', 'sign out of every device']])) {
  user
    .command(`${cmd} <email>`)
    .description(desc)
    .with(tenantOpt)
    .action(action((s, email, o) => {
      const id = userByEmail(s, o.tenant, email).id;
      const r =
        cmd === 'disable' ? s.setStatus(SYSTEM, id, 'disabled')
        : cmd === 'enable' ? s.setStatus(SYSTEM, id, 'active')
        : cmd === 'unlock' ? s.unlock(SYSTEM, id)
        : cmd === 'delete' ? s.deleteUser(SYSTEM, id)
        : s.logoutAll(SYSTEM, id);
      out(r, () => console.log(`${email}: ${cmd} done`));
    }));
}
user
  .command('reset-password <email>')
  .description('set a new password (generated if none given), unlock, sign out everywhere')
  .with(tenantOpt)
  .with(pwOpts)
  .action(action(async (s, email, o) => {
    const r = await s.resetPassword(SYSTEM, userByEmail(s, o.tenant, email).id, readPassword(o));
    out(r, () => {
      console.log(`${email}: password reset, ${r.sessionsRevoked} session(s) signed out`);
      if (r.temporaryPassword) console.log(`Temporary password (shown once): ${r.temporaryPassword}`);
    });
  }));
user
  .command('sessions <email>')
  .with(tenantOpt)
  .action(action((s, email, o) => {
    const rows = s.listSessions(SYSTEM, userByEmail(s, o.tenant, email).id);
    out(rows, () => table(/** @type {any[]} */ (rows), ['id', 'createdAt', 'lastUsedAt', 'ip', 'userAgent']));
  }));
program
  .command('session-revoke <sessionId>')
  .description('sign out one session')
  .action(action((s, id) => out(s.revokeSession(SYSTEM, id), () => console.log(`session ${id} revoked`))));

// ------------------------------------------------------------------ tokens
program
  .command('login')
  .description('log in and print access + refresh tokens (for testing APIs with curl)')
  .option('-t, --tenant <slug>', 'tenant slug (optional when the email is in one tenant)')
  .requiredOption('--email <email>')
  .with(pwOpts)
  .action(action(async (s, o) => {
    const password = readPassword(o);
    if (!password) throw new Error('give --password-env VAR (or --password)');
    const r = await s.login({ tenant: o.tenant, email: o.email, password }, { ip: 'cli', userAgent: 'authz-cli' });
    out(r, () => {
      console.log(`Logged in as ${r.user.email} (${r.user.role}) in ${r.tenant}; access token valid ${r.expiresIn}s`);
      console.log(`\nACCESS_TOKEN=${r.accessToken}\n\nREFRESH_TOKEN=${r.refreshToken}`);
    });
  }));

const token = program.command('token').description('inspect tokens');
token
  .command('verify <jwt>')
  .description('verify signature, claims and live account state (revoked? disabled? role changed?)')
  .action(action((s, t) => {
    const claims = s.tokens.verifyAccess(t);
    let state = 'valid';
    /** @type {any} */
    let principal = null;
    try {
      principal = s.authenticate(t);
    } catch (e) {
      state = /** @type {any} */ (e).code;
    }
    out({ valid: state === 'valid', state, claims, principal }, () => {
      console.log(`Signature + claims: OK (kid ${jwt.decode(t, { complete: true })?.header.kid})`);
      console.log(`Live state: ${state}`);
      console.log(`sub=${claims.sub} tenant=${claims.tid} role=${claims.role} team=${claims.team ?? '-'} session=${claims.sid}`);
      console.log(`expires ${new Date(claims.exp * 1000).toISOString()} (${claims.exp - Math.floor(Date.now() / 1000)}s left)`);
    });
    if (state !== 'valid') process.exitCode = 1;
  }));
token
  .command('decode <jwt>')
  .description('decode WITHOUT verifying (debugging only)')
  .action((t) => {
    const d = jwt.decode(t, { complete: true });
    if (!d) throw new Error('not a JWT');
    console.log(JSON.stringify({ header: d.header, payload: d.payload, warning: 'NOT VERIFIED' }, null, 2));
  });

// ------------------------------------------------------------------ policy
program
  .command('can <email> <permission>')
  .description('explain whether a user may do resource:action (optionally on a target) - e.g. can mark@acme.com projects:update --owner sam@acme.com')
  .with(tenantOpt)
  .option('--owner <email>', 'target resource owner (same tenant)')
  .option('--team <team>', 'target resource team')
  .option('--target-user <email>', 'target is this user account')
  .action(action((s, email, permission, o) => {
    const u = userByEmail(s, o.tenant, email);
    const actor = { id: u.id, tenantId: u.tenantId, role: u.role, teamId: u.teamId };
    /** @type {any} */
    let target;
    if (o.targetUser) {
      const t = userByEmail(s, o.tenant, o.targetUser);
      target = { id: t.id, tenantId: t.tenantId, teamId: t.teamId };
    } else if (o.owner || o.team) {
      const owner = o.owner ? userByEmail(s, o.tenant, o.owner) : null;
      target = { tenantId: u.tenantId, ownerId: owner?.id ?? null, teamId: o.team ?? owner?.teamId ?? null };
    }
    const d = s.can(actor, permission, target);
    const extra = u.status !== 'active' ? ' (but the account is disabled)' : '';
    out({ user: u.email, role: u.role, permission, target, ...d, accountActive: u.status === 'active' }, () =>
      console.log(`${d.allowed ? 'ALLOW' : 'DENY'}  ${u.email} (${u.role}${u.teamId ? '/' + u.teamId : ''}) ${permission}${target ? ' on target' : ''}: ${d.reason}${extra}`),
    );
    if (!d.allowed) process.exitCode = 2;
  }));

const policy = program.command('policy').description('inspect and validate the role policy');
policy
  .command('show')
  .description('role -> permission matrix')
  .action(() => {
    loadEnv();
    const cfg = loadConfig({ file: g().config });
    const p = loadPolicy(cfg.policyFile);
    out({ roles: p.roles.map((r) => ({ role: r, level: p.level(r), permissions: p.permissionsOf(r), canAssign: p.doc.assignable?.[r] || [] })), matrix: p.matrix() }, () => {
      for (const r of p.roles) console.log(`${r.padEnd(10)} level ${String(p.level(r)).padEnd(4)} can assign: ${(p.doc.assignable?.[r] || []).join(', ') || '-'}`);
      console.log('');
      table(p.matrix(), ['permission', ...p.roles]);
    });
  });
policy
  .command('check [file]')
  .description('validate a policy file (cycles, unknown roles, escalation paths)')
  .action((file) => {
    loadEnv();
    const f = file || loadConfig({ file: g().config }).policyFile;
    if (!fs.existsSync(f)) throw new Error(`policy file not found: ${f}`);
    const problems = validatePolicy(JSON.parse(fs.readFileSync(f, 'utf8')));
    out({ file: f, ok: !problems.length, problems }, () => {
      console.log(problems.length ? `${f}: INVALID` : `${f}: OK`);
      for (const p of problems) console.log(`  x ${p}`);
    });
    if (problems.length) process.exitCode = 1;
  });
policy
  .command('init')
  .description('write the default policy.json for editing')
  .option('--force', 'overwrite')
  .action((o) => {
    const f = 'policy.json';
    if (fs.existsSync(f) && !o.force) throw new Error('policy.json exists (use --force)');
    fs.writeFileSync(f, JSON.stringify(DEFAULT_POLICY, null, 2) + '\n');
    console.log(`Wrote ${f}`);
  });

// ------------------------------------------------------------------ keys
const keys = program.command('keys').description('signing keys (rotation + JWKS)');
const keyStore = () => {
  loadEnv();
  const cfg = loadConfig({ file: g().config });
  return { cfg, ks: new KeyStore({ alg: cfg.algorithm, dir: cfg.keysDir }) };
};
keys.command('list').action(() => {
  const { ks } = keyStore();
  ks.load({ create: false });
  out(ks.list(), () => table(ks.list(), ['kid', 'alg', 'status', 'createdAt', 'retiredAt']));
});
keys
  .command('rotate')
  .description('new active key; the previous key keeps verifying until pruned')
  .option('--prune', `also remove retiring keys older than 2x access TTL`)
  .action((o) => {
    const { cfg, ks } = keyStore();
    ks.load({ create: false });
    const kid = ks.rotate();
    const pruned = o.prune ? ks.prune(cfg.accessTtlSec * 2) : 0;
    out({ kid, pruned, keys: ks.list() }, () => console.log(`New active key ${kid}${o.prune ? `, pruned ${pruned}` : ''}. Running servers pick it up within 5 s; tokens signed with the old key keep verifying.`));
  });
keys
  .command('prune')
  .option('--older-than <dur>', 'retired for longer than', '30m')
  .action((o) => {
    const { ks } = keyStore();
    ks.load({ create: false });
    const n = ks.prune(parseDuration(o.olderThan));
    console.log(`Removed ${n} retired key(s)`);
  });
keys.command('jwks').description('print the public JWKS').action(() => {
  const { ks } = keyStore();
  ks.load({ create: false });
  console.log(JSON.stringify(ks.jwks(), null, 2));
});

// ------------------------------------------------------------------ audit / maintenance
program
  .command('audit')
  .description('security audit log')
  .option('-t, --tenant <slug>')
  .option('--action <pattern>', 'e.g. auth.* or user.role_change')
  .option('--outcome <o>', 'ok | denied | failed | alert')
  .option('--since <dur>', 'e.g. 24h, 7d')
  .option('--limit <n>', 'max rows', '50')
  .action(action((s, o) => {
    const since = o.since ? new Date(Date.now() - parseDuration(o.since) * 1000).toISOString() : undefined;
    const rows = s.auditLog(SYSTEM, { tenant: o.tenant, action: o.action, outcome: o.outcome, since, limit: Number(o.limit) });
    out(rows, () => table(rows.map((r) => ({ ...r, detail: r.detail ? JSON.stringify(r.detail) : '' })), ['at', 'action', 'outcome', 'actorId', 'targetId', 'ip', 'detail']));
  }));
program
  .command('purge')
  .description('delete expired refresh tokens and old sessions')
  .action(action((s) => {
    const r = s.store.purgeExpired();
    out(r, () => console.log(`Deleted ${r.refreshTokens} expired refresh token(s), ${r.sessions} old session(s)`));
  }));

// ------------------------------------------------------------------ serve / demo
program
  .command('serve')
  .description('run the auth REST API')
  .option('-p, --port <n>', 'port (default config.server.port / PORT)')
  .option('--host <host>', 'bind address', '0.0.0.0')
  .action(async (o) => {
    const s = open({ createKeys: false });
    for (const w of configWarnings(s.config)) console.warn(`warning: ${w}`);
    const port = o.port ? Number(o.port) : s.config.server.port;
    const srv = /** @type {any} */ (await startServer(s, { port, host: o.host }));
    console.log(`authz API listening on :${port} (issuer ${s.config.issuer}, ${s.keys.alg}, JWKS at /.well-known/jwks.json)`);
    const stop = async () => {
      await srv.close();
      s.close();
      process.exit(0);
    };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
  });
program
  .command('demo')
  .description('spin up an in-memory engine + API and run ~65 security and permission checks (no setup needed)')
  .addOption(new Option('--alg <alg>').choices(['ES256', 'RS256', 'HS256']).default('ES256'))
  .action(async (o) => {
    const r = await runDemo({ log: g().json ? undefined : console.log, algorithm: o.alg });
    if (g().json) console.log(JSON.stringify(r, null, 2));
    if (r.failed) process.exitCode = 1;
  });

program.parseAsync().catch((e) => {
  if (g().json) console.log(JSON.stringify({ error: { code: e.code || 'error', message: e.message, details: e.details } }));
  else console.error(`error: ${e.message}${e.details?.problems ? '\n - ' + e.details.problems.join('\n - ') : ''}`);
  process.exitCode = e instanceof AuthError ? 3 : 1;
});

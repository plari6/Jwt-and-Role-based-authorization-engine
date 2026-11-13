// @ts-check
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { AuthService, SYSTEM } from './service.js';
import { startServer } from './server.js';
import { ACCESS_TYP } from './tokens.js';

const PW = 'Demo-Passw0rd!x';
const b64 = (/** @type {any} */ o) => Buffer.from(JSON.stringify(o)).toString('base64url');

/**
 * Self-contained demo: in-memory engine + live HTTP server, two tenants, Admin/Manager/User accounts,
 * then ~45 checks covering role scopes, privilege escalation, cross-tenant access, forged tokens,
 * refresh-token theft, instant revocation and lockout. Every check must match the expected status.
 * @param {{log?:(line:string)=>void, bcryptRounds?:number, algorithm?:'ES256'|'RS256'|'HS256'}} [o]
 */
export async function runDemo(o = {}) {
  const log = o.log || (() => {});
  const alg = o.algorithm || 'ES256';
  if (alg === 'HS256' && !process.env.AUTHZ_HS_SECRET) process.env.AUTHZ_HS_SECRET = crypto.randomBytes(48).toString('base64');
  const service = AuthService.open({
    memory: true,
    isolated: true,
    overrides: {
      algorithm: alg,
      bcryptRounds: o.bcryptRounds ?? 8,
      issuer: 'http://localhost:4000',
      audience: 'demo-api',
      server: { loginPerIpPerMin: 10_000, trustProxy: false, port: 0, allowSignup: false, corsOrigins: [] },
    },
  });
  const srv = /** @type {{url:string, close:()=>Promise<unknown>}} */ (await startServer(service, { port: 0, host: '127.0.0.1', log: () => {} }));

  /** @type {{name:string, expected:number, got:number, ok:boolean, note?:string}[]} */
  const results = [];
  let section = '';
  const call = async (/** @type {string} */ method, /** @type {string} */ path, /** @type {string|null} */ token, /** @type {any} */ body) => {
    const res = await fetch(srv.url + path, {
      method,
      headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body ? { 'content-type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    let json = null;
    try {
      json = await res.json();
    } catch {
      /* empty */
    }
    return { status: res.status, body: /** @type {any} */ (json) };
  };
  const check = (/** @type {string} */ name, /** @type {{status:number, body:any}} */ r, /** @type {number} */ expected, /** @type {(b:any)=>boolean} */ extra = () => true, /** @type {string} */ note = '') => {
    const ok = r.status === expected && extra(r.body);
    const code = r.body?.error?.code ? ` ${r.body.error.code}` : '';
    results.push({ name: `${section}${name}`, expected, got: r.status, ok, note: note || code.trim() });
    log(`${ok ? '  PASS' : '  FAIL'}  ${String(r.status).padEnd(3)} ${name}${code ? ` (${code.trim()})` : ''}${ok ? '' : `  <- expected ${expected}`}`);
    return r;
  };
  const head = (/** @type {string} */ t) => {
    section = '';
    log(`\n${t}`);
  };

  try {
    // ---------------------------------------------------------------- seed
    const acme = await service.bootstrap({ tenant: 'acme', tenantName: 'Acme Inc', email: 'alice@acme.test', password: PW, name: 'Alice (admin)' });
    const mark = (await service.createUser(SYSTEM, { tenant: 'acme', email: 'mark@acme.test', password: PW, name: 'Mark (manager, sales)', role: 'manager', teamId: 'sales' })).user;
    const ursula = (await service.createUser(SYSTEM, { tenant: 'acme', email: 'ursula@acme.test', password: PW, name: 'Ursula (user, sales)', role: 'user', teamId: 'sales' })).user;
    const sam = (await service.createUser(SYSTEM, { tenant: 'acme', email: 'sam@acme.test', password: PW, name: 'Sam (user, support)', role: 'user', teamId: 'support' })).user;
    await service.bootstrap({ tenant: 'globex', tenantName: 'Globex Corp', email: 'gina@globex.test', password: PW, name: 'Gina (admin)' });
    log(`Engine: ${alg}, issuer ${service.config.issuer}, server ${srv.url}`);
    log('Tenants: acme (alice=admin, mark=manager/sales, ursula=user/sales, sam=user/support), globex (gina=admin)');

    // ---------------------------------------------------------------- login
    head('1. Login (bcrypt + generic errors)');
    const login = async (/** @type {string} */ email, /** @type {string} */ tenant) => (await call('POST', '/auth/login', null, { tenant, email, password: PW })).body;
    const tok = {
      alice: await login('alice@acme.test', 'acme'),
      mark: await login('mark@acme.test', 'acme'),
      ursula: await login('ursula@acme.test', 'acme'),
      sam: await login('sam@acme.test', 'acme'),
      gina: await login('gina@globex.test', ''),
    };
    for (const [n, t] of Object.entries(tok)) check(`${n} logs in`, { status: t?.accessToken ? 200 : 500, body: t }, 200, (b) => b.accessToken && b.refreshToken.startsWith('rt_'));
    const wrong = check('wrong password -> generic error', await call('POST', '/auth/login', null, { tenant: 'acme', email: 'alice@acme.test', password: 'nope-Wrong-123' }), 401);
    check('unknown email -> same generic error (no user enumeration)', await call('POST', '/auth/login', null, { tenant: 'acme', email: 'ghost@acme.test', password: 'nope-Wrong-123' }), 401, (b) => b.error.message === wrong.body.error.message);
    check('no token -> 401', await call('GET', '/me', null), 401);
    check('/me returns role + effective permissions', await call('GET', '/me', tok.mark.accessToken), 200, (b) => b.user.role === 'manager' && b.permissions.includes('users:read:team'));

    // ---------------------------------------------------------------- RBAC scopes
    head('2. Role scopes: own / team / tenant');
    check('user cannot list users', await call('GET', '/users', tok.ursula.accessToken), 403);
    check('manager lists only their team', await call('GET', '/users', tok.mark.accessToken), 200, (b) => b.users.length === 2 && b.users.every((/** @type {any} */ u) => u.teamId === 'sales'));
    check('admin lists the whole tenant', await call('GET', '/users', tok.alice.accessToken), 200, (b) => b.users.length === 4);
    const pU = (await call('POST', '/projects', tok.ursula.accessToken, { name: 'Ursula Q4 pipeline' })).body.project;
    const pS = (await call('POST', '/projects', tok.sam.accessToken, { name: 'Sam support macros' })).body.project;
    check('user sees only own projects', await call('GET', '/projects', tok.ursula.accessToken), 200, (b) => b.projects.length === 1 && b.projects[0].id === pU.id);
    check('manager sees team projects', await call('GET', '/projects', tok.mark.accessToken), 200, (b) => b.projects.length === 1 && b.projects[0].id === pU.id);
    check('admin sees all tenant projects', await call('GET', '/projects', tok.alice.accessToken), 200, (b) => b.projects.length === 2);
    check("user cannot edit a colleague's project", await call('PATCH', `/projects/${pS.id}`, tok.ursula.accessToken, { name: 'hacked' }), 403);
    check("manager cannot edit another team's project", await call('PATCH', `/projects/${pS.id}`, tok.mark.accessToken, { name: 'hacked' }), 403);
    check("manager edits own team's project", await call('PATCH', `/projects/${pU.id}`, tok.mark.accessToken, { name: 'Q4 pipeline (reviewed)' }), 200);
    check('user cannot delete project they do not own', await call('DELETE', `/projects/${pS.id}`, tok.ursula.accessToken), 403);

    // ---------------------------------------------------------------- escalation
    head('3. Privilege escalation attempts');
    check('user cannot change own role', await call('PUT', `/users/${ursula.id}/role`, tok.ursula.accessToken, { role: 'admin' }), 403);
    check('manager cannot promote self', await call('PUT', `/users/${mark.id}/role`, tok.mark.accessToken, { role: 'admin' }), 403);
    check('manager cannot grant admin to team member', await call('PUT', `/users/${ursula.id}/role`, tok.mark.accessToken, { role: 'admin' }), 403);
    check('manager cannot create a manager', await call('POST', '/users', tok.mark.accessToken, { email: 'newmgr@acme.test', role: 'manager' }), 403);
    check('manager cannot create users in another team', await call('POST', '/users', tok.mark.accessToken, { email: 'x@acme.test', teamId: 'support' }), 403);
    check('manager invites a user to own team (temp password returned once)', await call('POST', '/users', tok.mark.accessToken, { email: 'newrep@acme.test', name: 'New rep' }), 201, (b) => b.user.teamId === 'sales' && b.user.role === 'user' && typeof b.temporaryPassword === 'string');
    check('manager cannot disable the admin', await call('POST', `/users/${acme.user.id}/disable`, tok.mark.accessToken), 403);
    check('admin cannot demote self', await call('PUT', `/users/${acme.user.id}/role`, tok.alice.accessToken, { role: 'user' }), 403);
    check('unknown role rejected', await call('PUT', `/users/${ursula.id}/role`, tok.alice.accessToken, { role: 'superuser' }), 400);

    // ---------------------------------------------------------------- tenants
    head('4. Tenant isolation');
    check('other tenant admin cannot read acme user (404, not 403)', await call('GET', `/users/${ursula.id}`, tok.gina.accessToken), 404);
    check('other tenant admin cannot change acme roles', await call('PUT', `/users/${ursula.id}/role`, tok.gina.accessToken, { role: 'admin' }), 404);
    check('other tenant admin cannot read acme projects', await call('GET', `/projects/${pU.id}`, tok.gina.accessToken), 404);
    check('other tenant admin lists only own tenant', await call('GET', '/users', tok.gina.accessToken), 200, (b) => b.users.length === 1);

    // ---------------------------------------------------------------- instant revocation
    head('5. Role change takes effect immediately');
    check('admin promotes ursula to manager', await call('PUT', `/users/${ursula.id}/role`, tok.alice.accessToken, { role: 'manager' }), 200);
    check("ursula's old token (role=user) is rejected", await call('GET', '/me', tok.ursula.accessToken), 401, (b) => b.error.code === 'token_revoked');
    const ur2 = check('ursula refreshes -> new token', await call('POST', '/auth/refresh', null, { refreshToken: tok.ursula.refreshToken }), 200).body;
    check('new token carries role=manager', await call('GET', '/me', ur2.accessToken), 200, (b) => b.user.role === 'manager');
    check('admin demotes her back to user', await call('PUT', `/users/${ursula.id}/role`, tok.alice.accessToken, { role: 'user' }), 200);
    const ur3 = check('ursula refreshes again -> role=user', await call('POST', '/auth/refresh', null, { refreshToken: ur2.refreshToken }), 200, (b) => b.user.role === 'user').body;

    // ---------------------------------------------------------------- forged tokens
    head('6. Forged and tampered tokens');
    const good = tok.mark.accessToken;
    const [h, p, s] = good.split('.');
    const claims = JSON.parse(Buffer.from(p, 'base64url').toString());
    const header = JSON.parse(Buffer.from(h, 'base64url').toString());
    const { iat: _iat, exp: _exp, ...base } = claims;
    check('payload edited to role=admin (signature kept)', await call('GET', '/users', `${h}.${b64({ ...claims, role: 'admin' })}.${s}`), 401);
    check('alg=none token', await call('GET', '/me', `${b64({ alg: 'none', typ: ACCESS_TYP })}.${b64({ ...claims, role: 'admin' })}.`), 401);
    if (alg !== 'HS256') {
      const jwks = service.keys.jwks().keys[0];
      const pubPem = crypto.createPublicKey({ key: /** @type {any} */ (jwks), format: 'jwk' }).export({ type: 'spki', format: 'pem' });
      const hsHead = b64({ alg: 'HS256', typ: ACCESS_TYP, kid: header.kid });
      const hsBody = b64({ ...claims, role: 'admin' });
      const hsSig = crypto.createHmac('sha256', pubPem).update(`${hsHead}.${hsBody}`).digest('base64url');
      check('HS256 signed with the public key (alg confusion)', await call('GET', '/me', `${hsHead}.${hsBody}.${hsSig}`), 401);
      const rogue = crypto.generateKeyPairSync(alg === 'ES256' ? 'ec' : 'rsa', alg === 'ES256' ? { namedCurve: 'P-256' } : { modulusLength: 2048 });
      const rogueTok = jwt.sign({ ...base, role: 'admin' }, rogue.privateKey, { algorithm: alg, expiresIn: 600, header: { alg, typ: ACCESS_TYP, kid: header.kid } });
      check('attacker key reusing a real kid', await call('GET', '/me', rogueTok), 401);
    }
    const { key, kid } = service.keys.signingKey();
    const nowS = Math.floor(Date.now() / 1000);
    const expired = jwt.sign({ ...claims, iat: nowS - 3600, exp: nowS - 600 }, key, { algorithm: /** @type {any} */ (alg), header: { alg, typ: ACCESS_TYP, kid } });
    check('expired token', await call('GET', '/me', expired), 401, (b) => b.error.code === 'token_expired');
    const otherAud = jwt.sign({ ...claims, aud: 'billing-api', iat: nowS, exp: nowS + 600 }, key, { algorithm: /** @type {any} */ (alg), header: { alg, typ: ACCESS_TYP, kid } });
    check('token issued for another API (audience)', await call('GET', '/me', otherAud), 401);
    const otherIss = jwt.sign({ ...claims, iss: 'https://evil.example', iat: nowS, exp: nowS + 600 }, key, { algorithm: /** @type {any} */ (alg), header: { alg, typ: ACCESS_TYP, kid } });
    check('token from another issuer', await call('GET', '/me', otherIss), 401);
    const idTok = jwt.sign({ ...claims, iat: nowS, exp: nowS + 600 }, key, { algorithm: /** @type {any} */ (alg), header: { alg, typ: 'JWT', kid } });
    check('signed JWT that is not an access token (typ)', await call('GET', '/me', idTok), 401);
    check('garbage token', await call('GET', '/me', 'not.a.jwt'), 401);

    // ---------------------------------------------------------------- refresh theft
    head('7. Refresh token rotation + theft detection');
    const s1 = await login('sam@acme.test', 'acme');
    const s2 = check('refresh #1 rotates the token', await call('POST', '/auth/refresh', null, { refreshToken: s1.refreshToken }), 200, (b) => b.refreshToken !== s1.refreshToken).body;
    check('replaying the old refresh token (stolen copy)', await call('POST', '/auth/refresh', null, { refreshToken: s1.refreshToken }), 401, (b) => b.error.code === 'refresh_reused');
    check('-> whole session revoked: newest refresh token dead', await call('POST', '/auth/refresh', null, { refreshToken: s2.refreshToken }), 401);
    check('-> access token of that session dead', await call('GET', '/me', s2.accessToken), 401, (b) => b.error.code === 'session_revoked');
    check("sam's other session (other device) still works", await call('GET', '/me', tok.sam.accessToken), 200);

    // ---------------------------------------------------------------- logout / disable
    head('8. Logout, disable, lockout');
    check('ursula logs out', await call('POST', '/auth/logout', ur3.accessToken, {}), 200, (b) => b.revoked === 1);
    check('her access token stops working at once', await call('GET', '/me', ur3.accessToken), 401, (b) => b.error.code === 'session_revoked');
    check('logout with an already-dead access token + refresh token still works', await call('POST', '/auth/logout', ur3.accessToken, { refreshToken: ur3.refreshToken }), 200);
    check('admin disables sam', await call('POST', `/users/${sam.id}/disable`, tok.alice.accessToken), 200);
    check("sam's live token rejected", await call('GET', '/me', tok.sam.accessToken), 401, (b) => b.error.code === 'account_disabled');
    check('sam cannot log in (correct password)', await call('POST', '/auth/login', null, { tenant: 'acme', email: 'sam@acme.test', password: PW }), 403);
    const max = service.config.lockout.maxAttempts;
    for (let i = 0; i < max; i++) await call('POST', '/auth/login', null, { tenant: 'acme', email: 'mark@acme.test', password: `Wrong-pass-${i}x` });
    check(`after ${max} failures the account locks, even with the right password`, await call('POST', '/auth/login', null, { tenant: 'acme', email: 'mark@acme.test', password: PW }), 423);
    check('admin unlocks mark', await call('POST', `/users/${mark.id}/unlock`, tok.alice.accessToken), 200);
    const mark2 = check('mark logs in again', await call('POST', '/auth/login', null, { tenant: 'acme', email: 'mark@acme.test', password: PW }), 200).body;

    // ---------------------------------------------------------------- operator guards
    head('9. Audit, JWKS and safety rails');
    check('admin reads audit log incl. theft alert', await call('GET', '/audit?limit=200', tok.alice.accessToken), 200, (b) => b.events.some((/** @type {any} */ e) => e.action === 'auth.refresh_reuse' && e.outcome === 'alert'));
    check('manager cannot read audit log (admin only)', await call('GET', '/audit', mark2.accessToken), 403);
    check('JWKS is public and has no private parts', await call('GET', '/.well-known/jwks.json', null), 200, (b) => b.keys.every((/** @type {any} */ k) => !('d' in k) && !('p' in k)));
    let lastAdmin = { status: 0, body: /** @type {any} */ (null) };
    try {
      const gina = service.store.usersByEmail('gina@globex.test')[0];
      service.changeRole(SYSTEM, gina.id, 'user');
      lastAdmin = { status: 200, body: {} };
    } catch (e) {
      lastAdmin = { status: /** @type {any} */ (e).status, body: { error: { code: /** @type {any} */ (e).code } } };
    }
    check('even the operator cannot demote the last admin', lastAdmin, 409, (b) => b.error.code === 'last_admin');
  } finally {
    await srv.close();
    service.close();
  }
  const failed = results.filter((r) => !r.ok);
  log(`\n${results.length - failed.length}/${results.length} checks passed${failed.length ? ` - ${failed.length} FAILED` : ''}`);
  return { passed: results.length - failed.length, failed: failed.length, results };
}

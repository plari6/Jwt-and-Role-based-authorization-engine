# JWT & Role-Based Authorization Engine

Login, sessions and permissions for multi-tenant SaaS apps, ready to drop in. Users sign in with bcrypt-hashed passwords and get short-lived JWT access tokens plus rotating refresh tokens. Every request is checked against **Admin / Manager / User** roles with **own / team / organisation** scopes. It ships as a CLI, a REST API, Express middleware and a library.

**Stack:** JavaScript (Node.js 22.13+ ESM) - jsonwebtoken, bcrypt, express 5, commander, built-in `node:sqlite`. No LLM calls (security hot path, deterministic).

```bash
npm install
node bin/authz.js demo        # in-memory engine + live API + about 65 attack & permission checks, no setup
npm test                      # 49 tests, offline
```

## What it does

| Area | What you get |
|---|---|
| **Passwords** | bcrypt (cost 12) over an HMAC-SHA256 pre-hash with a server-side **pepper**. No 72-byte truncation, and a stolen database alone can't be cracked. Policy covers length, character mix, a common-password blocklist and "contains your email". Hashes upgrade automatically when you raise the cost. |
| **Login** | Generic error for a wrong password or an unknown email, with the same bcrypt timing, so attackers can't tell which emails exist. Per-account lockout with progressive backoff, a per-IP throttle, and disabled accounts. One email can belong to several organisations. |
| **Access tokens** | ES256 (default), RS256 or HS256 JWTs, 15 min. Pinned `alg`, `kid`, `iss`, `aud` and `typ: at+jwt`, so `alg=none`, HS256-with-public-key, foreign keys, other audiences and expired tokens are all rejected. |
| **Instant revocation** | Each request also checks a token version and the session. Role changes, disabling, password resets and logouts take effect on the **next request**, not 15 minutes later. |
| **Refresh tokens** | Opaque 256-bit tokens, stored only as SHA-256 hashes, **rotated on every use**. Reusing an old one means it was stolen, so the whole session is revoked and an `alert` is written to the audit log. Each session has a 7-day idle limit and a 30-day absolute limit. |
| **Roles** | `user` < `manager` < `admin` by default, with inheritance. Permissions are written `resource:action:scope` with wildcards. Scopes: `own` (your records), `team` (your team), `tenant` (your organisation), `any` (platform staff). |
| **Safety rails** | No self-promotion and no granting a role above your own (`assignable`). Managers can't touch admins. The **last admin** of an organisation can't be demoted, disabled or deleted. Other tenants' data answers **404**, not 403. |
| **Policy file** | `policy.json` is editable by the client. `authz policy check` rejects cycles, unknown roles, bad permission strings and any **privilege-escalation path**. |
| **Key rotation** | `authz keys rotate`: running servers pick up the new key within 5 s, old tokens keep verifying until pruned, and JWKS is published at `/.well-known/jwks.json`. |
| **Other services** | `createJwksVerifier()` lets a billing API, worker or microservice verify tokens and apply the same policy with only the public JWKS URL. |
| **Audit** | Logins, failures, lockouts, role changes, disables, resets, denials and token-theft alerts, filterable by tenant, action, outcome and time. |

## Quick start (real deployment)

```bash
export ADMIN_PW='Choose-A-Strong-One!'
node bin/authz.js init --tenant acme --tenant-name "Acme Inc" --email owner@acme.com --password-env ADMIN_PW \
     --issuer https://auth.acme.com --audience acme-api
# -> authz.config.json, policy.json, .env (AUTHZ_PEPPER), keys/keyset.json, data/authz.db

node bin/authz.js check       # validates config/policy/keys, prints production warnings
node bin/authz.js serve       # REST API on :4000
```

`init` never overwrites existing files. **Back up `.env` and `keys/`**: losing the pepper makes every stored password unusable, and losing the keys signs everyone out.

## CLI

```bash
authz demo [--alg ES256|RS256|HS256]                       # self-test with attacks; exit 1 on any failure
authz tenant create globex --name "Globex"   |  authz tenant list
authz user add -t acme --email mark@acme.com --role manager --team sales   # prints a one-time temp password
authz user list -t acme [--role manager] [--status disabled] [--team sales]
authz user role mark@acme.com admin -t acme                 # kills mark's live tokens instantly
authz user team sam@acme.com support -t acme
authz user disable|enable|unlock|delete|logout-all <email> -t acme
authz user reset-password <email> -t acme [--password-env VAR]
authz user sessions <email> -t acme   |  authz session-revoke <sessionId>
authz can mark@acme.com projects:update -t acme --owner sam@acme.com   # ALLOW/DENY + reason (exit 2 = deny)
authz login -t acme --email mark@acme.com --password-env PW            # tokens for curl testing
authz token verify <jwt>   |  authz token decode <jwt>
authz policy show | check [file] | init
authz keys list | rotate [--prune] | prune --older-than 30m | jwks
authz audit -t acme --action 'auth.*' --outcome alert --since 24h
authz purge                                                 # expired refresh tokens / old sessions
```

Global options: `-c config.json`, `--env-file .env`, `--json`. Exit codes: 0 ok, 1 error, 2 permission denied (`can`), 3 rule violation (e.g. last admin).
User commands run as the **operator**: they skip role checks but keep the safety rails.

## REST API

| Method & path | Who | Notes |
|---|---|---|
| `POST /auth/login` `{email, password, tenant?}` | anyone | `tenant` is needed only when the email exists in several orgs |
| `POST /auth/refresh` `{refreshToken}` | anyone | returns a new pair; the old refresh token is now dead |
| `POST /auth/logout` `{refreshToken?}` | anyone | works even if the access token already expired |
| `POST /auth/logout-all` | self | every device |
| `POST /auth/register` | if `allowSignup` | always the default role |
| `GET/PATCH /me`, `POST /me/password`, `GET /me/sessions` | self | password change signs out other devices |
| `GET /authz/check?permission=billing:read`, `GET /policy` | self | drive UI menus from the same rules |
| `GET/POST /users`, `GET/PATCH/DELETE /users/:id` | by scope | managers: own team; admins: tenant |
| `PUT /users/:id/role`, `POST /users/:id/{disable,enable,unlock,reset-password,logout-all}` | by scope + `assignable` | |
| `GET /users/:id/sessions`, `DELETE /sessions/:id` | self / admin | |
| `GET /audit` | admin | |
| `GET/POST /projects`, `GET/PATCH/DELETE /projects/:id` | by scope | example business object |
| `GET /.well-known/jwks.json`, `/.well-known/openid-configuration`, `/healthz` | public | |

Errors are always `{ "error": { "code", "message", "details?" } }`. A 401 response carries `WWW-Authenticate`, and 423/429 responses carry `Retry-After`.

## Library use

```js
import { AuthService, createAuth, createApp, errorHandler } from 'jwt-rbac-engine'; // or ./src/index.js

const service = AuthService.open();               // authz.config.json + .env
const auth = createAuth(service);

app.use('/auth', createApp(service));             // full auth API
app.get('/invoices', auth.authenticate(), auth.authorize('billing:read'), handler);
app.patch('/deals/:id', auth.authenticate(),
  auth.authorize('deals:update', (req) => db.deals.get(req.params.id)),   // record needs tenantId (+ ownerId / teamId)
  handler);                                       // req.auth, req.target, req.authz.scope
app.get('/team', auth.authenticate(), auth.requireRole('manager'), handler);
service.can(req.auth, 'users:create');            // { allowed, scope, reason } for UI flags
app.use(errorHandler());
```

See [examples/](examples/): [protect-existing-app.js](examples/protect-existing-app.js), [other-service-jwks.js](examples/other-service-jwks.js), [frontend-client.js](examples/frontend-client.js) (auto-refresh with a single shared refresh), and [policy.custom.json](examples/policy.custom.json) (a sales CRM with a `viewer` role and leads/deals permissions).

## Default policy

```
permission       user  manager  admin
users:read       -     team     tenant
users:create     -     team     tenant      (manager may only create role "user" in own team)
projects:read    own   team     tenant
projects:update  own   team     tenant
projects:delete  own   own      tenant
billing:*        -     -        tenant
audit:read       -     -        tenant
```

Run `authz policy show` for the full matrix. Edit `policy.json`, then run `authz policy check` and restart.

## Configuration (`authz.config.json`, env overrides)

| Key | Default | Env |
|---|---|---|
| `issuer` / `audience` | `http://localhost:4000` / `saas-api` | `AUTHZ_ISSUER` / `AUTHZ_AUDIENCE` |
| `algorithm` | `ES256` | `AUTHZ_ALGORITHM` (HS256 needs `AUTHZ_HS_SECRET` of at least 32 bytes) |
| `accessTtl` | `15m` | `AUTHZ_ACCESS_TTL` |
| `refreshTtlDays` / `refreshIdleDays` | 30 / 7 | |
| `bcryptRounds` | 12 | `AUTHZ_BCRYPT_ROUNDS` |
| `passwordPolicy` | min 10, max 128, 2 character classes, block common | |
| `lockout` | 5 attempts, 15 min (doubling, max 8x) | |
| `server.trustProxy` | `false` (set `1` behind one proxy or load balancer) | `AUTHZ_TRUST_PROXY` |
| `server.loginPerIpPerMin` | 20 | |
| `server.allowSignup` | `false` | `AUTHZ_ALLOW_SIGNUP` |
| `server.corsOrigins` | `[]` | `AUTHZ_CORS_ORIGINS` (comma list) |
| `dbPath`, `keysDir`, `policyFile` | `./data/authz.db`, `./keys`, `./policy.json` | `AUTHZ_DB`, `AUTHZ_KEYS_DIR`, `AUTHZ_POLICY` |
| pepper | | `AUTHZ_PEPPER` (generated by `init`) |

## Deploy

```bash
docker build -t authz .
docker run -d -p 4000:4000 --env-file .env -v $PWD/data:/app/data -v $PWD/keys:/app/keys \
  -v $PWD/authz.config.json:/app/authz.config.json -v $PWD/policy.json:/app/policy.json authz
```

Production checklist (`authz check` warns about most of these): HTTPS issuer, `trustProxy: 1` behind a load balancer, pepper set and backed up, `keys/` on a volume, run `keys rotate --prune` every few months, and `purge` daily (the server also purges hourly).

**Scaling note:** SQLite in WAL mode serves one instance comfortably (thousands of logins per minute). For several replicas, move the `Store` class to Postgres. It is one file with plain SQL. The keyset can be shared through a common volume.

## Design decisions

- **Stateful check on top of the JWT.** One indexed SQLite read per request buys instant revocation. Other services that can't reach the database use `createJwksVerifier`: stateless, with revocation lag of at most one access TTL.
- **Refresh-token reuse means revoking the session.** This follows the OAuth 2.0 Security BCP. Clients must not refresh in parallel; `examples/frontend-client.js` shares one in-flight refresh.
- **404 for other tenants.** It doesn't confirm that an ID exists in another organisation.
- **Lockout returns 423.** This reveals that an account exists only after 5 failed attempts, a trade-off in favour of support-friendly UX. The per-IP throttle stops enumeration at scale.

## License

MIT

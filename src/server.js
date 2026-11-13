// @ts-check
import express from 'express';
import { createAuth, errorHandler } from './middleware.js';
import { AuthError } from './errors.js';

/** Fixed-window counter per key (login brute-force guard per IP). */
export function windowLimiter(/** @type {number} */ limit, /** @type {number} */ windowMs) {
  /** @type {Map<string, {n:number, reset:number}>} */
  const hits = new Map();
  const timer = setInterval(() => {
    const t = Date.now();
    for (const [k, v] of hits) if (v.reset <= t) hits.delete(k);
  }, windowMs);
  timer.unref();
  return {
    /** @returns {{ok:boolean, retryAfterSec:number}} */
    hit(/** @type {string} */ key) {
      const t = Date.now();
      let e = hits.get(key);
      if (!e || e.reset <= t) {
        e = { n: 0, reset: t + windowMs };
        hits.set(key, e);
      }
      e.n++;
      return { ok: e.n <= limit, retryAfterSec: Math.ceil((e.reset - t) / 1000) };
    },
    stop: () => clearInterval(timer),
  };
}

/**
 * Reference REST API on top of the engine. Mount it as is, or copy the routes you need.
 * @param {import('./service.js').AuthService} service
 * @param {{log?: (e:unknown)=>void}} [o]
 */
export function createApp(service, o = {}) {
  const cfg = service.config;
  const app = express();
  const auth = createAuth(service);
  const limiter = windowLimiter(cfg.server.loginPerIpPerMin, 60_000);
  app.locals.limiter = limiter;
  app.disable('x-powered-by');
  app.set('trust proxy', cfg.server.trustProxy);

  app.use((req, res, next) => {
    res.set({ 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY' });
    const origin = req.get('origin');
    if (origin && cfg.server.corsOrigins.includes(origin)) {
      res.set({ 'Access-Control-Allow-Origin': origin, Vary: 'Origin', 'Access-Control-Allow-Headers': 'Authorization, Content-Type', 'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS', 'Access-Control-Max-Age': '600' });
      if (req.method === 'OPTIONS') return res.status(204).end();
    }
    next();
  });
  app.use(express.json({ limit: '32kb' }));

  const ctx = (/** @type {any} */ req) => ({ ip: req.ip, userAgent: req.get('user-agent') });
  const throttle = (/** @type {any} */ req, /** @type {any} */ res, /** @type {any} */ next) => {
    const r = limiter.hit(`ip:${req.ip}`);
    if (r.ok) return next();
    res.set('Retry-After', String(r.retryAfterSec));
    next(new AuthError('rate_limited', 429, 'Too many attempts from this address - slow down', { retryAfterSec: r.retryAfterSec }));
  };
  const body = (/** @type {any} */ req) => (req.body && typeof req.body === 'object' ? req.body : {});

  // ---- discovery
  app.get('/healthz', (_req, res) => {
    res.json({ ok: true, alg: service.keys.alg, issuer: cfg.issuer });
  });
  app.get('/.well-known/jwks.json', (_req, res) => {
    res.set('Cache-Control', 'public, max-age=300').json(service.keys.jwks());
  });
  app.get('/.well-known/openid-configuration', (_req, res) => {
    res.set('Cache-Control', 'public, max-age=300').json({
      issuer: cfg.issuer,
      jwks_uri: `${cfg.issuer.replace(/\/$/, '')}/.well-known/jwks.json`,
      token_endpoint: `${cfg.issuer.replace(/\/$/, '')}/auth/login`,
      id_token_signing_alg_values_supported: [service.keys.alg],
    });
  });

  // ---- auth
  app.post('/auth/login', throttle, async (req, res) => {
    const b = body(req);
    res.json(await service.login({ tenant: b.tenant, email: b.email, password: b.password }, ctx(req)));
  });
  app.post('/auth/refresh', throttle, (req, res) => {
    res.json(service.refresh({ refreshToken: body(req).refreshToken }, ctx(req)));
  });
  // Logout never fails because the access token already died (expired, revoked, role changed):
  // the refresh token in the body is enough to end the session.
  app.post('/auth/logout', (req, res) => {
    let principal;
    const m = /^Bearer\s+(\S+)$/i.exec(req.get('authorization') || '');
    if (m) {
      try {
        principal = service.authenticate(m[1]);
      } catch {
        principal = undefined;
      }
    }
    res.json(service.logout({ principal, refreshToken: body(req).refreshToken }, ctx(req)));
  });
  app.post('/auth/logout-all', auth.authenticate(), (req, res) => {
    const a = /** @type {any} */ (req).auth;
    res.json(service.logoutAll(a, a.id, ctx(req)));
  });
  app.post('/auth/register', throttle, async (req, res) => {
    const b = body(req);
    res.status(201).json({ user: await service.register({ tenant: b.tenant, email: b.email, password: b.password, name: b.name }, ctx(req)) });
  });

  // ---- self
  app.get('/me', auth.authenticate(), (req, res) => {
    res.json(service.me(/** @type {any} */ (req).auth));
  });
  app.patch('/me', auth.authenticate(), (req, res) => {
    const a = /** @type {any} */ (req).auth;
    res.json({ user: service.updateUser(a, a.id, { name: body(req).name }, ctx(req)) });
  });
  app.post('/me/password', auth.authenticate(), throttle, async (req, res) => {
    const b = body(req);
    res.json(await service.changePassword(/** @type {any} */ (req).auth, { currentPassword: b.currentPassword, newPassword: b.newPassword }, ctx(req)));
  });
  app.get('/me/sessions', auth.authenticate(), (req, res) => {
    const a = /** @type {any} */ (req).auth;
    res.json({ sessions: service.listSessions(a, a.id) });
  });
  app.get('/authz/check', auth.authenticate(), (req, res) => {
    const permission = String(req.query.permission || '');
    res.json({ permission, ...service.can(/** @type {any} */ (req).auth, permission, undefined) });
  });
  app.get('/policy', auth.authenticate(), (_req, res) => {
    res.json({ roles: service.policy.roles.map((r) => ({ role: r, level: service.policy.level(r), permissions: service.policy.permissionsOf(r) })), matrix: service.policy.matrix() });
  });

  // ---- users
  const A = (/** @type {any} */ req) => req.auth;
  app.get('/users', auth.authenticate(), (req, res) => {
    res.json({ users: service.listUsers(A(req), { role: /** @type {any} */ (req.query.role), status: /** @type {any} */ (req.query.status), teamId: /** @type {any} */ (req.query.team) }) });
  });
  app.post('/users', auth.authenticate(), async (req, res) => {
    const b = body(req);
    res.status(201).json(await service.createUser(A(req), { email: b.email, name: b.name, role: b.role, teamId: b.teamId, password: b.password }, ctx(req)));
  });
  app.get('/users/:id', auth.authenticate(), (req, res) => {
    res.json({ user: service.getUser(A(req), req.params.id, ctx(req)) });
  });
  app.patch('/users/:id', auth.authenticate(), (req, res) => {
    const b = body(req);
    res.json({ user: service.updateUser(A(req), req.params.id, { name: b.name, teamId: b.teamId }, ctx(req)) });
  });
  app.put('/users/:id/role', auth.authenticate(), (req, res) => {
    res.json({ user: service.changeRole(A(req), req.params.id, String(body(req).role || ''), ctx(req)) });
  });
  app.post('/users/:id/disable', auth.authenticate(), (req, res) => {
    res.json({ user: service.setStatus(A(req), req.params.id, 'disabled', ctx(req)) });
  });
  app.post('/users/:id/enable', auth.authenticate(), (req, res) => {
    res.json({ user: service.setStatus(A(req), req.params.id, 'active', ctx(req)) });
  });
  app.post('/users/:id/reset-password', auth.authenticate(), async (req, res) => {
    res.json(await service.resetPassword(A(req), req.params.id, body(req).password, ctx(req)));
  });
  app.post('/users/:id/unlock', auth.authenticate(), (req, res) => {
    res.json({ user: service.unlock(A(req), req.params.id, ctx(req)) });
  });
  app.post('/users/:id/logout-all', auth.authenticate(), (req, res) => {
    res.json(service.logoutAll(A(req), req.params.id, ctx(req)));
  });
  app.get('/users/:id/sessions', auth.authenticate(), (req, res) => {
    res.json({ sessions: service.listSessions(A(req), req.params.id) });
  });
  app.delete('/users/:id', auth.authenticate(), (req, res) => {
    res.json(service.deleteUser(A(req), req.params.id, ctx(req)));
  });
  app.delete('/sessions/:id', auth.authenticate(), (req, res) => {
    res.json(service.revokeSession(A(req), req.params.id, ctx(req)));
  });
  app.get('/audit', auth.authenticate(), (req, res) => {
    const q = /** @type {any} */ (req.query);
    res.json({ events: service.auditLog(A(req), { action: q.action, outcome: q.outcome, since: q.since, limit: Number(q.limit) || 50 }) });
  });

  // ---- example protected resource
  app.get('/projects', auth.authenticate(), (req, res) => {
    res.json({ projects: service.listProjects(A(req)) });
  });
  app.post('/projects', auth.authenticate(), (req, res) => {
    res.status(201).json({ project: service.createProject(A(req), body(req), ctx(req)) });
  });
  app.get('/projects/:id', auth.authenticate(), (req, res) => {
    res.json({ project: service.getProject(A(req), req.params.id, ctx(req)) });
  });
  app.patch('/projects/:id', auth.authenticate(), (req, res) => {
    res.json({ project: service.updateProject(A(req), req.params.id, body(req), ctx(req)) });
  });
  app.delete('/projects/:id', auth.authenticate(), (req, res) => {
    res.json(service.deleteProject(A(req), req.params.id, ctx(req)));
  });

  app.use((_req, _res, next) => next(new AuthError('not_found', 404, 'Route not found')));
  app.use(errorHandler({ log: o.log }));
  return app;
}

/**
 * Start the HTTP server. Returns { url, server, close }.
 * @param {import('./service.js').AuthService} service
 * @param {{port?:number, host?:string, log?:(e:unknown)=>void}} [o]
 */
export function startServer(service, o = {}) {
  const app = createApp(service, { log: o.log });
  const purge = setInterval(() => {
    try {
      service.store.purgeExpired();
    } catch {
      /* best effort */
    }
  }, 3600_000);
  purge.unref();
  return new Promise((resolve, reject) => {
    const server = app.listen(o.port ?? service.config.server.port, o.host ?? '0.0.0.0', () => {
      const addr = /** @type {import('node:net').AddressInfo} */ (server.address());
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        server,
        close: () =>
          new Promise((r) => {
            clearInterval(purge);
            app.locals.limiter.stop();
            server.closeAllConnections?.();
            server.close(() => r(undefined));
          }),
      });
    });
    server.on('error', reject);
  });
}

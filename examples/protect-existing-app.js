// Protect an EXISTING Express app with the engine (same process, same database).
// Run:  node examples/protect-existing-app.js   (after `authz init` in this folder)
import express from 'express';
import { AuthService, createAuth, createApp, errorHandler } from '../src/index.js';

const service = AuthService.open(); // reads authz.config.json + .env
const auth = createAuth(service);
const app = express();
app.use(express.json());

// 1) Mount the ready-made auth API (login, refresh, logout, users, roles, audit...) under /auth-api
app.use('/auth-api', createApp(service));

// 2) Protect your own routes
const invoices = new Map(); // stand-in for your database

// any logged-in user of the tenant with billing:read (admins in the default policy)
app.get('/invoices', auth.authenticate(), auth.authorize('billing:read'), (req, res) => {
  res.json([...invoices.values()].filter((i) => i.tenantId === req.auth.tenantId));
});

// object-level check: the resolver loads the record, the engine applies own / team / tenant scope.
// Records MUST carry tenantId (and ownerId / teamId where scopes need them).
app.patch(
  '/projects/:id',
  auth.authenticate(),
  auth.authorize('projects:update', async (req) => service.store.projectById(req.params.id)),
  (req, res) => res.json({ ok: true, project: req.target, grantedBy: req.authz.scope }),
);

// coarse role gate
app.get('/manager-dashboard', auth.authenticate(), auth.requireRole('manager'), (req, res) => {
  res.json({ hello: req.auth.email, role: req.auth.role });
});

// in-handler checks for UI menus / feature flags
app.get('/menu', auth.authenticate(), (req, res) => {
  res.json({
    canSeeBilling: service.can(req.auth, 'billing:read').allowed,
    canInvite: service.can(req.auth, 'users:create').allowed,
  });
});

app.use(errorHandler());
app.listen(3000, () => console.log('app on http://localhost:3000 (auth API under /auth-api)'));

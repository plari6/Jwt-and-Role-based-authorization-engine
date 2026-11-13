import { AuthService, SYSTEM } from '../src/index.js';

export const PW = 'Test-Passw0rd!x';

/** In-memory engine with fast bcrypt and a seeded tenant: admin, manager (sales), user (sales), user (support). */
export async function seeded(overrides = {}) {
  const s = AuthService.open({ memory: true, isolated: true, overrides: { bcryptRounds: 4, audience: 'test-api', ...overrides } });
  await s.bootstrap({ tenant: 'acme', email: 'admin@acme.test', password: PW });
  const add = async (email, role, teamId, tenant = 'acme') => (await s.createUser(SYSTEM, { tenant, email, password: PW, role, teamId })).user;
  const u = {
    admin: s.store.usersByEmail('admin@acme.test')[0],
    manager: await add('manager@acme.test', 'manager', 'sales'),
    user: await add('user@acme.test', 'user', 'sales'),
    other: await add('other@acme.test', 'user', 'support'),
  };
  const login = async (email, tenant = 'acme', password = PW) => s.login({ tenant, email, password });
  const principal = async (email, tenant = 'acme') => s.authenticate((await login(email, tenant)).accessToken);
  return { s, u, add, login, principal };
}

/** Assert that fn / promise throws an AuthError with this code. */
export async function rejects(promiseOrFn, code) {
  try {
    const r = typeof promiseOrFn === 'function' ? promiseOrFn() : promiseOrFn;
    await r;
  } catch (e) {
    if (code && e.code !== code) throw new Error(`expected error ${code}, got ${e.code}: ${e.message}`);
    return e;
  }
  throw new Error(`expected error ${code}, but it succeeded`);
}

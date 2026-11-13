// Browser / Node client: keeps the access token in memory and refreshes it once on 401.
// Concurrent 401s share ONE refresh call, so the refresh token is never used twice
// (a second use would look like theft and revoke the session).
export function createApiClient({ baseUrl, storage = globalThis.localStorage }) {
  let accessToken = null;
  let refreshing = null;
  const getRefresh = () => storage?.getItem('rt');
  const setRefresh = (t) => (t ? storage?.setItem('rt', t) : storage?.removeItem('rt'));

  async function login(email, password, tenant) {
    const r = await fetch(`${baseUrl}/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email, password, tenant }) });
    const body = await r.json();
    if (!r.ok) throw Object.assign(new Error(body.error?.message), { code: body.error?.code });
    accessToken = body.accessToken;
    setRefresh(body.refreshToken);
    return body.user;
  }

  function refresh() {
    refreshing ||= (async () => {
      const r = await fetch(`${baseUrl}/auth/refresh`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ refreshToken: getRefresh() }) });
      if (!r.ok) {
        accessToken = null;
        setRefresh(null);
        throw new Error('session expired');
      }
      const body = await r.json();
      accessToken = body.accessToken;
      setRefresh(body.refreshToken);
    })().finally(() => (refreshing = null));
    return refreshing;
  }

  async function api(path, init = {}) {
    const go = () => fetch(`${baseUrl}${path}`, { ...init, headers: { ...init.headers, authorization: `Bearer ${accessToken}` } });
    let r = await go();
    if (r.status === 401 && getRefresh()) {
      await refresh();
      r = await go();
    }
    return r;
  }

  async function logout() {
    await fetch(`${baseUrl}/auth/logout`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` }, body: JSON.stringify({ refreshToken: getRefresh() }) });
    accessToken = null;
    setRefresh(null);
  }

  return { login, api, logout };
}

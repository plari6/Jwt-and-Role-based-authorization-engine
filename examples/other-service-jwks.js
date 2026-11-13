// A SEPARATE service (billing API, worker, microservice) that trusts tokens from the auth server.
// It needs only the public JWKS URL - no database, no signing secret.
// Run:  AUTH_URL=http://localhost:4000 node examples/other-service-jwks.js
import express from 'express';
import { createJwksVerifier, errorHandler } from '../src/index.js';

const AUTH_URL = process.env.AUTH_URL || 'http://localhost:4000';
const verifier = createJwksVerifier({
  jwksUri: `${AUTH_URL}/.well-known/jwks.json`,
  issuer: process.env.AUTHZ_ISSUER || 'http://localhost:4000', // must equal the auth server's issuer
  audience: process.env.AUTHZ_AUDIENCE || 'saas-api',
  // policy: JSON.parse(fs.readFileSync('policy.json', 'utf8')),  // share the same policy file
});

const app = express();
app.use('/api', verifier.middleware());

app.get('/api/reports', verifier.authorize('reports:read'), (req, res) => {
  res.json({ tenant: req.auth.tenantId, scope: req.authz.scope });
});

app.use(errorHandler());
app.listen(4100, () => console.log('billing service on http://localhost:4100'));

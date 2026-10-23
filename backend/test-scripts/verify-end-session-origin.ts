/**
 * Runs the REAL oidc-provider (jest cannot load it: it is an ES module) and proves the sign-out page posts to the issuer's own address whatever Host the proxy
 * chain reports (oidc/end-session-origin.ts). Reads the signing keys and client rows of the database the environment points at; changes nothing.
 *
 *   npm run verify:end-session-origin            (development database)
 *   node scripts/run-with-env.cjs mirror tsx test-scripts/verify-end-session-origin.ts     (against the mirror's environment)
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { IDP_CONFIG } from '../src/config.js';
import { buildProvider } from '../src/oidc/provider.js';
import { pool } from '../src/db/pool.js';

const provider = await buildProvider();
const server = http.createServer(provider.callback());
await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
const port = (server.address() as AddressInfo).port;

const get = (headers: Record<string, string>) =>
  new Promise<{ status: number; body: string }>((resolve, reject) => {
    http
      .get({ host: '127.0.0.1', port, path: '/session/end', headers }, (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
      })
      .on('error', reject);
  });

const expected = `${IDP_CONFIG.issuer.replace(/\/+$/, '')}/session/end/confirm`;
let failed = 0;
for (const [label, headers] of [
  ['the Host is the frontend port behind Apache', { host: '127.0.0.1:9301' }],
  ['a forwarded host from an untrusted hop', { host: '127.0.0.1:9301', 'x-forwarded-host': 'evil.example', 'x-forwarded-proto': 'https' }],
] as Array<[string, Record<string, string>]>) {
  const { status, body } = await get(headers);
  const action = /action="([^"]+)"/.exec(body)?.[1] ?? '';
  // The provider is mounted at the root here, so the issuer's own path (the "/sso" prefix) is added by main.ts in the running service: compare host and scheme.
  const want = new URL(expected);
  const got = action ? new URL(action) : null;
  const ok = status === 200 && got !== null && got.host === want.host && got.protocol === want.protocol && got.pathname.endsWith('/session/end/confirm');
  if (!ok) failed += 1;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}: form action = ${action || '(none)'} (status ${status})`);
}
await new Promise<void>((r) => server.close(() => r()));
await pool.end();
console.log(failed ? `\n${failed} FAILED` : `\nAll passed: the sign-out form posts to ${new URL(expected).origin}`);
process.exit(failed ? 1 : 0);

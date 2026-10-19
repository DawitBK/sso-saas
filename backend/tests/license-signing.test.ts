/**
 * Dedicated licence signing key and the section-9 claims (docs/operations/PLATFORM-LICENSING.md sections 9.1 and 9.3). No database: the token module is
 * driven with a key file written to a temporary folder, and verified the way a consumer pins it (against a public JWK, never SSO's JWKS).
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { calculateJwkThumbprint, compactVerify, exportJWK, importJWK, decodeProtectedHeader } from 'jose';
import type { LicenseRecord } from '../src/licenses/repository.js';

const record = (over: Partial<LicenseRecord> = {}): LicenseRecord => ({
  system: 'gms', customer: 'Example Corp', expiresAt: '2030-01-01T00:00:00.000Z', graceDays: 14, warnDays: 30, maxUsers: 50,
  modules: ['visits'], modes: ['sso', 'standalone'], notes: '', version: 7,
  createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z', updatedBy: 'platform', ...over,
});

let dir = '';
let pem = '';
let otherPem = '';
let publicJwk: Record<string, unknown> = {};
let kid = '';

beforeAll(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'license-signing-'));
  const a = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const b = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  pem = a.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  otherPem = b.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  fs.writeFileSync(path.join(dir, 'license.pem'), pem);
  publicJwk = { ...(await exportJWK(a.publicKey)), alg: 'RS256' };
  kid = await calculateJwkThumbprint(publicJwk as never);
});
afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

async function verifyWith(token: string, jwk: Record<string, unknown>) {
  const key = await importJWK(jwk as never, 'RS256');
  const { payload } = await compactVerify(token, key);
  return JSON.parse(new TextDecoder().decode(payload)) as Record<string, unknown>;
}

describe('signLicenseTokenWith (the offline signer)', () => {
  it('signs the contract claims, including modes and jti, and verifies against the pinned public key', async () => {
    const { signLicenseTokenWith } = await import('../src/licenses/token.js');
    const { importPKCS8 } = await import('jose');
    const token = await signLicenseTokenWith(record(), await importPKCS8(pem, 'RS256'), kid, 'urn:test:issuer');
    const header = decodeProtectedHeader(token);
    expect(header).toMatchObject({ alg: 'RS256', typ: 'kcms-license+jwt', kid });
    const claims = await verifyWith(token, publicJwk);
    expect(claims).toMatchObject({ sys: 'gms', ver: 7, jti: 'gms-v7', modes: ['sso', 'standalone'], modules: ['visits'], aud: 'license:gms', iss: 'urn:test:issuer' });
    expect(claims.exp).toBeUndefined();
  });

  it('a key that is not the pinned one does not verify it', async () => {
    const { signLicenseTokenWith } = await import('../src/licenses/token.js');
    const { importPKCS8 } = await import('jose');
    const token = await signLicenseTokenWith(record(), await importPKCS8(otherPem, 'RS256'), 'other', 'urn:test:issuer');
    await expect(verifyWith(token, publicJwk)).rejects.toThrow();
  });
});

describe('LICENSE_SIGNING_KEY_FILE (the online signer)', () => {
  it('signs with the dedicated key, kid = its JWK thumbprint, and the token verifies against that key only', async () => {
    jest.resetModules();
    process.env.LICENSE_SIGNING_KEY_FILE = path.join(dir, 'license.pem');
    try {
      const { signLicenseToken, resetLicenseTokenCache } = await import('../src/licenses/token.js');
      resetLicenseTokenCache();
      const token = await signLicenseToken(record({ version: 9, modes: ['sso'] }));
      expect(decodeProtectedHeader(token).kid).toBe(kid);
      const claims = await verifyWith(token, publicJwk);
      expect(claims).toMatchObject({ ver: 9, modes: ['sso'], jti: 'gms-v9' });
      // unchanged licence, byte-identical token (the cache the contract relies on)
      expect(await signLicenseToken(record({ version: 9, modes: ['sso'] }))).toBe(token);
    } finally {
      delete process.env.LICENSE_SIGNING_KEY_FILE;
      jest.resetModules();
    }
  });
});

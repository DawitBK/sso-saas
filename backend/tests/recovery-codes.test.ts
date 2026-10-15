/**
 * Two-factor recovery codes (auth/recovery-codes.ts): the shape and parsing are pure; storage, single use and the race run against the
 * dev `idp` database with a scratch user (removed in afterAll).
 */
import { pool } from '../src/db/pool.js';
import {
  clearRecoveryCodes, consumeRecoveryCode, generateRecoveryCode, hashRecoveryCode, looksLikeTotp, normalizeRecoveryCode,
  RECOVERY_CODE_COUNT, recoveryCodesRemaining, replaceRecoveryCodes,
} from '../src/auth/recovery-codes.js';
import { disableTotp } from '../src/auth/local-users.js';

const EMAIL = 'jest-recovery@example.invalid';
let userId = '';

beforeAll(async () => {
  await pool.query('DELETE FROM idp_users WHERE email = $1', [EMAIL]);
  const { rows } = await pool.query<{ id: string }>(
    `INSERT INTO idp_users (email, email_verified, given_name, family_name, password_hash, source, is_active) VALUES ($1, TRUE, 'Jest', 'Recovery', 'x', 'local', TRUE) RETURNING id`,
    [EMAIL],
  );
  userId = rows[0].id;
});

afterAll(async () => {
  await pool.query('DELETE FROM idp_users WHERE email = $1', [EMAIL]);
  await pool.end();
});

describe('code shape and parsing', () => {
  it('a code is xxxxx-xxxxx from an alphabet without look-alike characters', () => {
    for (let i = 0; i < 200; i += 1) expect(generateRecoveryCode()).toMatch(/^[abcdefghjkmnpqrstuvwxyz23456789]{5}-[abcdefghjkmnpqrstuvwxyz23456789]{5}$/);
  });

  it('codes do not repeat', () => {
    const set = new Set(Array.from({ length: 500 }, generateRecoveryCode));
    expect(set.size).toBe(500);
  });

  it('typing is forgiven: case, spaces and a missing dash', () => {
    const code = generateRecoveryCode();
    const norm = normalizeRecoveryCode(code);
    expect(norm).toHaveLength(10);
    expect(normalizeRecoveryCode(code.toUpperCase())).toBe(norm);
    expect(normalizeRecoveryCode(` ${code.replace('-', ' ')} `)).toBe(norm);
    expect(normalizeRecoveryCode(code.replace('-', ''))).toBe(norm);
  });

  it('anything else is not a recovery code (so it never reaches the database)', () => {
    for (const bad of ['', '123456', 'abcde', 'abcde-fghjk-xyz23', 'abcde-fghj!', 'oooooooooo', 'iiiiiiiiii', '0000000000']) {
      expect({ bad, n: normalizeRecoveryCode(bad) }).toEqual({ bad, n: null });
    }
  });

  it('tells an authenticator code from a recovery code', () => {
    expect(looksLikeTotp('123456')).toBe(true);
    expect(looksLikeTotp('123 456')).toBe(true);
    expect(looksLikeTotp('abcde-fghjk')).toBe(false);
    expect(looksLikeTotp('1234567')).toBe(false);
  });

  it('the hash is keyed and stable, and differs per code', () => {
    const a = hashRecoveryCode('abcdefghjk');
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(hashRecoveryCode('abcdefghjk')).toBe(a);
    expect(hashRecoveryCode('abcdefghjm')).not.toBe(a);
    expect(a).not.toBe(require('node:crypto').createHash('sha256').update('abcdefghjk').digest('hex'));
  });
});

describe('storage and single use', () => {
  it('issues ten codes, stores only hashes', async () => {
    const codes = await replaceRecoveryCodes(userId);
    expect(codes).toHaveLength(RECOVERY_CODE_COUNT);
    expect(await recoveryCodesRemaining(userId)).toBe(10);
    const { rows } = await pool.query('SELECT code_hash FROM idp_recovery_codes WHERE user_id = $1', [userId]);
    for (const c of codes) expect(JSON.stringify(rows)).not.toContain(c.replace('-', ''));
    for (const r of rows) expect(r.code_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('a code works once, in any casing, and then never again', async () => {
    const [code] = await replaceRecoveryCodes(userId);
    expect(await consumeRecoveryCode(userId, (code as string).toUpperCase())).toBe(true);
    expect(await consumeRecoveryCode(userId, code as string)).toBe(false);
    expect(await recoveryCodesRemaining(userId)).toBe(9);
  });

  it('two requests racing with the same code: exactly one wins', async () => {
    const [code] = await replaceRecoveryCodes(userId);
    const results = await Promise.all(Array.from({ length: 8 }, () => consumeRecoveryCode(userId, code as string)));
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it('a wrong or foreign code is refused', async () => {
    await replaceRecoveryCodes(userId);
    expect(await consumeRecoveryCode(userId, 'abcde-fghjk')).toBe(false);
    expect(await consumeRecoveryCode(userId, '123456')).toBe(false);
    const { rows } = await pool.query<{ id: string }>(
      `INSERT INTO idp_users (email, email_verified, password_hash, source, is_active) VALUES ('jest-recovery-other@example.invalid', TRUE, 'x', 'local', TRUE) RETURNING id`,
    );
    try {
      const [theirs] = await replaceRecoveryCodes(rows[0].id);
      // one person's code does not open another person's account
      expect(await consumeRecoveryCode(userId, theirs as string)).toBe(false);
    } finally {
      await pool.query('DELETE FROM idp_users WHERE id = $1', [rows[0].id]);
    }
  });

  it('a new set replaces the old one at once', async () => {
    const old = await replaceRecoveryCodes(userId);
    const fresh = await replaceRecoveryCodes(userId);
    expect(await consumeRecoveryCode(userId, old[0] as string)).toBe(false);
    expect(await consumeRecoveryCode(userId, fresh[0] as string)).toBe(true);
  });

  it('turning two-factor off (or an administrator resetting it) deletes the codes', async () => {
    await replaceRecoveryCodes(userId);
    await disableTotp(userId);
    expect(await recoveryCodesRemaining(userId)).toBe(0);
  });

  it('clearRecoveryCodes removes them, and removing the account cascades', async () => {
    await replaceRecoveryCodes(userId);
    await clearRecoveryCodes(userId);
    expect(await recoveryCodesRemaining(userId)).toBe(0);
  });
});

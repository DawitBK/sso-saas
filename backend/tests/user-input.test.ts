import fs from 'node:fs';
import path from 'node:path';
import { USER_LIMITS, clipName, identityProblems, parseOfficeId } from '../src/admin/user-input.js';
import { pool } from '../src/db/pool.js';

describe('identityProblems', () => {
  const ok = { email: 'person@examplecorp.com', givenName: 'Abebe', familyName: 'Kebede' };

  it('accepts a normal identity and empty names (names are optional)', () => {
    expect(identityProblems(ok)).toEqual([]);
    expect(identityProblems({ ...ok, givenName: '', familyName: '' })).toEqual([]);
  });

  it('names the email problem in words', () => {
    expect(identityProblems({ ...ok, email: '' })).toEqual([{ field: 'email', message: 'Enter an email address.' }]);
    expect(identityProblems({ ...ok, email: 'person@host' })[0].message).toMatch(/valid email address/);
    expect(identityProblems({ ...ok, email: 'a b@x.co' })[0].field).toBe('email');
    expect(identityProblems({ ...ok, email: `${'a'.repeat(250)}@x.co` })[0].message).toMatch(/at most 254/);
  });

  it('counts characters, not UTF-16 units, so a 100-letter Amharic name is allowed and 101 is not', () => {
    const amharic = 'አ'.repeat(100);
    expect(identityProblems({ ...ok, givenName: amharic })).toEqual([]);
    expect(identityProblems({ ...ok, givenName: `${amharic}አ` })[0].field).toBe('given_name');
    expect(identityProblems({ ...ok, familyName: '😀'.repeat(100) })).toEqual([]);
  });
});

describe('clipName and parseOfficeId', () => {
  it('cuts a directory name to the stored length without splitting a character', () => {
    expect(Array.from(clipName('😀'.repeat(150))).length).toBe(100);
    expect(clipName('  Abebe  ')).toBe('Abebe');
    expect(clipName(undefined)).toBe('');
  });

  it('accepts only a positive whole number as an office id', () => {
    expect(parseOfficeId(undefined)).toBeNull();
    expect(parseOfficeId('')).toBeNull();
    expect(parseOfficeId('7')).toBe(7);
    expect(parseOfficeId(7)).toBe(7);
    for (const bad of ['abc', '1.5', '-3', '0', 'NaN', 1.5, {}]) expect(parseOfficeId(bad)).toBe('bad');
  });
});

describe('the table says the same as the route (migrations 023 and 024)', () => {
  const sql = fs.readFileSync(path.resolve(__dirname, '../migrations/023_user_identity_limits.sql'), 'utf8');
  const insert = 'INSERT INTO idp_users (email, email_verified, given_name, family_name, source, is_active) VALUES ($1, TRUE, $2, $3, $4, TRUE)';

  afterAll(async () => {
    await pool.end();
  });

  it('drift guard: the numbers in the migration are the numbers in the code', () => {
    expect(Number(/char_length\(email\) <= (\d+)/.exec(sql)?.[1])).toBe(USER_LIMITS.email);
    expect(Number(/char_length\(given_name\) <= (\d+)/.exec(sql)?.[1])).toBe(USER_LIMITS.name);
    expect(Number(/char_length\(family_name\) <= (\d+)/.exec(sql)?.[1])).toBe(USER_LIMITS.name);
  });

  it('refuses at the database what the console refuses, with the CHECK violation code (23514), and stores the boundary values', async () => {
    const client = await pool.connect();
    try {
      for (const [email, given, family, source] of [
        ['jest-ui-too-long@example.invalid', 'x'.repeat(101), 'Ok', 'local'],
        ['jest-ui-no-at.example.invalid', 'A', 'B', 'local'],
        ['jest ui space@example.invalid', 'A', 'B', 'local'],
        [`${'a'.repeat(250)}@example.invalid`, 'A', 'B', 'local'],
        ['jest-ui-source@example.invalid', 'A', 'B', 'ldap'],
      ] as const) {
        await client.query('BEGIN');
        await expect(client.query(insert, [email, given, family, source])).rejects.toMatchObject({ code: '23514' });
        await client.query('ROLLBACK');
      }
      await client.query('BEGIN');
      await client.query(insert, ['jest-ui-boundary@example.invalid', 'g'.repeat(100), 'f'.repeat(100), 'local']);
      await client.query('ROLLBACK');
    } finally {
      client.release();
    }
  });

  it('also requires a dot in the domain, as the route does (migration 024; 023 let it through for one account that has since been retired)', async () => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await expect(client.query(insert, ['jest-ui-dotless@examplecorpcom', 'A', 'B', 'local'])).rejects.toMatchObject({ code: '23514' });
      await client.query('ROLLBACK');
    } finally {
      client.release();
    }
  });
});

/**
 * Shared helpers for the owner-verification tests (not a test file itself).
 *
 * The integration tests run on their OWN scratch database on the local Postgres server (never the development, mirror or production databases): it is
 * dropped and created fresh, every migration is applied to it in order, and it is dropped again at the end. The connection settings (user, password,
 * host) are derived from the development DATABASE_URL at run time, so nothing is typed in here.
 *
 * Every secret in these tests (answers, mailbox address, authenticator secret, recovery codes) is generated at run time and never written anywhere.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import pg from 'pg';


function urlFor(base: string, db: string): string {
  const u = new URL(base);
  u.pathname = `/${db}`;
  return u.toString();
}

/** The scratch database's URL, derived from the development URL. */
export function scratchUrl(devUrl: string, name: string): string {
  return urlFor(devUrl, name);
}

export async function createScratchDb(devUrl: string, name: string): Promise<void> {
  const admin = new pg.Client({ connectionString: urlFor(devUrl, 'postgres') });
  await admin.connect();
  try {
    await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
    await admin.query(`CREATE DATABASE ${name}`);
  } finally {
    await admin.end();
  }
  const db = new pg.Client({ connectionString: scratchUrl(devUrl, name) });
  await db.connect();
  try {
    const dir = path.resolve(process.cwd(), 'migrations');
    const files = fs.readdirSync(dir).filter((f) => f.endsWith('.sql') && !f.endsWith('.down.sql')).sort();
    for (const f of files) await db.query(fs.readFileSync(path.join(dir, f), 'utf8'));
  } finally {
    await db.end();
  }
}

export async function dropScratchDb(devUrl: string, name: string): Promise<void> {
  const admin = new pg.Client({ connectionString: urlFor(devUrl, 'postgres') });
  await admin.connect();
  try {
    await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
  } finally {
    await admin.end();
  }
}

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Decode(s: string): Buffer {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of s.toUpperCase().replace(/[^A-Z2-7]/g, '')) {
    value = (value << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** A valid authenticator code for `secret` at the current time step plus `offsetSteps`. */
export function totpCode(secret: string, offsetSteps = 0): string {
  const counter = Math.floor(Date.now() / 1000 / 30) + offsetSteps;
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', base32Decode(secret)).update(buf).digest();
  const o = (hmac[hmac.length - 1] as number) & 0x0f;
  const n = (((hmac[o] as number) & 0x7f) << 24) | (((hmac[o + 1] as number) << 16) | ((hmac[o + 2] as number) << 8) | (hmac[o + 3] as number));
  return String(n % 1_000_000).padStart(6, '0');
}

/** A throwaway value that is different every run (a stand-in for an answer, an address local part, ...). */
export const throwaway = (label: string): string => `${label}-${crypto.randomBytes(6).toString('hex')}`;

export function tempKeyFilePath(): string {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'p4-owner-key-')), 'owner-store.key');
}

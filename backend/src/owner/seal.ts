/**
 * The seal around the owner store: AES-256-GCM with a key that is NOT in the repository, the environment or the database.
 *
 * The key is a file named by OWNER_STORE_KEY_FILE (64 hex characters = 32 random bytes), created by `npm run owner:enroll` with restrictive
 * permissions (mode 0600; on Windows `icacls` with inheritance removed and only the current account granted). Two sub-keys are derived from it with
 * HKDF-SHA256, one for sealing and one for keyed hashes (answers, recovery codes, the emailed code), so the one file protects all of it.
 *
 * Honest limit: a process that runs as the SAME operating-system account as the SSO service can read that file, so can a person who is that
 * account. What protects the store is running the service as its own account and the file's ACL; the seal protects against everything else
 * (a database dump, a read-only SQL injection, a backup copied off the server without the key file, a database write that tries to substitute
 * different questions or a different authenticator: the seal is authenticated, so a forged store fails to open instead of being believed).
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import os from 'node:os';

export interface StoreKeys {
  /** Identifies the key file without revealing it (a hash prefix); stored beside the sealed document. */
  keyId: string;
  enc: Buffer;
  mac: Buffer;
}

export class OwnerStoreKeyError extends Error {
  constructor(
    public readonly reason: 'not_configured' | 'missing' | 'unreadable' | 'malformed',
    message: string,
  ) {
    super(message);
    this.name = 'OwnerStoreKeyError';
  }
}

const HEX64 = /^[0-9a-fA-F]{64}$/;

/** Derive the working keys from the 32 raw bytes. */
export function deriveKeys(root: Buffer): StoreKeys {
  if (root.length !== 32) throw new OwnerStoreKeyError('malformed', 'The owner store key must be 32 bytes.');
  const enc = Buffer.from(crypto.hkdfSync('sha256', root, Buffer.alloc(0), 'examplecorp-owner-store/seal/v1', 32));
  const mac = Buffer.from(crypto.hkdfSync('sha256', root, Buffer.alloc(0), 'examplecorp-owner-store/mac/v1', 32));
  const keyId = crypto.createHash('sha256').update('examplecorp-owner-store/id/v1').update(root).digest('hex').slice(0, 16);
  return { keyId, enc, mac };
}

let cached: { path: string; mtimeMs: number; size: number; keys: StoreKeys } | null = null;

/** Read the key file (cached until the file changes). Never logs or returns the raw bytes beyond the derived keys. */
export function loadStoreKeys(file: string): StoreKeys {
  if (!file) throw new OwnerStoreKeyError('not_configured', 'OWNER_STORE_KEY_FILE is not set.');
  let stat: fs.Stats;
  try {
    stat = fs.statSync(file);
  } catch {
    throw new OwnerStoreKeyError('missing', 'The owner store key file does not exist.');
  }
  if (cached && cached.path === file && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) return cached.keys;
  let text: string;
  try {
    text = fs.readFileSync(file, 'utf8').trim();
  } catch {
    throw new OwnerStoreKeyError('unreadable', 'The owner store key file cannot be read.');
  }
  if (!HEX64.test(text)) throw new OwnerStoreKeyError('malformed', 'The owner store key file is not 64 hexadecimal characters.');
  const keys = deriveKeys(Buffer.from(text, 'hex'));
  cached = { path: file, mtimeMs: stat.mtimeMs, size: stat.size, keys };
  return keys;
}

/** Forget the cached key (tests, and after the enrolment tool writes a new file). */
export function resetStoreKeyCache(): void {
  cached = null;
}

const b64 = (b: Buffer): string => b.toString('base64url');

/** Seal a JSON-serialisable document. Format `v1.<iv>.<tag>.<ciphertext>`; `aad` is authenticated but not stored. */
export function seal(keys: StoreKeys, doc: unknown, aad: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', keys.enc, iv);
  cipher.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([cipher.update(JSON.stringify(doc), 'utf8'), cipher.final()]);
  return `v1.${b64(iv)}.${b64(cipher.getAuthTag())}.${b64(ct)}`;
}

/** Open a sealed document; throws if the key, the format, the context or any byte is wrong. */
export function open<T>(keys: StoreKeys, sealed: string, aad: string): T {
  const [v, iv, tag, ct] = sealed.split('.');
  if (v !== 'v1' || !iv || !tag || !ct) throw new Error('unsupported sealed format');
  const decipher = crypto.createDecipheriv('aes-256-gcm', keys.enc, Buffer.from(iv, 'base64url'));
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  const pt = Buffer.concat([decipher.update(Buffer.from(ct, 'base64url')), decipher.final()]);
  return JSON.parse(pt.toString('utf8')) as T;
}

/** HMAC-SHA256 (hex) with the keyed-hash sub-key: for the emailed code and the recovery codes. */
export function keyedHash(keys: StoreKeys, ...parts: string[]): string {
  return crypto.createHmac('sha256', keys.mac).update(parts.join('\u0000')).digest('hex');
}

/** Constant-time equality for two hex/text strings of any length (a length difference is not a timing leak worth hiding here: both are fixed-size digests). */
export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

/**
 * Create a NEW key file (refuses to overwrite one). Written with `wx` and mode 0600, then locked down with icacls on Windows. Returns the keys.
 * The file is the only copy: lose it and the sealed store cannot be opened (re-enrol with `npm run owner:recover`).
 */
export function createKeyFile(file: string): StoreKeys {
  const root = crypto.randomBytes(32);
  fs.writeFileSync(file, `${root.toString('hex')}\n`, { flag: 'wx', mode: 0o600 });
  if (process.platform === 'win32') {
    // Remove inherited permissions and grant only the account running this tool. A failure here is reported, not ignored: a key file anyone can read is not a seal.
    const me = (() => {
      try {
        return execFileSync('whoami', { encoding: 'utf8' }).trim();
      } catch {
        return `${process.env.USERDOMAIN ?? os.hostname()}\${os.userInfo().username}`;
      }
    })();
    execFileSync('icacls', [file, '/inheritance:r', '/grant:r', `${me}:(R,W,D)`], { stdio: 'ignore' });
  }
  resetStoreKeyCache();
  return deriveKeys(root);
}

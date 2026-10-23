/**
 * The sealed owner store (migration 027): one AES-256-GCM sealed document holding the security-question hashes, the owner's mailbox address, the
 * authenticator secret and the recovery-code hashes. See seal.ts for what the seal does and does not protect against.
 *
 * Reading never throws for an ordinary problem: it says which problem it is (`none`: nobody enrolled; `unreadable`: a row exists but this process
 * cannot open it, with the reason). Callers fail CLOSED on `unreadable` (a missing or wrong key file must never be read as "not enrolled, so allow").
 */
import { pool } from '../db/pool.js';
import { smtpConfigured, smtpFingerprint } from './mailer.js';
import { matchRecoveryCode, type RecoveryRecord } from './recovery.js';
import { storeKeyFile } from './runtime.js';
import { OwnerStoreKeyError, loadStoreKeys, open, seal, type StoreKeys } from './seal.js';

const AAD = 'examplecorp-owner-store:v1';

export interface OwnerStoreDoc {
  v: 1;
  /** The platform administrator's account id this store belongs to. A session of any other account never matches. */
  accountId: string;
  questions: Array<{ prompt: string; hash: string }>;
  email: { address: string; smtpFingerprint: string };
  /** The authenticator secret. Absent when the enrolment was made without the authenticator (`factors.authenticator === false`): nothing is stored for it then. */
  totp?: { secret: string };
  /**
   * The factors this enrolment was made with. A store written before this field existed has none and means authenticator = true. Verification always
   * demands the factors recorded here, never the current OWNER_AUTHENTICATOR_REQUIRED, so the setting can never weaken an existing enrolment.
   */
  factors?: { authenticator: boolean };
  recoveryCodes: RecoveryRecord[];
  createdAt: string;
  updatedAt: string;
}

export type StoreRead =
  | { state: 'none' }
  | { state: 'unreadable'; reason: 'not_configured' | 'missing' | 'unreadable' | 'malformed' | 'wrong_key' | 'corrupt' }
  | { state: 'ok'; doc: OwnerStoreDoc; keys: StoreKeys };

export async function readStore(): Promise<StoreRead> {
  const { rows } = await pool.query<{ sealed: string; key_id: string }>('SELECT sealed, key_id FROM owner_verification_store WHERE id = 1');
  if (!rows[0]) return { state: 'none' };
  let keys: StoreKeys;
  try {
    keys = loadStoreKeys(storeKeyFile());
  } catch (err) {
    if (err instanceof OwnerStoreKeyError) return { state: 'unreadable', reason: err.reason };
    return { state: 'unreadable', reason: 'unreadable' };
  }
  if (keys.keyId !== rows[0].key_id) return { state: 'unreadable', reason: 'wrong_key' };
  try {
    return { state: 'ok', doc: open<OwnerStoreDoc>(keys, rows[0].sealed, AAD), keys };
  } catch {
    return { state: 'unreadable', reason: 'corrupt' };
  }
}

/** Replace the whole store (enrolment, recovery, change of mailbox). Clears the used-recovery-code list and makes sure the counter row exists. */
export async function writeStore(keys: StoreKeys, doc: OwnerStoreDoc): Promise<void> {
  const sealed = seal(keys, doc, AAD);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `INSERT INTO owner_verification_store (id, sealed, key_id) VALUES (1, $1, $2)
       ON CONFLICT (id) DO UPDATE SET sealed = EXCLUDED.sealed, key_id = EXCLUDED.key_id, store_version = owner_verification_store.store_version + 1, updated_at = NOW()`,
      [sealed, keys.keyId],
    );
    await client.query('DELETE FROM owner_recovery_codes_used');
    await client.query('INSERT INTO owner_verification_state (id) VALUES (1) ON CONFLICT (id) DO NOTHING');
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}

/** Fails CLOSED: only an explicit `authenticator: false` in the sealed document means "no authenticator"; a missing or odd value means it is required. */
export function authenticatorRequired(doc: OwnerStoreDoc): boolean {
  return doc.factors?.authenticator !== false;
}

export interface EmailAvailability {
  available: boolean;
  reason: null | 'smtp_not_configured';
}

/**
 * The emailed code is offered whenever SMTP is configured in THIS environment, and it is always sent through the relay configured there NOW (owner decision
 * 2026-10-21: change SMTP_* in the env file, restart SSO, and the code follows, on the server, the development machine or anywhere else). The relay recorded at
 * enrolment is no longer a gate; a difference is only noted in the log (see `relayChangedSinceEnrolment`). The destination stays the owner's sealed mailbox.
 */
export function emailAvailability(_doc: OwnerStoreDoc): EmailAvailability {
  if (!smtpConfigured()) return { available: false, reason: 'smtp_not_configured' };
  return { available: true, reason: null };
}

/** True when the relay now configured differs from the one recorded at enrolment (used only to log a notice; never to refuse). */
export function relayChangedSinceEnrolment(doc: OwnerStoreDoc): boolean {
  return smtpFingerprint() !== doc.email.smtpFingerprint;
}

export async function recoveryCodesRemaining(doc: OwnerStoreDoc): Promise<number> {
  const { rows } = await pool.query<{ n: number }>('SELECT COUNT(*)::int AS n FROM owner_recovery_codes_used');
  return Math.max(0, doc.recoveryCodes.length - (rows[0]?.n ?? 0));
}

/**
 * Use a recovery code: `ok` the first time a correct one is presented, `used` for one already spent, `invalid` for anything else.
 * The primary key on the used table makes "spend once" atomic even for two simultaneous requests.
 */
export async function spendRecoveryCode(keys: StoreKeys, doc: OwnerStoreDoc, code: string): Promise<'ok' | 'used' | 'invalid'> {
  const id = matchRecoveryCode(keys, doc.recoveryCodes, code);
  if (!id) return 'invalid';
  const res = await pool.query('INSERT INTO owner_recovery_codes_used (code_id) VALUES ($1) ON CONFLICT DO NOTHING', [id]);
  return res.rowCount === 1 ? 'ok' : 'used';
}

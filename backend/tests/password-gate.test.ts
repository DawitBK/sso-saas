/**
 * Password checks go through a bounded gate (auth/password.ts + infrastructure/workGate.ts). When it is full, verifyPassword must throw
 * GateBusyError, NEVER return false: "busy" must not read as "wrong password" (it would be counted as a failed sign-in and shown as one).
 */
jest.mock('../src/config.js', () => ({ IDP_CONFIG: { passwordHash: { concurrency: 1, maxQueue: 0, maxWaitMs: 50 } } }));

import { hashPassword, passwordGate, verifyPassword } from '../src/auth/password.js';
import { GateBusyError } from '../src/infrastructure/workGate.js';

let stored: string;
beforeAll(async () => { stored = await hashPassword('Correct-Horse-1'); }, 30_000);

describe('password checks under load', () => {
  it('still verify normally when the gate has room', async () => {
    await expect(verifyPassword('Correct-Horse-1', stored)).resolves.toBe(true);
    await expect(verifyPassword('wrong', stored)).resolves.toBe(false);
  });

  it('a check turned away because the gate is full throws "busy", it does not report a wrong password', async () => {
    const first = verifyPassword('Correct-Horse-1', stored);
    // one slot, no queue: the second cannot start and cannot wait
    await expect(verifyPassword('Correct-Horse-1', stored)).rejects.toBeInstanceOf(GateBusyError);
    await expect(first).resolves.toBe(true);
    expect(passwordGate.stats().refused).toBeGreaterThanOrEqual(1);
  });

  it('hashing is gated the same way and recovers afterwards', async () => {
    const running = hashPassword('another-one');
    await expect(hashPassword('and-another')).rejects.toBeInstanceOf(GateBusyError);
    await expect(running).resolves.toMatch(/^scrypt\$/);
    await expect(verifyPassword('Correct-Horse-1', stored)).resolves.toBe(true);
  });

  it('input that is not a stored hash is false without touching the gate', async () => {
    const before = passwordGate.stats().completed;
    await expect(verifyPassword('x', null)).resolves.toBe(false);
    await expect(verifyPassword('x', 'plaintext')).resolves.toBe(false);
    await expect(verifyPassword('x', 'scrypt$1$2$3')).resolves.toBe(false);
    expect(passwordGate.stats().completed).toBe(before);
  });
});

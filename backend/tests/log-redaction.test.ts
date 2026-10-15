/** Secrets must not survive into a log line (logging/logger.ts LOG_REDACT_PATHS), at the top level or one level down. */
import pino from 'pino';
import { Writable } from 'node:stream';
import { LOG_REDACT_PATHS } from '../src/logging/logger.js';

function capture(): { log: pino.Logger; lines: () => string } {
  const chunks: string[] = [];
  const stream = new Writable({ write(chunk, _enc, cb) { chunks.push(String(chunk)); cb(); } });
  return { log: pino({ redact: LOG_REDACT_PATHS }, stream), lines: () => chunks.join('') };
}

describe('log redaction', () => {
  it('hides credentials at the top level and one level down', () => {
    const { log, lines } = capture();
    log.info({
      password: 'hunter2-top', authorization_code: 'abcde-fghjk', refresh_token: 'rt-top',
      body: { password: 'hunter2-nested', current_password: 'old-pass', new_password: 'new-pass', csrf: 'csrf-nested', client_secret: 'cs-nested', logout_token: 'lt-nested' },
      tokens: { access_token: 'at-nested', id_token: 'it-nested', refreshToken: 'rt-nested' },
      user: { totp_secret: 'JBSWY3DPEHPK3PXP', recoveryCode: 'zzzzz-yyyyy', passwordHash: 'scrypt$x' },
    }, 'attempt');
    const out = lines();
    for (const secret of ['hunter2-top', 'abcde-fghjk', 'rt-top', 'hunter2-nested', 'old-pass', 'new-pass', 'csrf-nested', 'cs-nested', 'lt-nested', 'at-nested', 'it-nested', 'rt-nested', 'JBSWY3DPEHPK3PXP', 'zzzzz-yyyyy', 'scrypt$x']) {
      expect({ secret, leaked: out.includes(secret) }).toEqual({ secret, leaked: false });
    }
    expect(out).toContain('[Redacted]');
  });

  it('hides the cookie header and shared keys on a logged request', () => {
    const { log, lines } = capture();
    log.info({ req: { method: 'GET', headers: { cookie: 'idp_portal=SESSIONVALUE', authorization: 'Bearer TOKENVALUE', 'x-internal-api-key': 'KEYVALUE', 'x-metrics-key': 'METRICSVALUE', 'user-agent': 'ua' } } }, 'req');
    const out = lines();
    for (const secret of ['SESSIONVALUE', 'TOKENVALUE', 'KEYVALUE', 'METRICSVALUE']) expect(out.includes(secret)).toBe(false);
    expect(out).toContain('"user-agent":"ua"');
  });

  it('leaves ordinary fields alone, including a database error code, which is how a fault is diagnosed', () => {
    const { log, lines } = capture();
    log.info({ accountId: 'u1', reason: 'mfa_failed', status: 401, err: { code: '28P01', message: 'x' } }, 'event');
    expect(lines()).toContain('28P01');
    expect(lines()).toContain('"accountId":"u1"');
    expect(lines()).toContain('"reason":"mfa_failed"');
  });
});

import express from 'express';
import type { Server } from 'node:http';
import { describeDatabaseError, describeRequestError, describeError, lastStopErrorHandler } from '../src/http/api-errors.js';

jest.mock('../src/logging/logger.js', () => ({
  logger: { error: jest.fn(), warn: jest.fn(), info: jest.fn(), debug: jest.fn(), child: () => ({ error: jest.fn(), warn: jest.fn(), info: jest.fn(), debug: jest.fn() }) },
}));

const pg = (code: string, extra: Record<string, string> = {}) => Object.assign(new Error('driver text that must never reach a caller: relation "idp_users" value (secret@x.y)'), { code, ...extra });

describe('describeDatabaseError', () => {
  it('turns the users email uniqueness into the same answer the create-user route gives', () => {
    expect(describeDatabaseError(pg('23505', { table: 'idp_users', constraint: 'idp_users_email_key' }))).toMatchObject({
      status: 409,
      code: 'ERR-EMAIL-EXISTS',
      message: 'A user with that email already exists.',
    });
  });

  it('answers any other duplicate as a 409 naming the kind of record', () => {
    expect(describeDatabaseError(pg('23505', { table: 'idp_clients', constraint: 'idp_clients_pkey' }))).toMatchObject({ status: 409, code: 'ERR-DUPLICATE', message: 'A application with these details already exists.' });
  });

  it('names the missing field in words for NOT NULL', () => {
    expect(describeDatabaseError(pg('23502', { table: 'idp_users', column: 'given_name' }))).toMatchObject({ status: 400, code: 'ERR-REQUIRED-FIELD', message: 'First name is required.' });
  });

  it('maps CHECK, foreign key, too long, out of range and malformed input to 4xx', () => {
    expect(describeDatabaseError(pg('23514', { table: 'idp_users', constraint: 'idp_users_email_length' }))).toMatchObject({ status: 422, code: 'ERR-CONSTRAINT-VIOLATION' });
    expect(describeDatabaseError(pg('23503'))).toMatchObject({ status: 409, code: 'ERR-REFERENCE' });
    expect(describeDatabaseError(pg('22001'))).toMatchObject({ status: 400, code: 'ERR-VALUE-TOO-LONG' });
    expect(describeDatabaseError(pg('22003'))).toMatchObject({ status: 400, code: 'ERR-VALUE-OUT-OF-RANGE' });
    expect(describeDatabaseError(pg('22P02'))).toMatchObject({ status: 400, code: 'ERR-VALIDATION-FAILED' });
  });

  it('leaves anything else alone (a lost connection is a fault, not the caller\'s mistake)', () => {
    expect(describeDatabaseError(pg('57P01'))).toBeNull();
    expect(describeDatabaseError(new Error('boom'))).toBeNull();
    expect(describeDatabaseError('text')).toBeNull();
  });

  it('never repeats the driver message, a table name or a value', () => {
    const answers = ['23505', '23502', '23503', '23514', '22001', '22003', '22P02'].map((c) => describeDatabaseError(pg(c, { table: 'idp_users', column: 'email', constraint: 'idp_users_secret_key' })));
    for (const a of answers) expect(`${a?.message}`).not.toMatch(/idp_|secret@|relation|driver text/);
  });
});

describe('describeRequestError', () => {
  it('recognises a body that is not JSON and one that is too large', () => {
    expect(describeRequestError(Object.assign(new Error('x'), { type: 'entity.parse.failed', status: 400 }))).toMatchObject({ status: 400, code: 'ERR-INVALID-JSON' });
    expect(describeRequestError(Object.assign(new Error('x'), { type: 'entity.too.large', status: 413 }))).toMatchObject({ status: 413, code: 'ERR-PAYLOAD-TOO-LARGE' });
    expect(describeRequestError(Object.assign(new Error('x'), { type: 'charset.unsupported', status: 415 }))).toMatchObject({ status: 415, code: 'ERR-UNSUPPORTED-MEDIA-TYPE' });
  });

  it('gives every client-error status its own code and sentence, and ignores 5xx and non-errors', () => {
    for (const [status, code] of [[400, 'ERR-VALIDATION-FAILED'], [401, 'ERR-NOT-AUTHENTICATED'], [403, 'ERR-FORBIDDEN'], [404, 'ERR-NOT-FOUND'], [429, 'ERR-RATE-LIMITED']] as const) {
      expect(describeRequestError({ status })).toMatchObject({ status, code });
    }
    expect(describeRequestError({ status: 418 })).toMatchObject({ status: 418, code: 'ERR-REQUEST' });
    expect(describeRequestError({ status: 502 })).toBeNull();
    expect(describeRequestError(null)).toBeNull();
  });
});

describe('describeError', () => {
  it('falls back to a 500 that carries no cause', () => {
    expect(describeError(new Error('the database password is hunter2'))).toEqual({ status: 500, code: 'ERR-INTERNAL', message: 'Something went wrong.' });
  });
});

describe('lastStopErrorHandler over real HTTP', () => {
  let server: Server;
  let base: string;

  beforeAll(async () => {
    const app = express();
    app.use((_req, res, next) => {
      res.locals.requestId = 'req-test-1';
      next();
    });
    app.use(express.json({ limit: '1kb' }));
    app.post('/api/v1/echo', (_req, res) => res.json({ ok: true }));
    app.get('/api/v1/duplicate', (_req, _res, next) => next(pg('23505', { table: 'idp_users', constraint: 'idp_users_email_key' })));
    app.get('/api/v1/crash', (_req, _res, next) => next(new Error('secret internals')));
    app.get('/page', (_req, _res, next) => next(pg('22001')));
    app.use(lastStopErrorHandler());
    await new Promise<void>((resolve) => {
      server = app.listen(0, '127.0.0.1', () => resolve());
    });
    base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('answers a malformed JSON body as 400 ERR-INVALID-JSON with the request id', async () => {
    const res = await fetch(`${base}/api/v1/echo`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"a":' });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: { code: 'ERR-INVALID-JSON', message: 'The request body is not valid JSON.' }, meta: { requestId: 'req-test-1' } });
  });

  it('answers an oversized body as 413', async () => {
    const res = await fetch(`${base}/api/v1/echo`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ a: 'x'.repeat(5000) }) });
    expect(res.status).toBe(413);
    expect((await res.json()).error.code).toBe('ERR-PAYLOAD-TOO-LARGE');
  });

  it('answers a database duplicate as a typed 409, and a crash as a plain 500 that hides the cause', async () => {
    const dup = await fetch(`${base}/api/v1/duplicate`);
    expect(dup.status).toBe(409);
    expect((await dup.json()).error.code).toBe('ERR-EMAIL-EXISTS');
    const crash = await fetch(`${base}/api/v1/crash`);
    expect(crash.status).toBe(500);
    const body = await crash.json();
    expect(body.error).toEqual({ code: 'ERR-INTERNAL', message: 'Something went wrong.' });
    expect(JSON.stringify(body)).not.toContain('secret internals');
  });

  it('answers a browser page request in plain text', async () => {
    const res = await fetch(`${base}/page`, { headers: { accept: 'text/html' } });
    expect(res.status).toBe(400);
    expect(res.headers.get('content-type')).toMatch(/text\/plain/);
    expect(await res.text()).toBe('One of the values provided is longer than allowed.');
  });
});

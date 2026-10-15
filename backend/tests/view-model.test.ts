import { describe, expect, it } from '@jest/globals';
import { serializeLocals, viewModelMiddleware, SSO_VIEW_CONTENT_TYPE } from '../src/http/view-model.js';
import type { Request, Response } from 'express';

function fakeRes() {
  const state: { statusCode: number; headers: Record<string, string>; body?: unknown } = {
    statusCode: 200,
    headers: {},
  };
  const res = {
    locals: {},
    get statusCode() {
      return state.statusCode;
    },
    status(code: number) {
      state.statusCode = code;
      return res;
    },
    set(name: string, value: string) {
      state.headers[name] = value;
      return res;
    },
    get(name: string) {
      return state.headers[name];
    },
    type(value: string) {
      state.headers['content-type'] = value;
      return res;
    },
    json(payload: unknown) {
      state.body = payload;
      return res;
    },
    render() {
      throw new Error('render must be overwritten by viewModelMiddleware');
    },
  };
  return { res: res as unknown as Response, state };
}

describe('view-model contract', () => {
  it('always returns the JSON view model, regardless of any request header', () => {
    const { res, state } = fakeRes();
    viewModelMiddleware({} as Request, res, () => undefined);
    res.render('login', { foo: 'bar' });
    expect(state.headers['content-type']).toBe(SSO_VIEW_CONTENT_TYPE);
    expect(state.body).toEqual({ view: 'login', locals: { foo: 'bar' } });
  });

  it('serializes Dates and BigInts safely', () => {
    const out = serializeLocals({
      when: new Date('2026-07-24T00:00:00.000Z'),
      count: 10n,
      nested: { ok: true },
    });
    expect(out.when).toBe('2026-07-24T00:00:00.000Z');
    expect(out.count).toBe('10');
    expect(out.nested).toEqual({ ok: true });
  });
});

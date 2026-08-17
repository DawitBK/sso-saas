import { describe, expect, it, jest } from '@jest/globals';
import { z } from 'zod';
import { parseOrRenderView, parseOrSendError } from '../src/validation/parse.js';
import { formatZodIssues, zodIssuesAsDetails } from '../src/validation/format.js';
import { LoginBodySchema, PasswordChangeBodySchema, TotpBodySchema } from '../src/interactions/schemas.js';
import { EmailParamSchema, SetRolesBodySchema } from '../src/admin/gms-role-grants.schemas.js';

function mockRes() {
  const calls: Array<{ status: number; view: string; locals: Record<string, unknown> }> = [];
  const res: any = {
    statusCode: 200,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    render(view: string, locals: Record<string, unknown>) {
      calls.push({ status: this.statusCode, view, locals });
    },
  };
  return { res, calls };
}

describe('parseOrRenderView', () => {
  it('returns the parsed data and renders nothing on success', () => {
    const { res, calls } = mockRes();
    const schema = z.object({ name: z.string() });
    const result = parseOrRenderView(schema, { name: 'ok' }, res, 'some-view', {});
    expect(result).toEqual({ data: { name: 'ok' } });
    expect(calls).toHaveLength(0);
  });

  it('renders the same view with a 400 and a message, returning null, on failure', () => {
    const { res, calls } = mockRes();
    const schema = z.object({ name: z.string() });
    const result = parseOrRenderView(schema, { name: 123 }, res, 'some-view', { uid: 'u1' });
    expect(result).toBeNull();
    expect(calls).toHaveLength(1);
    expect(calls[0].status).toBe(400);
    expect(calls[0].view).toBe('some-view');
    expect(calls[0].locals.uid).toBe('u1');
    expect(typeof calls[0].locals.error).toBe('string');
  });
});

describe('parseOrSendError', () => {
  it('returns the parsed data and never calls the responder on success', () => {
    const schema = z.object({ n: z.number() });
    const responder = jest.fn();
    const result = parseOrSendError(schema, { n: 5 }, responder);
    expect(result).toEqual({ data: { n: 5 } });
    expect(responder).not.toHaveBeenCalled();
  });

  it('calls the responder with field-level details and returns null on failure', () => {
    const schema = z.object({ n: z.number() });
    const responder = jest.fn();
    const result = parseOrSendError(schema, { n: 'not a number' }, responder);
    expect(result).toBeNull();
    expect(responder).toHaveBeenCalledTimes(1);
    const details = responder.mock.calls[0][0] as Array<{ field?: string; message: string }>;
    expect(details[0].field).toBe('n');
  });
});

describe('format helpers', () => {
  it('formatZodIssues joins path:message pairs, falling back to a bare message for root-level issues', () => {
    const schema = z.object({ email: z.string().email() });
    const result = schema.safeParse({ email: 'not-an-email' });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(formatZodIssues(result.error)).toMatch(/^email: /);
    }
  });

  it('zodIssuesAsDetails omits the field key entirely for root-level issues', () => {
    const schema = z.string();
    const result = schema.safeParse(123);
    expect(result.success).toBe(false);
    if (!result.success) {
      const details = zodIssuesAsDetails(result.error);
      expect(details[0].field).toBeUndefined();
    }
  });
});

describe('SSO route schemas reject the shapes they were added to catch', () => {
  it('LoginBodySchema requires a real email and a non-empty password', () => {
    expect(LoginBodySchema.safeParse({ email: 'admin@examplecorp.com', password: 'x' }).success).toBe(true);
    expect(LoginBodySchema.safeParse({ email: 'not-an-email', password: 'x' }).success).toBe(false);
    expect(LoginBodySchema.safeParse({ email: 'admin@examplecorp.com', password: '' }).success).toBe(false);
    expect(LoginBodySchema.safeParse({ email: 'admin@examplecorp.com' }).success).toBe(false);
  });

  it('TotpBodySchema requires a non-empty code', () => {
    expect(TotpBodySchema.safeParse({ code: '123456' }).success).toBe(true);
    expect(TotpBodySchema.safeParse({ code: '' }).success).toBe(false);
    expect(TotpBodySchema.safeParse({}).success).toBe(false);
  });

  it('PasswordChangeBodySchema requires both fields present (length/match rules stay in the handler)', () => {
    expect(PasswordChangeBodySchema.safeParse({ password: 'a', confirm: 'a' }).success).toBe(true);
    expect(PasswordChangeBodySchema.safeParse({ password: 'a' }).success).toBe(false);
  });

  it('EmailParamSchema and SetRolesBodySchema match the gms-role-grants API shape', () => {
    expect(EmailParamSchema.safeParse({ email: 'admin@examplecorp.com' }).success).toBe(true);
    expect(EmailParamSchema.safeParse({ email: 'not-an-email' }).success).toBe(false);
    expect(SetRolesBodySchema.safeParse({ roles: ['admin', 'reception'] }).success).toBe(true);
    expect(SetRolesBodySchema.safeParse({ roles: 'admin' }).success).toBe(false);
    expect(SetRolesBodySchema.safeParse({ roles: [] }).success).toBe(true);
  });
});

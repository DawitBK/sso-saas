import { reuseOrIssueCsrf } from '../src/http/csrf-token.js';

function fakeRes(cookieHeader?: string) {
  const set: Array<{ name: string; value: string; options: unknown }> = [];
  const res = { req: { headers: { cookie: cookieHeader } }, cookie: (name: string, value: string, options: unknown) => { set.push({ name, value, options }); } };
  return { res: res as never, set };
}
const OPTS = { httpOnly: true, sameSite: 'lax' as const, path: '/portal' };
const GOOD = 'a'.repeat(48);

describe('reuseOrIssueCsrf', () => {
  it('issues a fresh 48-hex token when the browser sent none, and sets the cookie', () => {
    const { res, set } = fakeRes();
    const token = reuseOrIssueCsrf(res, 'idp_portal_csrf', OPTS);
    expect(token).toMatch(/^[a-f0-9]{48}$/);
    expect(set).toEqual([{ name: 'idp_portal_csrf', value: token, options: OPTS }]);
  });

  it('reuses the token the browser already holds, so a second render does not invalidate the first', () => {
    const { res, set } = fakeRes(`other=1; idp_portal_csrf=${GOOD}; x=2`);
    expect(reuseOrIssueCsrf(res, 'idp_portal_csrf', OPTS)).toBe(GOOD);
    expect(set[0]?.value).toBe(GOOD);
  });

  it('ignores a malformed value and issues a new one', () => {
    for (const bad of ['short', 'Z'.repeat(48), `${GOOD}00`, '']) {
      const { res } = fakeRes(`idp_portal_csrf=${bad}`);
      const token = reuseOrIssueCsrf(res, 'idp_portal_csrf', OPTS);
      expect(token).not.toBe(bad);
      expect(token).toMatch(/^[a-f0-9]{48}$/);
    }
  });

  it('takes the first well-formed value when the name appears more than once', () => {
    const second = 'b'.repeat(48);
    const { res } = fakeRes(`idp_portal_csrf=bad; idp_portal_csrf=${GOOD}; idp_portal_csrf=${second}`);
    expect(reuseOrIssueCsrf(res, 'idp_portal_csrf', OPTS)).toBe(GOOD);
  });

  it('only reads the cookie it was asked for', () => {
    const { res } = fakeRes(`idp_csrf=${GOOD}`);
    expect(reuseOrIssueCsrf(res, 'idp_portal_csrf', OPTS)).not.toBe(GOOD);
  });
});

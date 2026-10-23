/**
 * The sign-out page is built for the issuer's address whatever Host the proxy chain reports (oidc/end-session-origin.ts). The rule itself is tested here;
 * the real oidc-provider (an ES module jest cannot load) is driven by test-scripts/verify-end-session-origin.ts (`npm run verify:end-session-origin`).
 */
import { END_SESSION_PATH, pinEndSessionOrigin } from '../src/oidc/end-session-origin.js';

describe('pinEndSessionOrigin (unit)', () => {
  const run = async (path: string) => {
    const ctx = { path, request: {} as { host?: string; protocol?: string } };
    await pinEndSessionOrigin('https://portal.example.com/sso')(ctx, async () => undefined);
    return ctx.request;
  };

  it('pins host and scheme on every end-session route and leaves every other route alone', async () => {
    for (const p of ['/session/end', '/session/end/confirm', '/session/end/success', '/sso/session/end']) {
      const r = await run(p);
      expect(r.host).toBe('portal.example.com');
      expect(r.protocol).toBe('https');
    }
    for (const p of ['/auth', '/token', '/jwks', '/.well-known/openid-configuration', '/session/ending', '/me']) {
      const r = await run(p);
      expect(r.host).toBeUndefined();
      expect(r.protocol).toBeUndefined();
    }
    expect(END_SESSION_PATH.test('/session/end')).toBe(true);
  });
});

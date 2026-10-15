import { MAX_URIS, validateClientUris } from '../src/oidc/client-validation.js';

const prod = { isProd: true, env: 'production', allowEmpty: false };
const mirror = { isProd: true, env: 'mirror', allowEmpty: false };
const dev = { isProd: false, env: 'development', allowEmpty: false };

describe('validateClientUris', () => {
  it('accepts exact https addresses, trims and de-duplicates', () => {
    const r = validateClientUris([' https://portal.examplecorp.com/dms/auth/callback ', 'https://portal.examplecorp.com/dms/auth/callback'], prod);
    expect(r).toEqual({ ok: true, value: ['https://portal.examplecorp.com/dms/auth/callback'] });
  });

  it('refuses plain http outside local development', () => {
    expect(validateClientUris(['http://portal.examplecorp.com/cb'], prod).ok).toBe(false);
    expect(validateClientUris(['http://intranet.example/cb'], dev).ok).toBe(false);
  });

  it('accepts http only on a loopback host, and only where loopback is expected', () => {
    expect(validateClientUris(['http://localhost:7101/auth/callback'], dev).ok).toBe(true);
    expect(validateClientUris(['http://127.0.0.1:7101/auth/callback'], dev).ok).toBe(true);
    expect(validateClientUris(['http://localhost:9101/auth/callback'], mirror).ok).toBe(true);
    const inProd = validateClientUris(['http://localhost:7101/auth/callback'], prod);
    expect(inProd.ok).toBe(false);
    if (!inProd.ok) expect(inProd.error).toMatch(/production/);
    expect(validateClientUris(['https://localhost/cb'], prod).ok).toBe(false);
  });

  it('refuses wildcards, fragments, credentials and things that are not addresses', () => {
    for (const bad of ['https://*.examplecorp.com/cb', 'https://x.example/cb#frag', 'https://user:pw@x.example/cb', 'x.example/cb', 'javascript:alert(1)', 'ftp://x.example/cb', '//x.example/cb', 'https://']) {
      expect({ bad, ok: validateClientUris([bad], dev).ok }).toEqual({ bad, ok: false });
    }
  });

  it('a redirect list cannot be empty, a sign-out list may be', () => {
    expect(validateClientUris([], prod).ok).toBe(false);
    expect(validateClientUris(['  '], prod).ok).toBe(false);
    expect(validateClientUris([], { ...prod, allowEmpty: true })).toEqual({ ok: true, value: [] });
  });

  it('caps the count and the length', () => {
    const many = Array.from({ length: MAX_URIS + 1 }, (_, i) => `https://x.example/cb${i}`);
    expect(validateClientUris(many, prod).ok).toBe(false);
    expect(validateClientUris([`https://x.example/${'a'.repeat(2001)}`], prod).ok).toBe(false);
  });

  it('rejects non-lists', () => {
    expect(validateClientUris('https://x.example/cb', prod).ok).toBe(false);
    expect(validateClientUris([1, 2], prod).ok).toBe(false);
    expect(validateClientUris(null, prod).ok).toBe(false);
  });

  it('names the address that is wrong', () => {
    const r = validateClientUris(['https://ok.example/cb', 'https://x.example/cb#frag'], prod);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain('https://x.example/cb#frag');
  });
});

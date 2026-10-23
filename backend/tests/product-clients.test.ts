import { parseProductClients, parseProductTiles } from '../src/oidc/product-clients.js';

const client = (over: Record<string, unknown> = {}) => ({
  client_id: 'shop',
  client_secret: 'a-secret-of-enough-length',
  redirect_uris: ['https://shop.example.com/auth/callback'],
  post_logout_redirect_uris: ['https://shop.example.com/'],
  name: 'Shop',
  ...over,
});

describe('PRODUCT_CLIENTS_JSON: extra applications that sign in through this IdP', () => {
  it('unset, empty or blank registers nothing', () => {
    expect(parseProductClients(undefined)).toEqual([]);
    expect(parseProductClients('')).toEqual([]);
    expect(parseProductClients('  ')).toEqual([]);
    expect(parseProductClients('[]')).toEqual([]);
  });

  it('a valid entry becomes a client with the standard scope and nothing else added', () => {
    const [c] = parseProductClients(JSON.stringify([client()]));
    expect(c).toEqual({
      client_id: 'shop',
      client_secret: 'a-secret-of-enough-length',
      scope: 'openid profile email',
      redirect_uris: ['https://shop.example.com/auth/callback'],
      post_logout_redirect_uris: ['https://shop.example.com/'],
      name: 'Shop',
    });
  });

  it('an optional backchannel_logout_uri is kept, and must be an http(s) address', () => {
    const [c] = parseProductClients(JSON.stringify([client({ backchannel_logout_uri: 'http://127.0.0.1:16101/api/v1/auth/backchannel-logout' })]));
    expect(c.backchannel_logout_uri).toBe('http://127.0.0.1:16101/api/v1/auth/backchannel-logout');
    expect(parseProductClients(JSON.stringify([client()]))[0]).not.toHaveProperty('backchannel_logout_uri');
    for (const bad of ['', 'ftp://x/y', 'javascript:alert(1)', 5]) {
      expect(() => parseProductClients(JSON.stringify([client({ backchannel_logout_uri: bad })]))).toThrow(/backchannel_logout_uri must be an http\(s\) address/);
    }
  });

  it.each([
    ['not JSON', 'nope', /not valid JSON/],
    ['not a list', '{"client_id":"shop"}', /must be a JSON list/],
    ['an entry that is not an object', '[1]', /client_id must be/],
    ['a bad client id', JSON.stringify([client({ client_id: 'Shop Now' })]), /client_id must be/],
    ['a built-in id', JSON.stringify([client({ client_id: 'gms' })]), /reserved/],
    ['the portal id', JSON.stringify([client({ client_id: 'portal' })]), /reserved/],
    ['a secret that is too short', JSON.stringify([client({ client_secret: 'short' })]), /client_secret is required/],
    ['no secret', JSON.stringify([client({ client_secret: undefined })]), /client_secret is required/],
    ['no name', JSON.stringify([client({ name: '' })]), /name is required/],
    ['no redirect address', JSON.stringify([client({ redirect_uris: [] })]), /redirect_uris must be a non-empty list/],
    ['a redirect list holding a non-address', JSON.stringify([client({ redirect_uris: [3] })]), /redirect_uris must be a non-empty list/],
    ['no logout list', JSON.stringify([client({ post_logout_redirect_uris: undefined })]), /post_logout_redirect_uris must be a list/],
    ['the same client twice', JSON.stringify([client(), client()]), /listed twice/],
  ])('refuses %s with a clear message (a startup error, never a silent skip)', (_label, raw, message) => {
    expect(() => parseProductClients(raw)).toThrow(message);
  });
});

describe('PRODUCT_APPS_JSON: portal tiles for those applications', () => {
  const tile = (over: Record<string, unknown> = {}) => ({ rp: 'shop', label: 'Shop', name: 'Shop - orders', url: 'https://shop.example.com/', ...over });

  it('unset or empty means no tiles; a valid entry is kept as given', () => {
    expect(parseProductTiles(undefined)).toEqual([]);
    expect(parseProductTiles('[]')).toEqual([]);
    expect(parseProductTiles(JSON.stringify([tile()]))).toEqual([tile()]);
  });

  it.each([
    ['not JSON', '{', /not valid JSON/],
    ['a reserved rp', JSON.stringify([tile({ rp: 'edams' })]), /reserved/],
    ['the admin tile rp', JSON.stringify([tile({ rp: 'idp-admin' })]), /reserved/],
    ['a bad rp', JSON.stringify([tile({ rp: 'Shop!' })]), /rp must be/],
    ['no label', JSON.stringify([tile({ label: '' })]), /label and name are required/],
    ['an address that is not http(s)', JSON.stringify([tile({ url: 'javascript:alert(1)' })]), /url must be an http\(s\) address/],
    ['the same rp twice', JSON.stringify([tile(), tile()]), /listed twice/],
  ])('refuses %s', (_label, raw, message) => {
    expect(() => parseProductTiles(raw)).toThrow(message);
  });
});

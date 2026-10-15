import { edgeClientIp } from '../src/http/client-ip.js';

const run = (peer: string, header?: string, ip = '127.0.0.1') => {
  const req: { socket: { remoteAddress: string }; headers: Record<string, unknown>; ip?: string } = { socket: { remoteAddress: peer }, headers: header === undefined ? {} : { 'x-kg-client-ip': header } };
  Object.defineProperty(req, 'ip', { value: ip, configurable: true, writable: true });
  let called = false;
  edgeClientIp(req, undefined, () => { called = true; });
  return { ip: req.ip, called };
};

describe('edgeClientIp', () => {
  it('uses the edge header when the request arrived from the local proxy chain', () => {
    expect(run('127.0.0.1', '203.0.113.9')).toEqual({ ip: '203.0.113.9', called: true });
    expect(run('::ffff:127.0.0.1', '198.51.100.4')).toEqual({ ip: '198.51.100.4', called: true });
  });
  it('ignores the header from any non-loopback peer (a direct caller cannot choose its address)', () => {
    expect(run('10.0.0.5', '203.0.113.9').ip).toBe('127.0.0.1');
  });
  it('ignores a header that is not an address', () => {
    expect(run('127.0.0.1', 'not-an-ip; DROP TABLE').ip).toBe('127.0.0.1');
    expect(run('127.0.0.1', '').ip).toBe('127.0.0.1');
  });
  it('keeps req.ip when the header is absent and normalises ::ffff: forms', () => {
    expect(run('127.0.0.1').ip).toBe('127.0.0.1');
    expect(run('127.0.0.1', '::ffff:203.0.113.9').ip).toBe('203.0.113.9');
  });
});

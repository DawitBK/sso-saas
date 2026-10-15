import http from 'node:http';
import type { AddressInfo } from 'node:net';
import express from 'express';
import { clientIpOf, normalizeClientIp } from '../src/http/client-ip.js';

describe('normalizeClientIp', () => {
  it('maps every spelling of one IPv4 client to the same string', () => {
    expect(normalizeClientIp('203.0.113.7')).toBe('203.0.113.7');
    expect(normalizeClientIp('::ffff:203.0.113.7')).toBe('203.0.113.7');
    expect(normalizeClientIp('::FFFF:203.0.113.7')).toBe('203.0.113.7');
    expect(normalizeClientIp('203.0.113.7:51234')).toBe('203.0.113.7');
    expect(normalizeClientIp('  203.0.113.7 ')).toBe('203.0.113.7');
  });

  it('keeps IPv6 clients intact and strips brackets and ports', () => {
    expect(normalizeClientIp('2001:db8::1')).toBe('2001:db8::1');
    expect(normalizeClientIp('[2001:db8::1]:51234')).toBe('2001:db8::1');
    expect(normalizeClientIp('[::1]')).toBe('::1');
    expect(normalizeClientIp('::1')).toBe('::1');
  });

  it('returns an empty string, never a made-up value, when there is no address', () => {
    expect(normalizeClientIp(undefined)).toBe('');
    expect(normalizeClientIp(null)).toBe('');
    expect(normalizeClientIp('   ')).toBe('');
    expect(clientIpOf({})).toBe('');
  });

  it('bounds the length of whatever a proxy sent', () => {
    expect(normalizeClientIp('x'.repeat(500)).length).toBe(64);
  });
});

describe('client address behind one trusted proxy (what Apache in front of SSO is)', () => {
  const ipSeenBy = async (trustHops: number, xff?: string): Promise<string> => {
    const app = express();
    app.set('trust proxy', trustHops);
    app.get('/ip', (req, res) => { res.json({ ip: clientIpOf(req) }); });
    const server = http.createServer(app);
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const { port } = server.address() as AddressInfo;
    try {
      const r = await fetch(`http://127.0.0.1:${port}/ip`, { headers: xff ? { 'x-forwarded-for': xff } : {} });
      return (await r.json()).ip;
    } finally {
      server.close();
    }
  };

  it('takes the address the proxy appended', async () => {
    expect(await ipSeenBy(1, '203.0.113.7')).toBe('203.0.113.7');
  });

  it('is not fooled by a spoofed prefix supplied by the client', async () => {
    expect(await ipSeenBy(1, '10.9.9.9, 203.0.113.7')).toBe('203.0.113.7');
  });

  it('reports loopback honestly when nothing was forwarded (a developer hitting the port directly)', async () => {
    expect(await ipSeenBy(1)).toBe('127.0.0.1');
  });

  it('with no trusted proxy, ignores the header entirely', async () => {
    expect(await ipSeenBy(0, '203.0.113.7')).toBe('127.0.0.1');
  });
});

// A rate limiter whose store has failed (Redis down) must let requests through, not answer 500 (infrastructure/rateLimiter.ts).
import express from 'express';
import type { AddressInfo } from 'node:net';
import type { Store } from 'express-rate-limit';
import { createLimiter } from '../src/infrastructure/rateLimiter.js';

const brokenStore: Store = {
  async increment() { throw new Error('redis is down'); },
  async decrement() { throw new Error('redis is down'); },
  async resetKey() { throw new Error('redis is down'); },
};

async function serve(limiter: express.RequestHandler) {
  const app = express();
  app.use(limiter);
  app.get('/x', (_req, res) => { res.json({ ok: true }); });
  const server = await new Promise<import('node:http').Server>((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const { port } = server.address() as AddressInfo;
  return { url: `http://127.0.0.1:${port}/x`, close: () => new Promise<void>((r) => server.close(() => r())) };
}

describe('createLimiter', () => {
  it('lets the request through when the store throws', async () => {
    const s = await serve(createLimiter('t-broken', { windowMs: 60_000, limit: 1, store: brokenStore }));
    try {
      const a = await fetch(s.url);
      const b = await fetch(s.url);
      expect(a.status).toBe(200);
      expect(b.status).toBe(200);
    } finally {
      await s.close();
    }
  });

  it('still limits normally with a healthy (in-memory) store', async () => {
    const s = await serve(createLimiter('t-ok', { windowMs: 60_000, limit: 2 }));
    try {
      const statuses = [await fetch(s.url), await fetch(s.url), await fetch(s.url)].map((r) => r.status);
      expect(statuses).toEqual([200, 200, 429]);
    } finally {
      await s.close();
    }
  });
});

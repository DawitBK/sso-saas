import crypto from 'node:crypto';
import { expect, type Page } from '@playwright/test';

/**
 * Shared by the newer specs. The account is the QA administrator `npm run db:seed:qa-admin` creates on the dev database
 * (an IdP administrator, no two-factor, not the platform administrator). Override with SSO_E2E_EMAIL / SSO_E2E_PASSWORD.
 */
export const ADMIN_EMAIL = process.env.SSO_E2E_EMAIL ?? 'qa.ssoadmin@qa.local';
export const ADMIN_PASSWORD = process.env.SSO_E2E_PASSWORD ?? 'Pass1234!';

/**
 * Sign in through the real OIDC flow and land on the portal. /portal/login bounces through the provider to /interaction/:uid, and
 * the provider can supersede an interaction mid-flight, so "still on a sign-in form" is retried rather than treated as failure.
 */
export async function login(page: Page, email = ADMIN_EMAIL, password = ADMIN_PASSWORD): Promise<void> {
  const emailField = page.locator('input[name="email"]');
  const onPortal = () => /\/portal(\/|$|\?)/.test(page.url());
  for (let attempt = 1; attempt <= 3 && !onPortal(); attempt += 1) {
    await page.goto('/portal/login');
    await Promise.race([
      emailField.waitFor({ state: 'visible', timeout: 30_000 }).catch(() => null),
      page.waitForURL(/\/portal(\/|$|\?)/, { timeout: 30_000 }).catch(() => null),
    ]);
    if (onPortal()) break;
    if (await emailField.isVisible().catch(() => false)) {
      // Typed before React takes over, a controlled input is reset: wait for the form to say it is live.
      await page.locator('form[data-hydrated="true"]').waitFor({ timeout: 30_000 }).catch(() => null);
      await emailField.fill(email);
      await page.locator('input[name="password"]').fill(password);
      await page.locator('button[type="submit"]').click();
      await page.waitForURL(/\/portal(\/|$|\?)/, { timeout: 30_000 }).catch(() => null);
    }
  }
  expect(onPortal(), `login should land on /portal, got ${page.url()}`).toBeTruthy();
  const session = await page.request.get('/api/v1/auth/session');
  const body = await session.json().catch(() => ({}));
  expect(body?.data?.user?.email, 'login should establish a real session').toBe(email);
}

/** The CSRF token the console's JSON mutations must echo (issued by the settings GET, which any admin page can call). */
export async function adminCsrf(page: Page): Promise<string> {
  const res = await page.request.get('/api/v1/admin/settings');
  const json = await res.json();
  return json?.data?.csrf as string;
}

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** RFC 6238 code (SHA-1, 6 digits, 30 s) for a base32 secret. `steps` shifts the time step: +1 is the next code, still inside the server's +/-1 window. */
export function totp(secretBase32: string, steps = 0): string {
  const clean = secretBase32.replace(/[\s=]/g, '').toUpperCase();
  let bits = '';
  for (const ch of clean) bits += B32.indexOf(ch).toString(2).padStart(5, '0');
  const bytes = Buffer.from(bits.match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const counter = Math.floor(Date.now() / 30_000) + steps;
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', bytes).update(msg).digest();
  const off = h[h.length - 1]! & 0xf;
  const n = ((h[off]! & 0x7f) << 24) | (h[off + 1]! << 16) | (h[off + 2]! << 8) | h[off + 3]!;
  return String(n % 1_000_000).padStart(6, '0');
}

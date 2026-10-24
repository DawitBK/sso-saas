import { test, expect } from '@playwright/test';
import { adminCsrf, login } from './helpers';

/**
 * The platform administrator's side of the console, in a real browser.
 *
 * The dev database cannot create a platform administrator on its own: the database refuses it without the vault, and the vault and account
 * passwords are only ever typed at a terminal (backend/scripts/seed-platform-admin.ts). So these specs run only when the owner has made
 * one on the DEV database and says so:
 *
 *   cd backend && npx tsx scripts/seed-platform-admin.ts          (asks for the vault and account passwords)
 *   set SSO_E2E_PLATFORM_EMAIL=...  &&  set SSO_E2E_PLATFORM_PASSWORD=...   (the account just created; never commit them)
 *   cd frontend && npx playwright test e2e/platform-admin.spec.ts
 *
 * Without them every test here is skipped (and says why), so the suite stays green on a machine that has no such account. The rules this
 * file would exercise are also proved over HTTP, with the gate mocked, in backend/tests/{settings-api,clients-api,audit-chain-api}.test.ts.
 *
 * Every test puts back what it changed.
 */
const EMAIL = process.env.SSO_E2E_PLATFORM_EMAIL;
const PASSWORD = process.env.SSO_E2E_PLATFORM_PASSWORD;

test.describe('Platform administrator', () => {
  test.skip(!EMAIL || !PASSWORD, 'set SSO_E2E_PLATFORM_EMAIL and SSO_E2E_PLATFORM_PASSWORD for a platform administrator created on the dev database');

  test.beforeEach(async ({ page }) => {
    await login(page, EMAIL!, PASSWORD!);
  });

  test('is recognised as the platform administrator, and sees the Keys page and its controls', async ({ page }) => {
    const verify = await (await page.request.get('/api/v1/admin/audit/verify')).json();
    expect(verify.data.viewerIsPlatformAdmin).toBe(true);
    await page.goto('/admin/keys');
    await expect(page.getByRole('button', { name: /rotate signing key/i })).toBeVisible();
    await expect(page.getByRole('link', { name: /^keys$/i }).first()).toBeVisible();
  });

  test('can change and reset a platform-only setting, which an ordinary administrator cannot', async ({ page }) => {
    await page.goto('/admin/settings');
    await page.getByRole('button', { name: 'Passwords', exact: true }).click();
    const minLength = page.getByLabel('Minimum length');
    await expect(minLength).toBeEnabled();
    const before = await minLength.inputValue();
    try {
      await minLength.fill(String(Number(before) === 12 ? 13 : 12));
      await page.getByRole('button', { name: 'Save' }).first().click();
      await page.getByRole('dialog').getByRole('button', { name: 'Save change' }).click();
      await expect(page.getByText(/saved/i).first()).toBeVisible();
    } finally {
      const csrf = await adminCsrf(page);
      await page.request.delete('/api/v1/admin/settings/password.minLength', { data: { csrf } });
    }
  });

  test('sees the application controls an ordinary administrator only reads', async ({ page }) => {
    await page.goto('/admin/clients');
    await expect(page.getByRole('button', { name: 'Edit addresses' }).first()).toBeVisible();
    await expect(page.getByRole('button', { name: 'Rotate secret' }).first()).toBeVisible();
  });

  test('never appears in the Users list or the audit log by name', async ({ page }) => {
    const users = JSON.stringify(await (await page.request.get(`/api/v1/admin/users?q=${encodeURIComponent(EMAIL!)}`)).json());
    expect(users).not.toContain(EMAIL!);
    const audit = JSON.stringify(await (await page.request.get('/api/v1/admin/audit?limit=100')).json());
    expect(audit).not.toContain(EMAIL!);
  });
});

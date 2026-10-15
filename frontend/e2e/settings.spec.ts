import { test, expect, type Page } from '@playwright/test';
import { adminCsrf, login } from './helpers';

/**
 * Settings (Admin > System > Settings), in a real browser against the dev servers.
 *
 * The account is an IdP administrator, NOT the platform administrator, so this also proves the split: platform-only settings are
 * visible and read-only, and the API refuses them. The platform administrator's own edits are covered over HTTP in
 * backend/tests/settings-api.test.ts (the dev database cannot mark a platform administrator outside the vault).
 *
 * Every test puts back what it changed.
 */

const NOTICE = 'Planned maintenance tonight 22:00–23:00. Sign-in may pause briefly.';

async function openSettings(page: Page, group: string) {
  await page.goto('/admin/settings');
  await expect(page.getByRole('heading', { name: 'Settings', level: 1 })).toBeVisible();
  await page.getByRole('button', { name: group, exact: true }).click();
}

async function resetViaApi(page: Page, key: string) {
  await page.request.delete(`/api/v1/admin/settings/${key}`, { data: { csrf: await adminCsrf(page) } });
}

test.describe('Settings', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('every group is reachable, and platform-only settings are read-only for an IdP administrator', async ({ page }) => {
    await page.goto('/admin/settings');
    for (const group of ['Branding', 'Portal', 'Passwords', 'Sign-in lockout', 'Two-factor sign-in', 'Sessions and tokens', 'Data retention']) {
      await page.getByRole('button', { name: group, exact: true }).click();
      await expect(page.getByRole('heading', { name: group, level: 2 })).toBeVisible();
    }
    await page.getByRole('button', { name: 'Passwords', exact: true }).click();
    await expect(page.getByText('Platform administrator only').first()).toBeVisible();
    const minLength = page.getByLabel('Minimum length');
    await expect(minLength).toBeDisabled();
    // The platform-only rows offer no Save (the group also holds one setting an ordinary administrator may change, which does).
    const minLengthRow = page.locator('.setting-row', { has: page.getByLabel('Minimum length') });
    await expect(minLengthRow.getByRole('button', { name: 'Save' })).toHaveCount(0);
    const resetRow = page.locator('.setting-row', { hasText: 'Let people ask for a password reset' });
    await expect(resetRow.getByRole('checkbox')).toBeEnabled();
  });

  test('the API refuses a platform-only change from an IdP administrator', async ({ page }) => {
    const csrf = await adminCsrf(page);
    const res = await page.request.put('/api/v1/admin/settings/password.minLength', { data: { value: 12, csrf } });
    expect(res.status()).toBe(403);
    expect((await res.json()).error.code).toBe('ERR-PLATFORM-ADMIN-ONLY');
  });

  test('a sign-in notice saved here appears on the sign-in page for everyone, and Reset removes it', async ({ page, browser }) => {
    await openSettings(page, 'Branding');
    const notice = page.getByLabel('Sign-in notice');
    await notice.fill(NOTICE);
    await page.getByRole('status').filter({ hasText: /unsaved change/ }).waitFor();
    // The live preview shows it before it is saved.
    await expect(page.locator('.brand-preview-notice').first()).toContainText('Planned maintenance');
    await page.screenshot({ path: 'test-results/settings-branding.png', fullPage: true });

    const row = page.locator('.setting-row', { has: page.getByLabel('Sign-in notice') });
    await row.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByText('Sign-in notice saved')).toBeVisible();

    // A visitor who has never signed in sees it on the real sign-in page.
    const visitor = await browser.newContext({ ignoreHTTPSErrors: true });
    const vp = await visitor.newPage();
    await vp.goto('http://localhost:7301/portal/login');
    await expect(vp.locator('.sso-notice')).toContainText('Planned maintenance tonight', { timeout: 30_000 });
    await vp.screenshot({ path: 'test-results/signin-with-notice.png' });
    await visitor.close();

    await row.getByRole('button', { name: 'Reset to default' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Reset to default' }).click();
    await expect(page.getByText('Sign-in notice reset to the default')).toBeVisible();

    const visitor2 = await browser.newContext({ ignoreHTTPSErrors: true });
    const vp2 = await visitor2.newPage();
    await vp2.goto('http://localhost:7301/portal/login');
    await expect(vp2.getByRole('heading', { name: 'Sign in' })).toBeVisible({ timeout: 30_000 });
    await expect(vp2.locator('.sso-notice')).toHaveCount(0);
    await visitor2.close();
  });

  test('an accent colour that is too pale is refused with the reason, and nothing is saved', async ({ page }) => {
    await openSettings(page, 'Branding');
    const hex = page.getByLabel('Accent colour (light theme)', { exact: true });
    await hex.fill('#ffff99');
    const row = page.locator('.setting-row', { has: hex });
    await row.getByRole('button', { name: 'Save' }).click();
    await expect(row.getByRole('alert')).toContainText(/contrast/i);
    await expect(row.getByText('Using the default')).toBeVisible();
  });

  test('changing the product name and accent shows in the preview, and a saved accent reaches the stylesheet', async ({ page }) => {
    await openSettings(page, 'Branding');
    await page.getByLabel('Product name').fill('Acme Identity');
    await expect(page.locator('.brand-preview').first()).toContainText('Acme Identity');
    const hex = page.getByLabel('Accent colour (light theme)', { exact: true });
    await hex.fill('#1d4ed8');
    const row = page.locator('.setting-row', { has: hex });
    await row.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByText('Accent colour (light theme) saved')).toBeVisible();
    try {
      await page.reload();
      const css = await page.locator('style#branding').textContent();
      expect(css).toContain('#1d4ed8');
      await page.screenshot({ path: 'test-results/settings-accent.png', fullPage: true });
    } finally {
      await resetViaApi(page, 'branding.accentColor');
    }
  });

  test('leaving with an unsaved edit warns, and Discard clears it', async ({ page }) => {
    await openSettings(page, 'Branding');
    const tagline = page.getByLabel('Tagline');
    await tagline.fill('Something else');
    await expect(page.getByRole('status').filter({ hasText: '1 unsaved change' })).toBeVisible();
    const row = page.locator('.setting-row', { has: tagline });
    await row.getByRole('button', { name: 'Discard' }).click();
    await expect(page.getByText('unsaved change')).toHaveCount(0);
    await expect(tagline).toHaveValue('Single sign-on');
  });

  test('the Settings page is in the sidebar under System', async ({ page }) => {
    await page.goto('/admin');
    await expect(page.getByRole('link', { name: 'Settings' })).toBeVisible();
  });
});

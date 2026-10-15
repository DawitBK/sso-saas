import { test, expect } from '@playwright/test';
import { login } from './helpers';

/** Admin > System health: what an administrator sees about the service and the systems around it. */

test.describe('System health', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('shows the verdict, every check with its meaning, the connected systems and the jobs', async ({ page }) => {
    await page.goto('/admin/system');
    await expect(page.getByRole('heading', { name: 'System health', level: 1 })).toBeVisible();
    await expect(page.locator('.health-banner')).toBeVisible();
    for (const title of ['Database', 'Signing keys', 'Database schema', 'Redis', 'DMS reachability', 'GMS reachability', 'DMS role lookup', 'Authenticator secrets', 'Responsiveness']) {
      await expect(page.locator('.health-card header', { hasText: title }).first()).toBeVisible();
    }
    const database = page.locator('.health-card', { hasText: 'Where accounts, sessions and settings live' });
    await expect(database).toContainText('Working');
    await expect(page.getByRole('heading', { name: 'Connected systems' })).toBeVisible();
    await expect(page.locator('table').first()).toContainText('DMS');
    await expect(page.locator('table').first()).toContainText('GMS');
    await expect(page.getByRole('heading', { name: 'Background jobs' })).toBeVisible();
    await expect(page.getByText('Clean-up of expired records')).toBeVisible();
    await page.screenshot({ path: 'test-results/system-health.png', fullPage: true });
  });

  test('the process card reports a version, an uptime and the database connections', async ({ page }) => {
    await page.goto('/admin/system');
    const processCard = page.locator('.admin-card', { has: page.locator('dt', { hasText: 'Running for' }) });
    await expect(processCard).toContainText('Version');
    await expect(processCard).toContainText('Node.js');
    await expect(page.getByText('Waiting for a connection')).toBeVisible();
  });

  test('automatic refresh can be paused and resumed, and Check now re-reads', async ({ page }) => {
    await page.goto('/admin/system');
    const pause = page.getByRole('button', { name: /pause refresh/i });
    await pause.click();
    await expect(page.getByRole('button', { name: /resume refresh/i })).toHaveAttribute('aria-pressed', 'true');
    await page.getByRole('button', { name: /resume refresh/i }).click();
    await expect(page.getByRole('button', { name: /pause refresh/i })).toBeVisible();
    const responded = page.waitForResponse((r) => r.url().includes('/api/v1/admin/system') && r.ok());
    await page.getByRole('button', { name: /check now/i }).click();
    await responded;
  });

  test('the API is reachable by any administrator and carries no secret', async ({ page }) => {
    const res = await page.request.get('/api/v1/admin/system');
    expect(res.ok()).toBeTruthy();
    const text = JSON.stringify(await res.json());
    // `passwordChecks` (a load counter) is allowed; a field that IS a password or secret, or a connection string or key name, is not.
    expect(text).not.toMatch(/postgres:\/\/|DMS_INTERNAL_API_KEY|COOKIE_KEYS|"(password|secret|[a-z]*secret|passwordHash)"\s*:/i);
  });

  test('System health is in the sidebar', async ({ page }) => {
    await page.goto('/admin');
    await expect(page.getByRole('link', { name: 'System health' })).toBeVisible();
  });
});

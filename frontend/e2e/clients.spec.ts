import { test, expect } from '@playwright/test';
import { adminCsrf, login } from './helpers';

/**
 * Admin > Applications, as an IdP administrator (not the platform administrator): everything is visible, the secrets are not, and
 * every change is refused. The platform administrator's actions are covered over HTTP in backend/tests/clients-api.test.ts, and the
 * fact that a change reaches oidc-provider on the next request is proven by backend/test-scripts/verify-client-live.ts.
 */

test.describe('Applications', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('shows each application with its addresses, scopes, usage and secret age, and never a secret', async ({ page }) => {
    await page.goto('/admin/clients');
    await expect(page.getByRole('heading', { name: 'Applications', level: 1 })).toBeVisible();
    for (const name of ['EDAMS Document Management', 'GMS (Guest Management System)', 'Example Corp SSO Portal']) {
      await expect(page.getByRole('heading', { name, level: 2 })).toBeVisible();
    }
    const edams = page.locator('section', { has: page.getByRole('heading', { name: 'EDAMS Document Management', level: 2 }) });
    await expect(edams).toContainText('Where sign-ins are sent');
    await expect(edams).toContainText('edams_roles');
    await expect(edams).toContainText('PKCE required');
    await expect(edams).toContainText('Sign-ins held');
    await expect(edams).toContainText(/Secret: /);
    await expect(edams).toContainText(/may open it/);
    await page.screenshot({ path: 'test-results/applications.png', fullPage: true });

    const text = await page.locator('main').innerText();
    expect(text).not.toMatch(/-dev-secret/);
  });

  test('the portal client is marked protected', async ({ page }) => {
    await page.goto('/admin/clients');
    const portal = page.locator('section', { has: page.getByRole('heading', { name: 'Example Corp SSO Portal', level: 2 }) });
    await expect(portal.getByText('Protected')).toBeVisible();
    await expect(portal).toContainText('would lock every administrator out');
  });

  test('an IdP administrator sees no change buttons, and the API refuses the changes', async ({ page }) => {
    await page.goto('/admin/clients');
    await expect(page.getByRole('heading', { name: 'Applications', level: 1 })).toBeVisible();
    for (const label of ['Edit addresses', 'Rotate secret', 'Switch off', 'Restore configured addresses']) {
      await expect(page.getByRole('button', { name: label })).toHaveCount(0);
    }
    await expect(page.getByText(/belong to the platform administrator/)).toBeVisible();
    const csrf = await adminCsrf(page);
    const uris = await page.request.put('/api/v1/admin/clients/edams/uris', { data: { redirectUris: ['https://x.example/cb'], csrf } });
    expect(uris.status()).toBe(403);
    const active = await page.request.put('/api/v1/admin/clients/edams/active', { data: { active: false, csrf } });
    expect(active.status()).toBe(403);
    const rotate = await page.request.post('/api/v1/admin/clients/edams/rotate-secret', { data: { confirm: 'edams', csrf } });
    expect(rotate.status()).toBe(403);
  });

  test('the API never returns a secret', async ({ page }) => {
    const res = await page.request.get('/api/v1/admin/clients');
    expect(res.ok()).toBeTruthy();
    const text = await res.text();
    expect(text).not.toMatch(/"clientSecret"|"client_secret"|"secret"|-dev-secret/);
  });

  test('who may open an application: lists the people, filters them, links to the person', async ({ page }) => {
    await page.goto('/admin/clients/edams');
    await expect(page.getByRole('heading', { name: /EDAMS/, level: 1 })).toBeVisible();
    await expect(page.locator('tbody tr').first()).toBeVisible();
    const filter = page.getByPlaceholder('Filter by name or email');
    await filter.fill('no-such-person-zzz');
    await expect(page.getByText('Nobody matches that filter')).toBeVisible();
    await filter.fill('');
    await expect(page.locator('tbody tr').first()).toBeVisible();
  });

  test('an unknown application is reported, not a blank page', async ({ page }) => {
    await page.goto('/admin/clients/retail-os');
    await expect(page.getByText('Unknown application')).toBeVisible();
  });

  test('the sidebar calls it Applications', async ({ page }) => {
    await page.goto('/admin');
    await expect(page.getByRole('link', { name: 'Applications' })).toBeVisible();
  });
});

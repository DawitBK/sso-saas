import { test, expect, type Page } from '@playwright/test';
import { login } from './helpers';

/**
 * Admin > Users: sorting, the two-factor filter and column, page size, selecting people, bulk actions, and the CSV export.
 * The bulk specs act only on qa.bulk1@qa.local and qa.bulk2@qa.local (created by `npm run db:seed:qa-admin`) and leave them active.
 */

async function search(page: Page, text: string) {
  await page.goto('/admin/users');
  await expect(page.getByRole('heading', { name: 'Users', level: 1 })).toBeVisible();
  await page.getByPlaceholder('Search by email').fill(text);
  await page.getByRole('button', { name: 'Search', exact: true }).click();
  await expect(page).toHaveURL(/q=/);
}

const firstEmails = async (page: Page, n = 3) => page.locator('tbody tr td:nth-child(2)').evaluateAll((cells, count) => cells.slice(0, count as number).map((c) => c.textContent), n);

test.describe('Users list', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('shows two-factor and status for each person, and the application filter lists real names', async ({ page }) => {
    await page.goto('/admin/users');
    await expect(page.getByRole('columnheader', { name: 'Two-factor' })).toBeVisible();
    await expect(page.locator('tbody tr').first()).toBeVisible();
    const options = await page.getByLabel('Filter by can sign in to').locator('option').allTextContents();
    expect(options).toContain('Any application');
    expect(options.some((o) => /EDAMS|GMS/.test(o))).toBe(true);
    expect(options.every((o) => o.trim().length > 0)).toBe(true);
    await page.screenshot({ path: 'test-results/users-list.png', fullPage: true });
  });

  test('clicking a column heading sorts, and again reverses it', async ({ page }) => {
    await page.goto('/admin/users');
    await expect(page.locator('tbody tr').first()).toBeVisible();
    const asc = await firstEmails(page);
    await page.getByRole('button', { name: /^Email/ }).click();
    await expect(page).toHaveURL(/dir=desc/);
    await expect(page.getByRole('columnheader', { name: /Email/ })).toHaveAttribute('aria-sort', 'descending');
    await expect.poll(async () => (await firstEmails(page))[0]).not.toBe(asc[0]);
    const desc = await firstEmails(page);
    expect([...desc].sort().reverse()).toEqual(desc);
  });

  test('the two-factor filter narrows the list, and the page size changes how many rows show', async ({ page }) => {
    await page.goto('/admin/users');
    await page.getByLabel('Filter by two-factor').selectOption('not_enrolled');
    await expect(page).toHaveURL(/mfa=not_enrolled/);
    await expect(page.locator('tbody tr').first()).toBeVisible();
    const chips = await page.locator('tbody tr td:nth-child(5)').allTextContents();
    expect(chips.length).toBeGreaterThan(0);
    expect(chips.every((c) => /None/.test(c))).toBe(true);

    await page.getByRole('button', { name: 'Clear filters' }).click();
    await page.getByLabel('People per page').selectOption('50');
    await expect(page).toHaveURL(/pageSize=50/);
    await expect.poll(async () => page.locator('tbody tr').count()).toBeGreaterThan(20);
  });

  test('select, disable, enable and sign out several people at once', async ({ page }) => {
    await search(page, 'qa.bulk');
    await expect(page.locator('tbody tr')).toHaveCount(2);
    await page.getByLabel('Select everyone on this page').check();
    await expect(page.getByText('2 selected')).toBeVisible();

    await page.getByRole('button', { name: 'Disable', exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Disable' }).click();
    await expect(page.getByText('2 changed')).toBeVisible();
    await expect(page.locator('tbody tr .admin-badge.off')).toHaveCount(2);

    await page.getByLabel('Select everyone on this page').check();
    await page.getByRole('button', { name: 'Enable', exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Enable' }).click();
    await expect(page.getByText('2 changed').last()).toBeVisible();
    await expect(page.locator('tbody tr .admin-badge.on')).toHaveCount(2);

    await page.getByLabel('Select everyone on this page').check();
    await page.getByRole('button', { name: 'Sign out everywhere' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Sign out' }).click();
    await expect(page.getByText('2 changed').last()).toBeVisible();
    // signing out does not disable anyone
    await expect(page.locator('tbody tr .admin-badge.on')).toHaveCount(2);
  });

  test('an administrator cannot disable their own account in bulk either', async ({ page }) => {
    await search(page, 'qa.ssoadmin');
    await page.locator('tbody tr').first().getByRole('checkbox').check();
    await page.getByRole('button', { name: 'Disable', exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Disable' }).click();
    await expect(page.getByText(/cannot disable your own account/i)).toBeVisible();
    await expect(page.locator('tbody tr .admin-badge.on')).toHaveCount(1);
  });

  test('Export CSV downloads the current filter as a spreadsheet file', async ({ page }) => {
    await search(page, 'qa.bulk');
    const link = page.getByRole('link', { name: /Export CSV/ });
    await expect(link).toHaveAttribute('href', /\/api\/v1\/admin\/users\/export\?.*q=qa\.bulk/);
    const [download] = await Promise.all([page.waitForEvent('download'), link.click()]);
    expect(download.suggestedFilename()).toMatch(/^users-\d{4}-\d{2}-\d{2}\.csv$/);
    const res = await page.request.get('/api/v1/admin/users/export?q=qa.bulk');
    expect(res.status()).toBe(200);
    expect(res.headers()['content-type']).toMatch(/text\/csv/);
    const body = await res.text();
    expect(body.replace(/^\uFEFF/, '').trim().split('\r\n')).toHaveLength(3);
    expect(body).toContain('qa.bulk1@qa.local');
  });

  test('the export and bulk endpoints refuse a request with no CSRF token or no session', async ({ page, browser }) => {
    const noToken = await page.request.post('/api/v1/admin/users/bulk', { data: { ids: [], action: 'enable', csrf: 'x' } });
    expect(noToken.status()).toBe(403);
    const anon = await browser.newContext({ baseURL: 'http://localhost:7301' });
    const res = await anon.request.get('/api/v1/admin/users/export');
    expect(res.status()).toBe(401);
    await anon.close();
  });
});

import { test, expect } from '@playwright/test';
import { ADMIN_EMAIL, login } from './helpers';

/** Audit, Sign-ins and Sessions: filters, readable labels, details, exports. */

test.describe('Activity pages', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('Audit: entries read as sentences with the code beside them, and the filters narrow the trail', async ({ page }) => {
    // make sure there is something to read: the export itself is audited
    await page.request.get('/api/v1/admin/audit/export?limit=1');
    await page.goto('/admin/audit');
    await expect(page.getByRole('heading', { name: 'Audit Log', level: 1 })).toBeVisible();
    await expect(page.locator('tbody tr').first()).toBeVisible();
    await expect(page.locator('tbody').getByText('Exported the audit trail').first()).toBeVisible();
    await expect(page.locator('tbody code.admin-code').first()).toContainText('.');
    await page.screenshot({ path: 'test-results/audit-page.png', fullPage: true });

    await page.getByLabel('What was done').selectOption('audit.');
    await page.getByRole('button', { name: 'Apply' }).click();
    await expect(page).toHaveURL(/action=audit\./);
    // the table keeps showing the previous page (dimmed) until the filtered one arrives, so wait for it rather than read at once
    await expect.poll(async () => {
      const codes = await page.locator('tbody code.admin-code').allInnerTexts();
      return codes.length > 0 && codes.every((c) => c.startsWith('audit.'));
    }).toBe(true);

    await page.getByRole('button', { name: 'Clear' }).click();
    await page.getByLabel('Search').fill('zzz-no-such-thing-zzz');
    await page.getByRole('button', { name: 'Apply' }).click();
    await expect(page.getByText('Nothing matches these filters')).toBeVisible();
  });

  test('Audit: a row with detail expands to show it', async ({ page }) => {
    await page.request.get('/api/v1/admin/audit/export');
    await page.goto('/admin/audit?action=audit.');
    const toggle = page.getByRole('button', { name: /Show details of entry/ }).first();
    await expect(toggle).toBeVisible();
    await toggle.click();
    await expect(page.locator('pre.admin-code').first()).toContainText('rows');
  });

  test('Audit: Export CSV downloads the filtered trail, and taking the copy is itself recorded', async ({ page }) => {
    await page.goto('/admin/audit?action=audit.');
    const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('link', { name: /Export CSV/ }).click()]);
    expect(download.suggestedFilename()).toMatch(/^audit-\d{4}-\d{2}-\d{2}\.csv$/);
    const res = await page.request.get('/api/v1/admin/audit/export?action=audit.');
    expect(res.headers()['content-type']).toMatch(/text\/csv/);
    expect(res.headers()['x-export-truncated']).toBe('false');
    const text = (await res.text()).replace(/^﻿/, '');
    expect(text.split('\r\n')[0]).toBe('sequence,when,actor,action,target,detail,address');
    expect(text).toContain('audit.export');
  });

  test('Audit: Verify integrity still reports a verdict', async ({ page }) => {
    await page.goto('/admin/audit');
    await page.getByRole('button', { name: /verify integrity/i }).click();
    await expect(page.getByRole('status').filter({ hasText: /chain/i })).toBeVisible({ timeout: 30_000 });
  });

  test('Sign-ins: the result buttons, readable reasons, search and export', async ({ page }) => {
    await page.goto('/admin/logins');
    await expect(page.getByRole('heading', { name: 'Sign-in History', level: 1 })).toBeVisible();
    await expect(page.locator('tbody tr').first()).toBeVisible();
    await expect(page.getByRole('button', { name: 'All', exact: true })).toHaveAttribute('aria-pressed', 'true');

    await page.getByRole('button', { name: 'Failed', exact: true }).click();
    await expect(page).toHaveURL(/filter=failed/);
    await expect(page.getByRole('button', { name: 'Failed', exact: true })).toHaveAttribute('aria-pressed', 'true');
    await expect.poll(async () => {
      const results = await page.locator('tbody .admin-badge').allInnerTexts();
      return results.length > 0 && results.every((r) => r === 'Failed');
    }).toBe(true);
    await page.screenshot({ path: 'test-results/signins-page.png', fullPage: true });

    const reasonOptions = await page.getByLabel('Reason').locator('option').allInnerTexts();
    expect(reasonOptions).toContain('Any');
    expect(reasonOptions.some((o) => /Wrong email or password|Locked|two-factor/i.test(o))).toBe(true);

    await page.getByRole('button', { name: 'All', exact: true }).click();
    await page.getByLabel('Email or address').fill(ADMIN_EMAIL);
    await page.getByRole('button', { name: 'Search' }).click();
    await expect(page).toHaveURL(/q=/);
    await expect.poll(async () => {
      const emails = await page.locator('tbody tr td:nth-child(2)').allInnerTexts();
      return emails.length > 0 && emails.every((e) => e.toLowerCase().includes('qa.ssoadmin'));
    }).toBe(true);

    const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('link', { name: /Export CSV/ }).click()]);
    expect(download.suggestedFilename()).toMatch(/^sign-ins-\d{4}-\d{2}-\d{2}\.csv$/);
  });

  test('Sessions: search finds a person, and each session shows the applications it has opened', async ({ page }) => {
    await page.goto('/admin/sessions');
    await expect(page.getByRole('heading', { name: 'Active Sessions', level: 1 })).toBeVisible();
    await page.getByLabel('Search by email or name').fill('qa.ssoadmin');
    await page.getByRole('button', { name: 'Search' }).click();
    await expect(page).toHaveURL(/q=qa\.ssoadmin/);
    await expect(page.locator('tbody tr').first()).toContainText(ADMIN_EMAIL);
    await expect(page.getByRole('columnheader', { name: 'Applications' })).toBeVisible();
    await expect(page.locator('tbody tr').first().locator('td').nth(3)).toContainText(/Portal|none yet|DMS|GMS/);

    await page.getByLabel('Search by email or name').fill('no-such-person-zzz');
    await page.getByRole('button', { name: 'Search' }).click();
    await expect(page.getByText('No sessions match that search')).toBeVisible();
  });

  test('Sessions: signing a person out asks first and says what it will do', async ({ page }) => {
    await page.goto('/admin/sessions?q=qa.ssoadmin');
    await page.getByRole('button', { name: 'Sign out everywhere' }).first().click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('whole account');
    await expect(dialog).toContainText('every device');
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toHaveCount(0);
  });
});

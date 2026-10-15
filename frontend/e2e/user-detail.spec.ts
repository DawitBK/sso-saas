import { test, expect } from '@playwright/test';
import { login } from './helpers';

/** The person's own page: security facts, recent sign-ins, readable history, and confirmations before anything disruptive. */

test.describe('User detail', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    const list = await (await page.request.get('/api/v1/admin/users?q=qa.bulk1@qa.local')).json();
    const id = list.data.users[0]?.id as string;
    expect(id, 'qa.bulk1 should exist (npm run db:seed:qa-admin)').toBeTruthy();
    await page.goto(`/admin/users/${id}`);
    await expect(page.getByRole('heading', { name: 'qa.bulk1@qa.local', level: 1 })).toBeVisible();
  });

  test('shows when they last signed in, their recent attempts and the change history in words', async ({ page }) => {
    await expect(page.getByText(/Last signed in:/)).toBeVisible();
    await expect(page.getByRole('heading', { name: /Recent sign-in attempts/ })).toBeVisible();
    await expect(page.getByRole('link', { name: /see all/ })).toHaveAttribute('href', /\/admin\/logins\?q=qa\.bulk1/);
    await expect(page.getByRole('heading', { name: /Change history/ })).toBeVisible();
    await page.screenshot({ path: 'test-results/user-detail.png', fullPage: true });
  });

  test('the temporary password form states the real minimum, can generate one, and asks before resetting', async ({ page }) => {
    const field = page.getByLabel('Temporary password');
    await expect(field).toHaveAttribute('placeholder', /At least \d+ characters/);
    const reset = page.getByRole('button', { name: /Reset password/ });
    await expect(reset).toBeDisabled();
    await page.getByRole('button', { name: 'Generate' }).click();
    const value = await field.inputValue();
    expect(value.length).toBeGreaterThanOrEqual(14);
    expect(value).toMatch(/^[A-Za-z2-9]+$/);
    await expect(reset).toBeEnabled();
    await reset.click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('signed out');
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toHaveCount(0);
    await expect(field).toHaveValue(value);
  });

  test('a person without two-factor has nothing to remove', async ({ page }) => {
    await expect(page.getByText(/Two-factor auth:/)).toContainText('off');
    await expect(page.getByRole('button', { name: /Remove two-factor/ })).toHaveCount(0);
  });
});

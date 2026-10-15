import { test, expect } from '@playwright/test';
import { login } from './helpers';

/**
 * "Forgot your password?" with no mail server: a person asks on a public page, an administrator sees the request on Admin > Users and
 * deals with it. The reset itself (which closes the request) is covered over HTTP in backend/tests/reset-requests.test.ts.
 */
test.describe('Password reset requests', () => {
  test('the public page gives the same answer for a real and an unknown address, and the administrator sees only the real one', async ({ page }) => {
    const note = `e2e note ${Date.now()}`;

    // 1. as nobody
    await page.goto('/forgot-password');
    await expect(page.getByRole('heading', { name: 'Forgot your password?' })).toBeVisible();
    await expect(page.locator('form[data-hydrated="true"]')).toBeVisible();
    await page.getByLabel('Email').fill('qa.bulk1@qa.local');
    await page.getByLabel(/How can we recognise you/).fill(note);
    await page.getByRole('button', { name: 'Ask for a reset' }).click();
    const realAnswer = await page.getByRole('status').innerText();
    expect(realAnswer).toMatch(/administrators have been told/);

    await page.goto('/forgot-password');
    await expect(page.locator('form[data-hydrated="true"]')).toBeVisible();
    await page.getByLabel('Email').fill('nobody-here@qa.local');
    await page.getByRole('button', { name: 'Ask for a reset' }).click();
    expect(await page.getByRole('status').innerText()).toBe(realAnswer);

    // 2. as an administrator
    await login(page);
    await page.goto('/admin/users');
    const card = page.getByTestId('reset-requests');
    await expect(card).toBeVisible();
    await expect(card).toContainText('qa.bulk1@qa.local');
    await expect(card).toContainText(note);
    await expect(card).not.toContainText('nobody-here');
    await expect(card.getByRole('link', { name: /Reset password/ }).first()).toHaveAttribute('href', /\/admin\/users\/[0-9a-f-]{36}/);
    await page.screenshot({ path: 'test-results/reset-requests.png', fullPage: true });

    // 3. dismissing asks first, then the card goes
    const row = card.locator('tbody tr', { hasText: 'qa.bulk1@qa.local' });
    await row.getByRole('button', { name: 'Dismiss' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('Their password is not changed');
    await dialog.getByRole('button', { name: 'Dismiss request' }).click();
    await expect(page.getByText('Request dismissed.')).toBeVisible();
    await expect(page.getByTestId('reset-requests')).toHaveCount(0);
  });

  test('the sign-in page is told to offer the link (the setting is on)', async ({ page }) => {
    const res = await page.request.get('/api/v1/public/branding');
    expect((await res.json()).data.passwordResetRequests).toBe(true);
  });
});

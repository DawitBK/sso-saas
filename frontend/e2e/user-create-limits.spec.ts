import { test, expect } from '@playwright/test';
import { login } from './helpers';

/**
 * The create-user form against the server's own rules: its inputs stop at the numbers the API publishes (there is no copy of them in the page),
 * and a refusal from the server reaches the screen in words. Nothing is created: every submit here is one the server must refuse.
 */
test.describe('Create user: the form and the server say the same thing', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await page.goto('/admin/users/new');
    await expect(page.getByRole('heading', { name: 'Register a new user' })).toBeVisible();
  });

  test('inputs stop at the published limits, and the password box states the live minimum', async ({ page }) => {
    const catalog = await (await page.request.get('/api/v1/admin/role-catalog')).json();
    const { email, name, passwordMinLength, passwordMaxLength } = catalog.data.limits as { email: number; name: number; passwordMinLength: number; passwordMaxLength: number };
    await expect(page.locator('#email')).toHaveAttribute('maxlength', String(email));
    await expect(page.locator('#given_name')).toHaveAttribute('maxlength', String(name));
    await expect(page.locator('#family_name')).toHaveAttribute('maxlength', String(name));
    await expect(page.locator('#password')).toHaveAttribute('minlength', String(passwordMinLength));
    await expect(page.locator('#password')).toHaveAttribute('maxlength', String(passwordMaxLength));
    await expect(page.locator('#password')).toHaveAttribute('placeholder', `At least ${passwordMinLength} characters`);
    // Typing past the limit is not possible: the box keeps the first `name` characters.
    await page.locator('#given_name').fill('n'.repeat(name + 20));
    expect(await page.locator('#given_name').inputValue()).toHaveLength(name);
  });

  test('an address with no dot in its domain passes the browser but the server refuses it, in words, and nothing is created', async ({ page }) => {
    await page.locator('#email').fill('qa.nodot@localhost');
    await page.locator('#password').fill('Temporary#12345-Strong');
    await page.getByRole('button', { name: /create user/i }).click();
    await expect(page.getByText('Enter a valid email address, such as person@examplecorp.com.')).toBeVisible();
    const found = await (await page.request.get('/api/v1/admin/users?q=qa.nodot')).json();
    expect(found.data.users).toHaveLength(0);
  });
});

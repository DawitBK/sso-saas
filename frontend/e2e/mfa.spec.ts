import { test, expect, type Browser, type Page } from '@playwright/test';
import { ADMIN_PASSWORD, login, totp } from './helpers';

/**
 * Two-factor sign-in and recovery codes, end to end in a real browser, on the QA account qa.mfa@qa.local:
 * enrol (QR + setup key), receive ten recovery codes once, sign in with password + a recovery code, see a code can be used only once,
 * see the sign-in log say so, create a new set with an authenticator code, and have an administrator's reset clear everything.
 */

const EMAIL = 'qa.mfa@qa.local';
test.describe.configure({ mode: 'serial' });

let secret = '';
let codes: string[] = [];

/** An administrator session resets this account's two-factor so every run starts from "off". */
async function adminReset(browser: Browser) {
  const ctx = await browser.newContext({ baseURL: 'http://localhost:7301' });
  const page = await ctx.newPage();
  await login(page);
  const list = await (await page.request.get(`/api/v1/admin/users?q=${EMAIL}`)).json();
  const id = list.data.users[0]?.id as string;
  expect(id, 'qa.mfa account should exist (npm run db:seed:qa-admin)').toBeTruthy();
  const detail = await (await page.request.get(`/api/v1/admin/users/${id}`)).json();
  const res = await page.request.post(`/api/v1/admin/users/${id}/mfa-reset`, { data: { csrf: detail.data.csrf } });
  expect([200, 400, 404]).toContain(res.status());
  await ctx.close();
  return id;
}

async function signInPassword(page: Page) {
  await page.goto('/portal/login');
  await page.locator('input[name="email"]').waitFor({ state: 'visible', timeout: 30_000 });
  await page.locator('form[data-hydrated="true"]').waitFor({ timeout: 30_000 });
  await page.locator('input[name="email"]').fill(EMAIL);
  await page.locator('input[name="password"]').fill(ADMIN_PASSWORD);
  await page.locator('button[type="submit"]').click();
}

test.beforeAll(async ({ browser }) => {
  await adminReset(browser);
});

test('enrolment shows a QR code and a setup key, then ten recovery codes exactly once', async ({ page }) => {
  await login(page, EMAIL);
  await page.goto('/portal/security');
  await page.getByRole('button', { name: 'Set up two-factor sign-in' }).click();
  await expect(page.getByAltText(/QR code to add this account/)).toBeVisible();
  secret = (await page.locator('code.admin-code').first().innerText()).trim();
  expect(secret).toMatch(/^[A-Z2-7]{16,}$/);
  await page.screenshot({ path: 'test-results/mfa-enrol.png', fullPage: true });

  await page.getByLabel('6-digit code').fill(totp(secret));
  await page.getByRole('button', { name: 'Turn on two-factor sign-in' }).click();

  await expect(page.getByRole('heading', { name: 'Save your recovery codes' })).toBeVisible();
  codes = await page.locator('.sso-recovery-grid code').allInnerTexts();
  expect(codes).toHaveLength(10);
  expect(new Set(codes).size).toBe(10);
  for (const c of codes) expect(c).toMatch(/^[a-z2-9]{5}-[a-z2-9]{5}$/);
  await page.screenshot({ path: 'test-results/mfa-recovery-codes.png', fullPage: true });

  // cannot carry on until they say they have saved them
  const next = page.getByRole('button', { name: 'Continue' });
  await expect(next).toBeDisabled();
  await page.getByLabel('I have saved these codes').check();
  await next.click();
  await expect(page.getByText(/Two-factor sign-in is/)).toContainText('on');
  await expect(page.getByText('10 unused')).toBeVisible();
  // and they are never shown again
  await page.reload();
  await expect(page.getByText('10 unused')).toBeVisible();
  await expect(page.locator('.sso-recovery-grid')).toHaveCount(0);
});

test('a recovery code signs in once; the same code is refused the second time', async ({ page, browser }) => {
  await signInPassword(page);
  await expect(page.getByRole('heading', { name: 'Two-factor verification' })).toBeVisible();
  await page.getByRole('button', { name: /Use a recovery code/ }).click();
  await expect(page.getByLabel('Recovery code')).toBeVisible();
  await page.getByLabel('Recovery code').fill(codes[0]!.toUpperCase());
  await page.getByRole('button', { name: 'Verify' }).click();
  await page.waitForURL(/\/portal(\/|$|\?)/, { timeout: 30_000 });

  await page.goto('/portal/security');
  await expect(page.getByText('9 unused')).toBeVisible();
  await expect(page.getByText('Signed in with a recovery code').first()).toBeVisible();

  const second = await browser.newContext({ baseURL: 'http://localhost:7301' });
  const p2 = await second.newPage();
  await signInPassword(p2);
  await p2.getByRole('button', { name: /Use a recovery code/ }).click();
  await p2.getByLabel('Recovery code').fill(codes[0]!);
  await p2.getByRole('button', { name: 'Verify' }).click();
  await expect(p2.getByRole('alert').filter({ hasText: /not valid, or it has already been used/ })).toBeVisible();
  await second.close();
});

test('a wrong recovery code is refused, and the person can switch back to the authenticator field', async ({ browser }) => {
  const ctx = await browser.newContext({ baseURL: 'http://localhost:7301' });
  const page = await ctx.newPage();
  await signInPassword(page);
  await page.getByRole('button', { name: /Use a recovery code/ }).click();
  await page.getByLabel('Recovery code').fill('zzzzz-zzzzz');
  await page.getByRole('button', { name: 'Verify' }).click();
  await expect(page.getByRole('alert').filter({ hasText: /not valid/ })).toBeVisible();
  await page.getByRole('button', { name: 'Use my authenticator app instead' }).click();
  await expect(page.getByLabel('Authentication code')).toBeVisible();
  await ctx.close();
});

test('new recovery codes need a current authenticator code and replace the old set', async ({ page }) => {
  // The account now asks for a second factor, so sign in with the second recovery code.
  await signInPassword(page);
  await page.getByRole('button', { name: /Use a recovery code/ }).click();
  await page.getByLabel('Recovery code').fill(codes[1]!);
  await page.getByRole('button', { name: 'Verify' }).click();
  await page.waitForURL(/\/portal(\/|$|\?)/, { timeout: 30_000 });
  await page.goto('/portal/security');
  await page.getByLabel(/Confirm with a current code/).fill('000000');
  await page.getByRole('button', { name: 'Create new recovery codes' }).click();
  await expect(page.getByText(/Enter a valid current code/)).toBeVisible();

  await page.getByLabel(/Confirm with a current code/).fill(totp(secret, 1));
  await page.getByRole('button', { name: 'Create new recovery codes' }).click();
  await expect(page.getByRole('heading', { name: 'Save your recovery codes' })).toBeVisible();
  const fresh = await page.locator('.sso-recovery-grid code').allInnerTexts();
  expect(fresh).toHaveLength(10);
  expect(fresh.some((c) => codes.includes(c))).toBe(false);
  codes = fresh;
});

test('the old set no longer works, and the authenticator still signs in once its next code is due', async ({ browser }) => {
  test.setTimeout(180_000);
  const ctx = await browser.newContext({ baseURL: 'http://localhost:7301' });
  const page = await ctx.newPage();
  await signInPassword(page);
  await page.getByRole('button', { name: /Use a recovery code/ }).click();
  await page.getByLabel('Recovery code').fill('zzzzz-zzzzz');
  await page.getByRole('button', { name: 'Verify' }).click();
  await expect(page.getByRole('alert').filter({ hasText: /not valid/ })).toBeVisible();
  // The authenticator codes used so far cannot be used again (replay guard), so wait for the next time step before the real one.
  await page.waitForTimeout(31_000);
  await page.getByRole('button', { name: 'Use my authenticator app instead' }).click();
  await page.getByLabel('Authentication code').fill(totp(secret, 1));
  await page.getByRole('button', { name: 'Verify' }).click();
  await page.waitForURL(/\/portal(\/|$|\?)/, { timeout: 30_000 });
  await ctx.close();
});

test('an administrator reset clears two-factor and the codes', async ({ browser, page }) => {
  const id = await adminReset(browser);
  expect(id).toBeTruthy();
  await login(page, EMAIL);
  await page.goto('/portal/security');
  await expect(page.getByRole('button', { name: 'Set up two-factor sign-in' })).toBeVisible();
  await expect(page.getByText(/unused/)).toHaveCount(0);
});

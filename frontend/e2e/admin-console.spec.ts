import { test, expect } from '@playwright/test';
import { ADMIN_EMAIL, login } from './helpers';

/**
 * Exercises the SSO admin controls added on 2026-09-04 in a real browser.
 *
 * These were shipped with types, builds and unit tests green but never once
 * clicked, which is exactly the gap this file closes. Every assertion below
 * targets a control that did not exist before that change:
 *
 *   - "Rotate signing key" and per-key "Withdraw now" on /admin/keys, plus the
 *     "In JWKS" column that makes the publication window visible at all
 *   - "Verify integrity" on /admin/audit
 *   - the profile card (given/family name) on /admin/users/[id]
 *   - "Sign out everywhere" on /admin/sessions, renamed from "Kill"
 *
 * Two of them mutate real state — rotation writes a new signing key, and
 * withdrawal backdates one out of the published JWKS. That is deliberate:
 * asserting the button renders proves nothing about whether the endpoint
 * behind it works, and `retireSigningKey` was *unreachable by construction*
 * for its entire existence before being rewritten. So the key tests assert
 * against /.well-known/jwks.json, not against the UI's own optimism.
 */

// Signing in is shared with the other specs (e2e/helpers.ts): it waits for the sign-in form to be live before typing, which this
// file's own copy did not, so a fast page lost the typed address and the run failed at "login should land on /portal".

test.describe('SSO admin console', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('the admin shell renders with the signed-in account', async ({ page }) => {
    await page.goto('/admin');
    await expect(page.locator('.admin-header')).toBeVisible();
    await expect(page.locator('.who')).toContainText(ADMIN_EMAIL);
  });


  test('audit: Verify integrity runs the chain check and reports a verdict', async ({ page }) => {
    await page.goto('/admin/audit');

    const verify = page.getByRole('button', { name: /verify integrity/i });
    await expect(verify).toBeVisible();
    await verify.click();

    // The endpoint is GET /api/v1/admin/audit/verify — read-only, no CSRF.
    // Whatever it concludes, it must conclude something visible.
    await expect(page.locator('body')).toContainText(/verified|intact|valid|tamper|broken|mismatch/i, {
      timeout: 30_000,
    });
  });

  test('users: the profile card saves given and family name', async ({ page }) => {
    // Resolve a real user id from the API rather than clicking the first
    // /admin/users/ link on the page — that matched the "New user" link
    // (/admin/users/new), whose Register form ALSO has First name and Last
    // name fields, so the test filled the wrong form and then waited forever
    // for a Save profile button that only exists on the detail page.
    const listRes = await page.request.get('/api/v1/admin/users?limit=1');
    expect(listRes.ok(), 'admin users list should be reachable').toBeTruthy();
    const list = await listRes.json();
    const userId = (list?.data?.users ?? list?.data?.items ?? list?.data ?? [])[0]?.id;
    expect(userId, 'there should be at least one user to edit').toBeTruthy();

    await page.goto(`/admin/users/${userId}`);
    await expect(page.getByRole('heading', { name: /profile/i }).first()).toBeVisible();

    // The inputs carry no id or name — they are wrapped in a <label> whose
    // <span> is the visible text, so the accessible name is what to target.
    const given = page.getByLabel(/first name/i).first();
    const family = page.getByLabel(/last name/i).first();
    await expect(given, 'the profile card should render a given-name field').toBeVisible();

    const stamp = `E2E${Date.now().toString().slice(-6)}`;
    const originalGiven = await given.inputValue();
    const originalFamily = await family.inputValue();

    await given.fill(stamp);
    await family.fill(`${stamp}-fam`);
    await page.getByRole('button', { name: /save profile/i }).click();

    // Prove it persisted rather than just sat in React state.
    await page.reload();
    await expect(page.getByLabel(/first name/i).first()).toHaveValue(stamp, { timeout: 30_000 });

    // Put it back, so a real directory is not left with test data in it.
    await page.getByLabel(/first name/i).first().fill(originalGiven);
    await page.getByLabel(/last name/i).first().fill(originalFamily);
    await page.getByRole('button', { name: /save profile/i }).click();
    await expect(page.getByRole('button', { name: /save profile/i })).toBeDisabled({
      timeout: 30_000,
    });
  });

  test('sessions: the revoke control is named for what it does', async ({ page }) => {
    await page.goto('/admin/sessions');
    await expect(page.getByRole('heading', { name: /session/i }).first()).toBeVisible();

    // Renamed from "Kill". The old label said nothing about scope; this action
    // signs the user out of every session they hold, which is a different and
    // much larger thing than closing the row you are looking at.
    const rows = page.getByRole('button', { name: /sign out everywhere/i });
    if (await rows.count()) {
      await expect(rows.first()).toBeVisible();
    }
    await expect(page.getByRole('button', { name: /^kill$/i })).toHaveCount(0);
  });

  /**
   * LAST on purpose: this is the only destructive spec in the file.
   *
   * Rotating and withdrawing signing keys mutates provider state the whole
   * suite shares. Run earlier, it left every following spec landing on
   * /portal with a session the provider would not recognise, so
   * /api/v1/auth/session returned no user and four unrelated tests failed
   * with "login should establish a real session" -- a symptom that points
   * nowhere near key rotation. Keep it at the end of the file; workers is 1
   * and fullyParallel is false, so file order is execution order.
   */
  test('signing keys are the platform administrator alone: an ordinary IdP administrator sees no key controls', async ({ page }) => {
    // 2026-10-04 (platform admin autonomy): keys sit ABOVE the IdP administrator group. The earlier specs here
    // rotated and withdrew keys as an ordinary administrator; that is exactly what is no longer possible.
    await page.goto('/admin/keys');
    await expect(page.getByText(/visible and managed by the platform administrator only/i)).toBeVisible();
    await expect(page.getByRole('button', { name: /rotate signing key/i })).toHaveCount(0);
    await expect(page.getByRole('link', { name: /^keys$/i })).toHaveCount(0);
    // and the API agrees, so it is not merely hidden in the page
    const res = await page.request.post('/api/v1/admin/keys/generate', { data: {} });
    expect(res.status(), 'key generation must be refused to an ordinary administrator').toBeGreaterThanOrEqual(400);
  });

});

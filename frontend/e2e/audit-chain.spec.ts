import { test, expect } from '@playwright/test';
import { login } from './helpers';

/**
 * The audit chain on the Audit page and in the health check. The dev database holds ten July 2026 entries that no longer recompute; they are
 * acknowledged by `npm run db:ack:dev-audit` (backend), which is what makes "Chain intact" the expected verdict here.
 * The platform administrator's acknowledge button cannot be driven from a browser on a dev machine (that account only exists in the vault),
 * so who may acknowledge is proved over HTTP in backend/tests/audit-chain-api.test.ts.
 */
test.describe('Audit chain', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('Verify integrity shows the verdict, lists acknowledged problems with who explained them, and offers an ordinary administrator no way to acknowledge', async ({ page }) => {
    await page.goto('/admin/audit');
    await page.getByRole('button', { name: /verify integrity/i }).click();
    const status = page.getByRole('status').filter({ hasText: /chain/i });
    await expect(status).toBeVisible({ timeout: 30_000 });
    await expect(status).toContainText('Chain intact');
    await expect(status).toContainText(/acknowledged/);

    await expect(page.getByRole('heading', { name: 'Problems found in the chain' })).toBeVisible();
    const rows = page.getByTestId('chain-breaks').locator('tbody tr');
    expect(await rows.count()).toBeGreaterThanOrEqual(10);
    await expect(rows.first()).toContainText('An entry was edited');
    await expect(rows.first()).toContainText('Acknowledged');
    await expect(rows.first()).toContainText('Dev data only');
    await expect(page.getByRole('button', { name: /^Acknowledge…/ })).toHaveCount(0);
    await page.screenshot({ path: 'test-results/audit-chain.png', fullPage: true });
  });

  test('the API never sends what an acknowledgement is pinned to', async ({ page }) => {
    const res = await page.request.get('/api/v1/admin/audit/verify');
    expect(res.ok()).toBeTruthy();
    const text = await res.text();
    // (a break's message may say "entry_hash" in words; what must not travel is the pinned values themselves)
    expect(text).not.toMatch(/"pin"|"fingerprint"|"entryHash"|"previousHash"/);
    const json = JSON.parse(text);
    expect(json.data.viewerIsPlatformAdmin).toBe(false);
    expect(json.data.chain.valid).toBe(true);
  });

  test('an ordinary administrator is refused when they try to acknowledge anyway', async ({ page }) => {
    const first = await (await page.request.get('/api/v1/admin/audit/verify')).json();
    const res = await page.request.post('/api/v1/admin/audit/chain-acknowledgements', {
      data: { sequenceNumber: '5', kind: 'hash', reason: 'Trying to acknowledge without being the platform administrator.', csrf: first.data.csrf },
    });
    expect(res.status()).toBe(403);
    expect((await res.json()).error.code).toBe('ERR-PLATFORM-ADMIN-ONLY');
  });

  test('System health lists the audit log check and it is working', async ({ page }) => {
    await page.goto('/admin/system');
    const card = page.locator('.health-card', { hasText: 'Audit log integrity' });
    await expect(card).toBeVisible();
    await expect(card).toContainText(/Working/);
  });
});

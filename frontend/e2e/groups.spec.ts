import { test, expect } from '@playwright/test';
import { login } from './helpers';

/** Admin > Groups and Admin > DMS Roles: readable names, search, what a group opens, and a warning before a change that signs people out. */

test.describe('Groups and DMS roles', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('the list names each group, says what it opens, and searches by name', async ({ page }) => {
    const all = (await (await page.request.get('/api/v1/admin/groups?page=1')).json()).data;
    expect(all.groups.length).toBeGreaterThan(0);
    expect(all.groups[0]).toHaveProperty('apps');

    await page.goto('/admin/groups');
    await expect(page.getByRole('heading', { name: 'Groups', level: 1 })).toBeVisible();
    const first = all.groups[0] as { dn: string };
    const cn = /^CN=([^,]+)/i.exec(first.dn)?.[1] ?? first.dn;
    await expect(page.getByRole('table')).toContainText(cn);
    await expect(page.getByRole('table').first().locator('thead')).toContainText('Opens');

    await page.getByLabel('Search groups').fill(cn);
    await page.getByRole('button', { name: 'Search' }).click();
    await expect(page).toHaveURL((url) => url.searchParams.get('q') === cn);
    await expect(page.getByRole('table')).toContainText(cn);

    await page.getByLabel('Search groups').fill('zz-no-such-group-zz');
    await page.getByRole('button', { name: 'Search' }).click();
    await expect(page.getByText(/No group matches/)).toBeVisible();
    await page.getByRole('button', { name: 'Clear' }).click();
    await expect(page.getByRole('table')).toBeVisible();
  });

  test('the search is server-side: the API narrows by name and echoes the filter', async ({ page }) => {
    const res = await (await page.request.get('/api/v1/admin/groups?q=zz-no-such-group-zz')).json();
    expect(res.data.groups).toEqual([]);
    expect(res.data.filters.q).toBe('zz-no-such-group-zz');
    expect(res.data.pagination.total).toBe(0);
  });

  test('a change to a group with members asks first and says how many are signed out; cancelling saves nothing', async ({ page }) => {
    const groups = (await (await page.request.get('/api/v1/admin/groups?limit=200')).json()).data.groups as Array<{ dn: string; memberCount: number }>;
    const withMembers = groups.find((g) => g.memberCount > 0);
    test.skip(!withMembers, 'no group with members in this database');
    await page.goto(`/admin/groups/detail?dn=${encodeURIComponent(withMembers!.dn)}`);
    const save = page.getByRole('button', { name: /^(Save access|No changes to save)$/ }).first();
    await expect(save).toBeDisabled(); // nothing changed yet
    const box = page.locator('.admin-checks input[type="checkbox"]').first();
    await box.click();
    await expect(page.getByRole('button', { name: 'Save access' })).toBeEnabled();
    await page.getByRole('button', { name: 'Save access' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('signed out of every application');
    await expect(dialog).toContainText(withMembers!.memberCount === 1 ? 'The 1 person' : `The ${withMembers!.memberCount} people`);
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toHaveCount(0);
    // nothing was saved: reloading shows the original selection and a disabled button again
    await page.reload();
    await expect(page.getByRole('button', { name: /^(Save access|No changes to save)$/ }).first()).toBeDisabled();
    await page.screenshot({ path: 'test-results/group-detail.png', fullPage: true });
  });

  test('DMS roles: filter, counts and a way back when DMS does not answer', async ({ page }) => {
    await page.goto('/admin/dms-roles');
    await expect(page.getByRole('heading', { name: 'DMS Roles', level: 1 })).toBeVisible();
    const body = (await (await page.request.get('/api/v1/admin/dms-roles')).json()).data as { roles: Array<{ name: string }>; error: string | null };
    if (body.error || body.roles.length === 0) {
      await expect(page.getByRole('alert').or(page.getByText(/DMS has no roles/))).toBeVisible();
      return;
    }
    await expect(page.getByText(new RegExp(`${body.roles.length} of ${body.roles.length}`))).toBeVisible();
    await page.getByLabel('Filter roles').fill('zz-no-such-role-zz');
    await expect(page.getByText(/No role matches/)).toBeVisible();
    await page.getByLabel('Filter roles').fill(body.roles[0].name.slice(0, 3));
    await expect(page.getByRole('table')).toContainText(body.roles[0].name);
  });
});

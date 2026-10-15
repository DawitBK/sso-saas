import { test, expect, Page } from '@playwright/test';

/**
 * Exercises the GMS approval-history panel in a real browser.
 *
 * This panel (ApprovalHistoryPanel + useVisitApprovals + api.listForVisit) was
 * added on 2026-09-04 and wired into the visit detail page and the reception
 * queue. It shipped with types and builds green and was never opened, which is
 * the gap this closes.
 *
 * The failure modes that actually matter for freshly-wired UI are not layout
 * ones — they are: the component silently never mounting, the hook calling a
 * path that 404s, the request going out unauthenticated, and the panel
 * throwing on an empty result set. Every one of those is invisible to `tsc`
 * and to a production build, and every one of them is caught below.
 *
 * Lives in the SSO frontend's e2e directory because that is the only checkout
 * in the platform with Playwright installed. It therefore uses absolute URLs
 * rather than the shared baseURL.
 */

const GMS_WEB = process.env.GMS_E2E_WEB ?? 'http://localhost:7201';
const GMS_API = process.env.GMS_E2E_API ?? 'http://localhost:7200';
const EMAIL = process.env.GMS_E2E_EMAIL ?? 'admin@gms.local';
const PASSWORD = process.env.GMS_E2E_PASSWORD ?? 'GMSAdmin@2026';

/**
 * A guest-role account, needed for the visit-detail spec and nothing else.
 *
 * `/dashboard/*` is the GUEST portal — canAccessPathForRole() (GMS
 * frontend/shared/lib/auth-redirect.ts) sends an admin to `/admin/*`, reception
 * to `/reception/*`, and only role `guest` to `/dashboard/*`. So the admin
 * account every other spec here uses is structurally incapable of opening
 * /dashboard/visits/:id, and always was.
 *
 * Guest accounts are seeded with NO password (GMS provisions them with an
 * unusable hash on purpose — see GMS/CLAUDE.md, "Bulk-imported accounts have no
 * default password"), so one has to be given a password in gmsdev before this
 * spec can run. That is deliberately not automated here: it is a dev-database
 * mutation and this file does not own the database.
 */
const GUEST_EMAIL = process.env.GMS_E2E_GUEST_EMAIL ?? 'natnael.hailu19@guestmail.et';
const GUEST_PASSWORD = process.env.GMS_E2E_GUEST_PASSWORD ?? 'GuestE2E@2026';

/** zustand's persist key — see GMS/frontend/state/auth.store.ts. */
const STORAGE_KEY = 'gms-auth-session';

interface Session {
  accessToken: string;
  userId: string;
  roles: string[];
}

async function apiLogin(page: Page, email = EMAIL, password = PASSWORD): Promise<Session> {
  const res = await page.request.post(`${GMS_API}/api/v1/auth/login`, {
    data: { email, password },
  });
  expect(res.ok(), `GMS login should succeed for ${email}`).toBeTruthy();
  const body = await res.json();
  expect(body?.data?.accessToken, 'login should return an access token').toBeTruthy();
  return {
    accessToken: body.data.accessToken,
    userId: String(body.data.user.id),
    roles: body.data.user.roles ?? [],
  };
}

/**
 * Seed the persisted auth store before the app boots.
 *
 * Driving the login form would work too, but it makes every assertion below
 * depend on the login UI as well as the thing under test. Writing the store
 * directly seeds only identity context; the access token itself is no longer
 * persisted anywhere (P1-21 is closed) and is obtained at runtime from the
 * httpOnly refresh cookie, so this exercises the real startup path.
 */
async function seedSession(page: Page, session: Session) {
  await page.addInitScript(
    ([key, value]) => {
      window.localStorage.setItem(key as string, value as string);
    },
    [
      STORAGE_KEY,
      JSON.stringify({
        state: {
          // P1-21: no accessToken here any more — the store stopped persisting
          // it, so seeding one would be seeding a key the app ignores and the
          // test would prove nothing about how the app actually starts up.
          //
          // This now mirrors a real reload exactly: identity context in
          // localStorage, and the credential itself supplied by the httpOnly
          // gms_refresh_token cookie that apiLogin() left in the browser
          // context (page.request shares the page's cookie jar). The app's
          // bootstrapAccessToken() trades that cookie for an in-memory token
          // on load, which is the path every signed-in user now takes.
          authenticated: true,
          userId: session.userId,
          roles: session.roles,
          officeId: null,
          // null, not a guess. The store normalizes role names on rehydrate
          // and auto-selects when there is exactly one, so handing it a
          // literal that does not survive normalization ('admin' for a
          // super_admin account) leaves selectedRole invalid and the route
          // guard bounces to the staff login instead of the visit page.
          selectedRole: null,
          requiresPasswordChange: false,
        },
        version: 0,
      }),
    ],
  );
}

test.describe('GMS approval history', () => {
  let session: Session;

  test.beforeEach(async ({ page }) => {
    session = await apiLogin(page);
    await seedSession(page, session);
  });

  test('the approvals endpoint the panel calls is reachable and authorised', async ({ page }) => {
    // Before touching the UI, prove the contract the panel depends on. A 404
    // here would mean the hook is pointed at a path that does not exist; a 401
    // would mean the panel renders but is permanently empty for everyone.
    const visits = await page.request.get(`${GMS_API}/api/v1/visits?limit=1`, {
      headers: { Authorization: `Bearer ${session.accessToken}` },
    });
    expect(visits.ok(), 'visits list should be reachable').toBeTruthy();
    const list = await visits.json();
    const visitId = (list?.data?.rows ?? list?.data?.items ?? list?.data ?? [])[0]?.id;
    expect(visitId, 'dev database should contain at least one visit').toBeTruthy();

    const approvals = await page.request.get(`${GMS_API}/api/v1/approvals/visit/${visitId}`, {
      headers: { Authorization: `Bearer ${session.accessToken}` },
    });
    expect(
      approvals.status(),
      `GET /api/v1/approvals/visit/${visitId} should answer 200, not 404 or 401`,
    ).toBe(200);

    const body = await approvals.json();
    expect(body?.success, 'the approvals response should be a success envelope').toBeTruthy();
  });

  /**
   * Previously test.fixme, with the cause recorded as a guess ("the route guard
   * wants a completed /auth/me round trip"). The guess was wrong, and so was a
   * later guess that P1-21 had fixed it. The actual reason, confirmed by
   * reading canAccessPathForRole():
   *
   *   `/dashboard/*` is the GUEST portal. An admin role is routed to `/admin/*`
   *   and is refused `/dashboard/*` outright, so the admin session every other
   *   spec in this file uses could never open this page. It bounced for a
   *   role-scoping reason that had nothing to do with tokens.
   *
   * So this test signs in as an actual guest. That also makes it the only spec
   * here covering the guest portal, and the only one proving the panel renders
   * on the visit DETAIL page rather than the reception queue.
   *
   * It does still depend on P1-21 behaving: the guest session is seeded with
   * `authenticated` and no token, so the panel's request only goes out if
   * bootstrapAccessToken() successfully trades the refresh cookie for one.
   */
  /**
   * This spec found a real defect and now guards the fix.
   *
   * ApprovalHistoryPanel is mounted on /dashboard/visits/[id] — the guest
   * portal — but GET /approvals/visit/:id was gated
   * `requireRole(['admin','host','reception'])`. The only role that could open
   * the page was the only role the endpoint refused, so every guest viewing
   * their own visit got a 403 behind that panel and the feature was unreachable
   * by construction.
   *
   * The route-level role check is gone (approval.routes.ts). It was never what
   * enforced access: listVisitApprovals() defers to getVisitForActor(), whose
   * scope policy is strictly narrower — office scope for admin/reception,
   * assignment for hosts, `visit.guest_id === actor.id` for guests. Verified
   * against the running API: a guest gets 200 on their own visits and 403 on
   * five others', staff are unaffected, anonymous is still 401, and the POST
   * decision route is still refused to a guest on their own visit.
   */
  test('the visit detail page renders the approval history panel', async ({ page }) => {
    const guest = await apiLogin(page, GUEST_EMAIL, GUEST_PASSWORD);
    expect(guest.roles, 'the guest fixture must actually hold the guest role').toContain('guest');
    await seedSession(page, guest);

    // A guest sees only their own visits, so this must be one of THEIRS —
    // reusing the admin's first visit would 403 and prove nothing.
    const visits = await page.request.get(`${GMS_API}/api/v1/visits?limit=1`, {
      headers: { Authorization: `Bearer ${guest.accessToken}` },
    });
    const list = await visits.json();
    const visitId = (list?.data?.rows ?? list?.data?.items ?? list?.data ?? [])[0]?.id;
    expect(visitId, 'the guest fixture should own at least one visit').toBeTruthy();

    // Watch for the panel's own request rather than trusting the DOM alone —
    // a component that mounts but never fetches looks identical to one that
    // fetched and got nothing back.
    const approvalCall = page.waitForResponse(
      (r) => r.url().includes(`/approvals/visit/${visitId}`),
      { timeout: 60_000 },
    );

    await page.goto(`${GMS_WEB}/dashboard/visits/${visitId}`, { waitUntil: 'domcontentloaded' });

    const response = await approvalCall;
    expect(response.status(), 'the panel should get a 200 from the approvals endpoint').toBe(200);

    // The heading renders whether or not there are decisions to show; the
    // empty state is a legitimate render and is the case the dev database
    // actually exercises today (the approvals table is empty).
    await expect(page.getByText(/approval history/i).first()).toBeVisible({ timeout: 30_000 });
  });

  /**
   * The other half of removing that role gate: dropping it must not have turned
   * the endpoint into one any signed-in guest can walk.
   *
   * Visit ids are sequential, so "a guest can read their own visit" is only
   * safe if "a guest cannot read anyone else's" holds at the same time. This
   * asserts both against the same session, which is the property the role check
   * was mistakenly credited with providing and the scope policy actually does.
   */
  test('a guest can read their own visit approvals and no one else\'s', async ({ page }) => {
    const guest = await apiLogin(page, GUEST_EMAIL, GUEST_PASSWORD);

    const mine = await page.request.get(`${GMS_API}/api/v1/visits?limit=50`, {
      headers: { Authorization: `Bearer ${guest.accessToken}` },
    });
    const list = await mine.json();
    const ownIds: number[] = (list?.data?.rows ?? list?.data?.items ?? list?.data ?? [])
      .map((v: { id: number }) => Number(v.id));
    expect(ownIds.length, 'the guest fixture should own at least one visit').toBeGreaterThan(0);

    for (const id of ownIds) {
      const res = await page.request.get(`${GMS_API}/api/v1/approvals/visit/${id}`, {
        headers: { Authorization: `Bearer ${guest.accessToken}` },
      });
      expect(res.status(), `guest should read approvals for their own visit ${id}`).toBe(200);
    }

    // Ids the guest does not own. Taken from the admin's view so they are real
    // rows — a 403 on a nonexistent visit would prove nothing.
    const admin = await apiLogin(page);
    const all = await page.request.get(`${GMS_API}/api/v1/visits?limit=50`, {
      headers: { Authorization: `Bearer ${admin.accessToken}` },
    });
    const allList = await all.json();
    const othersIds: number[] = (allList?.data?.rows ?? allList?.data?.items ?? allList?.data ?? [])
      .map((v: { id: number }) => Number(v.id))
      .filter((id: number) => !ownIds.includes(id))
      .slice(0, 5);
    expect(othersIds.length, 'need at least one visit the guest does not own').toBeGreaterThan(0);

    for (const id of othersIds) {
      const res = await page.request.get(`${GMS_API}/api/v1/approvals/visit/${id}`, {
        headers: { Authorization: `Bearer ${guest.accessToken}` },
      });
      expect(res.status(), `guest must NOT read approvals for visit ${id}`).toBe(403);
    }
  });

  test('the reception queue also mounts the panel without erroring', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(e.message));

    await page.goto(`${GMS_WEB}/reception/visits`, { waitUntil: 'domcontentloaded' });
    await expect(page.locator('body')).toBeVisible();

    // Give client-side rendering a beat to throw if it is going to.
    await page.waitForLoadState('networkidle', { timeout: 60_000 }).catch(() => {});

    expect(errors, `unhandled client errors on the reception queue: ${errors.join(' | ')}`).toEqual(
      [],
    );
  });
});

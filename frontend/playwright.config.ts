import { defineConfig, devices } from '@playwright/test';

/**
 * End-to-end config for the SSO admin console.
 *
 * No `webServer` block on purpose: these specs run against the dev servers
 * already started by hand (SSO backend 7300, SSO frontend 7301, GMS backend
 * 7200, GMS frontend 7201). Letting Playwright own the lifecycle would mean
 * booting four processes and a database per run, and the SSO frontend's dev
 * server takes long enough that the first navigation would time out anyway
 * while Next compiles the route.
 *
 * Serial, single worker: every spec drives the same admin account against one
 * shared database, and two of them mutate global state — signing-key rotation
 * and session revocation are not things two parallel workers can do to each
 * other's satisfaction.
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list']],
  // Generous, because the Next dev server compiles each admin route the first
  // time it is hit and the very first spec pays for the login flow's routes as
  // well as its own. Against a built server this is wildly more than needed.
  timeout: 180_000,
  expect: { timeout: 20_000 },
  use: {
    // localhost, not 127.0.0.1. The provider's issuer and the portal's
    // redirect_uri are both built on `localhost`, and a browser treats the two
    // as different origins for cookie purposes — driving 127.0.0.1 sends the
    // OIDC flow to an origin that cannot see the session cookie it just set,
    // which fails as "logged in but no session" rather than as a redirect error.
    baseURL: 'http://localhost:7301',
    // Next dev compiles each route on first hit; the first navigation to a
    // page can take tens of seconds on a cold server.
    navigationTimeout: 60_000,
    actionTimeout: 20_000,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    ignoreHTTPSErrors: true,
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});

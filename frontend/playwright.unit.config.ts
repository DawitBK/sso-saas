import { defineConfig } from '@playwright/test';

/**
 * Unit tests for pure frontend logic. Same runner as the browser specs (no new dependency), but no browser, no server and no
 * login: these specs never use the `page` fixture, so nothing is launched. Run with `npm run test:unit`.
 */
export default defineConfig({
  testDir: './tests/unit',
  testMatch: /.*\.spec\.tsx?$/,
  fullyParallel: true,
  retries: 0,
  reporter: [['list']],
  timeout: 30_000,
});

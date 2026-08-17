// Real headless-Chromium click-through proving the end-to-end SSO UX:
//   1. DMS login page shows the SSO button
//   2. Click it → IdP login screen
//   3. Enter credentials → land in DMS dashboard (JIT-provisioned)
//   4. Open the IdP portal → already signed in (NO second password), personalized
//   5. Click the GMS tile → bridged into GMS
// Saves a screenshot at each step and asserts key on-page text.
import { chromium } from "playwright";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "screenshots",
);
mkdirSync(DIR, { recursive: true });
const shot = (page, name) =>
  page.screenshot({ path: path.join(DIR, name), fullPage: true });

const results = [];
function check(label, cond) {
  results.push({ label, ok: !!cond });
  console.log(`   [${cond ? "PASS" : "FAIL"}] ${label}`);
}

const browser = await chromium.launch({ headless: true, channel: "msedge" });
const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
const page = await ctx.newPage();
page.setDefaultTimeout(30000);

// Capture any cross-origin call to the GMS backend :7200 (would be a CORS-prone
// call that should instead go same-origin through the gateway).
const crossOriginGmsCalls = [];
page.on("request", (req) => {
  if (/localhost:7200\//.test(req.url())) crossOriginGmsCalls.push(req.url());
});

try {
  // 1) DMS login page
  console.log("1) DMS /login");
  await page.goto("http://localhost:7101/login", { waitUntil: "networkidle" });
  await page.getByText(/Sign in with Example Corp SSO/i).waitFor();
  await shot(page, "01-dms-login.png");
  check(
    'DMS login shows "Sign in with Example Corp SSO"',
    await page.getByText(/Sign in with Example Corp SSO/i).isVisible(),
  );

  // 2) Click SSO → IdP login
  console.log("2) click SSO → IdP login");
  await page.getByText(/Sign in with Example Corp SSO/i).click();
  await page.waitForURL(/localhost:7301\/interaction\//, { timeout: 30000 });
  await page.locator("#email").waitFor();
  await shot(page, "02-idp-login.png");
  check("landed on IdP login screen", page.url().includes(":7301/interaction"));

  // 3) Credentials → DMS dashboard
  console.log("3) submit credentials");
  await page.fill("#email", "admin@examplecorp.com");
  await page.fill("#password", "demo");
  await page.click("button[type=submit]");
  await page
    .waitForURL(/localhost:7101\/(dashboard|select-tenant|$)/, {
      timeout: 45000,
    })
    .catch(() => {});
  await page.waitForLoadState("networkidle").catch(() => {});
  await shot(page, "03-dms-after-login.png");
  check(
    "returned to DMS after SSO (not on IdP)",
    page.url().includes(":7101") && !page.url().includes("/login"),
  );
  console.log("   DMS url:", page.url());

  // 4) Portal — should be signed in already (NO password prompt) + personalized
  console.log("4) open IdP portal (expect no re-login)");
  await page.goto("http://localhost:7301/portal", { waitUntil: "networkidle" });
  await page.waitForLoadState("networkidle").catch(() => {});
  const onLogin = page.url().includes("/interaction"); // would mean it asked to log in again
  const bodyText = await page.locator("body").innerText();
  await shot(page, "04-portal-personalized.png");
  check(
    "portal did NOT ask for password again (SSO reused)",
    !onLogin && /Welcome/i.test(bodyText),
  );
  check(
    "portal greets the user (personalized)",
    /Administrator|admin@examplecorp/i.test(bodyText),
  );
  check("portal shows GMS tile", /GMS/i.test(bodyText));
  check("portal shows EDAMS tile", /EDAMS/i.test(bodyText));

  // 5) Click GMS tile → bridge → same-origin gateway → authenticated GMS
  console.log("5) click GMS tile → bridge → gateway → authenticated GMS");
  await Promise.all([
    page
      .waitForURL(/gms\.localtest\.me:4200/, { timeout: 45000 })
      .catch(() => {}),
    page.getByText(/GMS — Guest Management/i).click(),
  ]);
  await page.waitForLoadState("networkidle").catch(() => {});
  await page.waitForTimeout(2000);
  console.log("   landed on:", page.url());

  const seeded = await page.evaluate(() => {
    try {
      const v = JSON.parse(localStorage.getItem("gms-auth-session") || "{}");
      return !!(v.state && v.state.accessToken);
    } catch {
      return false;
    }
  });
  check("GMS session seeded on the gateway origin (localStorage)", seeded);

  const apiStatus = await page.evaluate(async () => {
    try {
      const v = JSON.parse(localStorage.getItem("gms-auth-session") || "{}");
      const r = await fetch("/api/v1/offices", {
        headers: { Authorization: "Bearer " + v.state.accessToken },
      });
      return r.status;
    } catch {
      return -1;
    }
  });
  check(
    `same-origin GMS API accepts the bridged session (${apiStatus})`,
    apiStatus === 200,
  );

  // The gateway hands off to the role-appropriate area (super_admin → /admin).
  await page
    .waitForURL(/gms\.localtest\.me:4200\/(admin|reception|host)/, {
      timeout: 15000,
    })
    .catch(() => {});
  await page.waitForLoadState("networkidle").catch(() => {});
  await page.waitForTimeout(1500);
  await shot(page, "05-gms-authenticated.png");
  const gmsBody = await page
    .locator("body")
    .innerText()
    .catch(() => "");
  check(
    "GMS landed on an authenticated staff area (not login/guest)",
    /\/(admin|reception|host)/.test(page.url()) &&
      !/Staff Login|Guest Registration/i.test(gmsBody),
  );

  // The SPA's own API calls must go same-origin through the gateway (no direct
  // :7200 cross-origin calls → no CORS failures).
  const officesStatus = await page.evaluate(async () => {
    try {
      const v = JSON.parse(localStorage.getItem("gms-auth-session") || "{}");
      const r = await fetch("/api/v1/offices", {
        headers: { Authorization: "Bearer " + v.state.accessToken },
      });
      return r.status;
    } catch {
      return -1;
    }
  });
  check(
    `admin data loads same-origin through the gateway (/offices ${officesStatus})`,
    officesStatus === 200,
  );
  check(
    `no cross-origin :7200 calls from the SPA (CORS-free) [${crossOriginGmsCalls.length}]`,
    crossOriginGmsCalls.length === 0,
  );
  console.log("   final url:", page.url());
} catch (err) {
  console.error("ERROR during flow:", err.message);
  await shot(page, "99-error.png").catch(() => {});
} finally {
  await browser.close();
}

const passed = results.filter((r) => r.ok).length;
console.log(
  `\nRESULT: ${passed}/${results.length} checks passed. Screenshots in test-scripts/screenshots/`,
);
process.exit(passed === results.length ? 0 : 1);

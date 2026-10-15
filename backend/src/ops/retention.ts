import { getNumber } from '../settings/store.js';

/** How long sign-in events (idp_login_events) are kept: the platform setting retention.loginEventDays (default 90). The hourly purge job
 *  (main.ts) deletes older rows; the console's Sign-ins page quotes this number, so both read it from here. */
export const loginEventRetentionDays = (): number => getNumber('retention.loginEventDays');

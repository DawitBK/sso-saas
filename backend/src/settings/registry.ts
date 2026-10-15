/**
 * Every platform setting the console can change, in one place: what it is, how it is validated, who may change it, and what its
 * default is. The admin console renders itself from this list (GET /api/v1/admin/settings), so a setting added here appears there
 * with its help text and limits, and nothing in the UI can offer a value the backend would refuse.
 *
 * DEFAULTS come from the environment (IDP_CONFIG) or are built in, and a stored override wins. Nothing is stored until somebody
 * changes it, so an installation behaves exactly as before until an administrator edits something (settings/store.ts).
 *
 * WHO MAY CHANGE IT. `admin` = any console administrator. `platform` = the platform administrator only: anything that can lock
 * people out, weaken sign-in, or change how long a stolen token lives sits above the IdP administrator group, the same line the
 * signing keys already draw (auth/platform-admin.ts).
 *
 * This module is pure apart from reading IDP_CONFIG for defaults, so validation is unit-tested without a database.
 */
import { IDP_CONFIG } from '../config.js';

export type SettingValue = number | boolean | string | string[];
export type SettingType = 'int' | 'bool' | 'text' | 'color' | 'apps';
export type SettingGroupId = 'branding' | 'portal' | 'passwords' | 'lockout' | 'mfa' | 'sessions' | 'retention';
export type EditableBy = 'admin' | 'platform';

export interface SettingDef {
  key: string;
  group: SettingGroupId;
  label: string;
  help: string;
  type: SettingType;
  /** int */
  min?: number;
  max?: number;
  unit?: string;
  /** text */
  maxLength?: number;
  multiline?: boolean;
  editableBy: EditableBy;
  /** Shown beside the control so nobody expects an effect that is not there. */
  applies: 'immediately' | 'new-sign-ins' | 'new-tokens';
  defaultValue: () => SettingValue;
  /** Light/dark accent colours must stay readable on the page they are drawn on. */
  contrastAgainst?: string[];
}

export interface SettingGroup {
  id: SettingGroupId;
  title: string;
  description: string;
}

export const SETTING_GROUPS: SettingGroup[] = [
  { id: 'branding', title: 'Branding', description: 'What people see on the sign-in page, the portal and the console header.' },
  { id: 'portal', title: 'Portal', description: 'The application launcher people land on after signing in.' },
  { id: 'passwords', title: 'Passwords', description: 'What a new password has to satisfy, for local accounts (Active Directory accounts follow the directory).' },
  { id: 'lockout', title: 'Sign-in lockout', description: 'Whether repeated wrong passwords lock an account for a while.' },
  { id: 'mfa', title: 'Two-factor sign-in', description: 'Who must use an authenticator app.' },
  { id: 'sessions', title: 'Sessions and tokens', description: 'How long a sign-in and the tokens issued from it stay valid.' },
  { id: 'retention', title: 'Data retention', description: 'How long operational records are kept.' },
];

const HEX = /^#[0-9a-f]{6}$/i;

export const SETTINGS: SettingDef[] = [
  // ── Branding ────────────────────────────────────────────────────────────────────────────────────────────────────
  { key: 'branding.productName', group: 'branding', label: 'Product name', help: 'Shown as the title of the sign-in page and the portal.', type: 'text', maxLength: 60, editableBy: 'admin', applies: 'immediately', defaultValue: () => 'Example Corp Identity' },
  { key: 'branding.tagline', group: 'branding', label: 'Tagline', help: 'The line under the product name.', type: 'text', maxLength: 80, editableBy: 'admin', applies: 'immediately', defaultValue: () => 'Single sign-on' },
  { key: 'branding.accentColor', group: 'branding', label: 'Accent colour (light theme)', help: 'Buttons, links and highlights in the light theme. Must stay readable on a white page.', type: 'color', editableBy: 'admin', applies: 'immediately', defaultValue: () => '#166534', contrastAgainst: ['#ffffff'] },
  { key: 'branding.accentColorDark', group: 'branding', label: 'Accent colour (dark themes)', help: 'The same, for the black and blue themes. Must stay readable on a dark page.', type: 'color', editableBy: 'admin', applies: 'immediately', defaultValue: () => '#22c55e', contrastAgainst: ['#0b1220', '#050d1e'] },
  { key: 'branding.loginNotice', group: 'branding', label: 'Sign-in notice', help: 'A message shown above the sign-in form (planned maintenance, a security reminder). Leave empty for none.', type: 'text', maxLength: 300, multiline: true, editableBy: 'admin', applies: 'immediately', defaultValue: () => '' },
  { key: 'branding.supportContact', group: 'branding', label: 'Help contact', help: 'Who people should contact when they cannot sign in, for example "IT service desk, ext. 120".', type: 'text', maxLength: 120, editableBy: 'admin', applies: 'immediately', defaultValue: () => '' },
  { key: 'branding.footerText', group: 'branding', label: 'Footer text', help: 'The line at the bottom of the sign-in page and portal.', type: 'text', maxLength: 120, editableBy: 'admin', applies: 'immediately', defaultValue: () => '© Example Corp · Secured by OpenID Connect' },

  // ── Portal ──────────────────────────────────────────────────────────────────────────────────────────────────────
  { key: 'portal.welcomeMessage', group: 'portal', label: 'Portal message', help: 'A short message shown above the application list. Leave empty for none.', type: 'text', maxLength: 200, multiline: true, editableBy: 'admin', applies: 'immediately', defaultValue: () => '' },
  { key: 'portal.hiddenApps', group: 'portal', label: 'Hidden applications', help: 'Applications taken off the launcher for everyone. Access rules are untouched; this only hides the tile (use it during maintenance).', type: 'apps', editableBy: 'admin', applies: 'immediately', defaultValue: () => [] },

  // ── Passwords ───────────────────────────────────────────────────────────────────────────────────────────────────
  { key: 'password.minLength', group: 'passwords', label: 'Minimum length', help: 'Characters a new password must have at least. Longer is better than complicated (NIST SP 800-63B).', type: 'int', min: 8, max: 64, unit: 'characters', editableBy: 'platform', applies: 'new-sign-ins', defaultValue: () => 8 },
  { key: 'password.allowResetRequests', group: 'passwords', label: 'Let people ask for a password reset', help: 'Adds "Forgot your password?" to the sign-in page. There is no email: the request appears for administrators under Admin > Users, who reset the password and tell the person. Turn off if you would rather people call the help desk.', type: 'bool', editableBy: 'admin', applies: 'immediately', defaultValue: () => true },
  { key: 'password.blockCommon', group: 'passwords', label: 'Refuse common passwords', help: 'Reject the passwords every guess list tries first, and any password that contains the person\'s sign-in name.', type: 'bool', editableBy: 'platform', applies: 'new-sign-ins', defaultValue: () => true },

  // ── Lockout ─────────────────────────────────────────────────────────────────────────────────────────────────────
  { key: 'lockout.enabled', group: 'lockout', label: 'Lock accounts after repeated failures', help: 'When on, too many wrong passwords lock the account for the period below. When off, people may retry as often as they like (every failure is still recorded in the sign-in log).', type: 'bool', editableBy: 'platform', applies: 'immediately', defaultValue: () => IDP_CONFIG.loginLockoutEnabled },
  { key: 'lockout.threshold', group: 'lockout', label: 'Failures before a lock', help: 'Wrong passwords within the window that trigger the lock.', type: 'int', min: 3, max: 20, unit: 'attempts', editableBy: 'platform', applies: 'immediately', defaultValue: () => 5 },
  { key: 'lockout.minutes', group: 'lockout', label: 'Lock period and counting window', help: 'How long the lock lasts, and how far back failures are counted.', type: 'int', min: 1, max: 240, unit: 'minutes', editableBy: 'platform', applies: 'immediately', defaultValue: () => 15 },

  // ── Two-factor ──────────────────────────────────────────────────────────────────────────────────────────────────
  { key: 'mfa.requireForAdmins', group: 'mfa', label: 'Require two-factor for console administrators', help: 'An administrator without an authenticator app enrolled is refused the console until they enrol one (Portal > Security). Turn it on after every administrator has enrolled.', type: 'bool', editableBy: 'platform', applies: 'immediately', defaultValue: () => IDP_CONFIG.adminRequireMfa },

  // ── Sessions and tokens ─────────────────────────────────────────────────────────────────────────────────────────
  { key: 'ttl.accessTokenSeconds', group: 'sessions', label: 'Access token lifetime', help: 'Shorter is safer: a stolen token stops working sooner. Applies to tokens issued from now on.', type: 'int', min: 60, max: 86400, unit: 'seconds', editableBy: 'platform', applies: 'new-tokens', defaultValue: () => IDP_CONFIG.ttl.accessToken },
  { key: 'ttl.idTokenSeconds', group: 'sessions', label: 'ID token lifetime', help: 'How long the identity token handed to an application stays valid. Applies to tokens issued from now on.', type: 'int', min: 60, max: 86400, unit: 'seconds', editableBy: 'platform', applies: 'new-tokens', defaultValue: () => IDP_CONFIG.ttl.idToken },
  { key: 'ttl.refreshTokenHours', group: 'sessions', label: 'Refresh token lifetime', help: 'How long an application can keep renewing a session without the person signing in again.', type: 'int', min: 1, max: 720, unit: 'hours', editableBy: 'platform', applies: 'new-tokens', defaultValue: () => Math.max(1, Math.round(IDP_CONFIG.ttl.refreshToken / 3600)) },
  { key: 'ttl.ssoSessionHours', group: 'sessions', label: 'Single sign-on session length', help: 'How long one sign-in covers every application before the person must sign in again.', type: 'int', min: 1, max: 720, unit: 'hours', editableBy: 'platform', applies: 'new-sign-ins', defaultValue: () => Math.max(1, Math.round(IDP_CONFIG.ttl.session / 3600)) },
  { key: 'ttl.portalSessionHours', group: 'sessions', label: 'Portal and console session length', help: 'How long the portal and the admin console stay signed in.', type: 'int', min: 1, max: 720, unit: 'hours', editableBy: 'platform', applies: 'new-sign-ins', defaultValue: () => 336 },

  // ── Retention ───────────────────────────────────────────────────────────────────────────────────────────────────
  { key: 'retention.loginEventDays', group: 'retention', label: 'Keep sign-in records for', help: 'The sign-in log is purged beyond this. The admin audit trail is never purged (it is a tamper-evident chain).', type: 'int', min: 30, max: 730, unit: 'days', editableBy: 'platform', applies: 'immediately', defaultValue: () => 90 },
];

const BY_KEY = new Map(SETTINGS.map((s) => [s.key, s]));

export function settingDef(key: string): SettingDef | undefined {
  return BY_KEY.get(key);
}

// ── Colour contrast (WCAG 2.x) ───────────────────────────────────────────────────────────────────────────────────────

function channel(v: number): number {
  const s = v / 255;
  return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
}

export function luminance(hex: string): number {
  const n = parseInt(hex.slice(1), 16);
  return 0.2126 * channel((n >> 16) & 255) + 0.7152 * channel((n >> 8) & 255) + 0.0722 * channel(n & 255);
}

export function contrastRatio(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

/** Black or white, whichever reads better on `hex` (for text on a button of the accent colour). */
export function readableInk(hex: string): '#000000' | '#ffffff' {
  return contrastRatio(hex, '#ffffff') >= contrastRatio(hex, '#000000') ? '#ffffff' : '#000000';
}

const MIN_CONTRAST = 3;

// ── Validation ───────────────────────────────────────────────────────────────────────────────────────────────────────

export type ParseResult = { ok: true; value: SettingValue } | { ok: false; error: string };

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;

/** Checks one raw value from the API against its definition. `appIds` is the set of launcher ids (the `apps` type only). */
export function parseSettingValue(def: SettingDef, raw: unknown, appIds: readonly string[] = []): ParseResult {
  switch (def.type) {
    case 'bool':
      return typeof raw === 'boolean' ? { ok: true, value: raw } : { ok: false, error: `${def.label} must be on or off.` };
    case 'int': {
      if (typeof raw !== 'number' || !Number.isInteger(raw)) return { ok: false, error: `${def.label} must be a whole number.` };
      if (raw < (def.min ?? 0) || raw > (def.max ?? Number.MAX_SAFE_INTEGER)) {
        return { ok: false, error: `${def.label} must be between ${def.min} and ${def.max}${def.unit ? ` ${def.unit}` : ''}.` };
      }
      return { ok: true, value: raw };
    }
    case 'text': {
      if (typeof raw !== 'string') return { ok: false, error: `${def.label} must be text.` };
      const value = raw.replace(/\r\n/g, '\n').trim();
      if (value.length > (def.maxLength ?? 200)) return { ok: false, error: `${def.label} can be at most ${def.maxLength} characters.` };
      if (CONTROL.test(value) || (!def.multiline && value.includes('\n'))) return { ok: false, error: `${def.label} contains characters that are not allowed.` };
      return { ok: true, value };
    }
    case 'color': {
      if (typeof raw !== 'string' || !HEX.test(raw.trim())) return { ok: false, error: `${def.label} must be a colour like #166534.` };
      const value = raw.trim().toLowerCase();
      for (const bg of def.contrastAgainst ?? []) {
        const ratio = contrastRatio(value, bg);
        if (ratio < MIN_CONTRAST) {
          return { ok: false, error: `${def.label} is too close to the page colour (contrast ${ratio.toFixed(1)}:1; at least ${MIN_CONTRAST}:1 is needed to stay readable). Choose a stronger colour.` };
        }
      }
      return { ok: true, value };
    }
    case 'apps': {
      if (!Array.isArray(raw) || raw.some((v) => typeof v !== 'string')) return { ok: false, error: `${def.label} must be a list of applications.` };
      const unique = [...new Set(raw as string[])];
      const unknown = unique.filter((id) => !appIds.includes(id));
      if (unknown.length) return { ok: false, error: `Unknown application: ${unknown.join(', ')}.` };
      return { ok: true, value: unique.sort() };
    }
  }
}

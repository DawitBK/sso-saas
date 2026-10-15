/**
 * Branding: the values an administrator sets under Settings > Branding (backend: settings/registry.ts, served unauthenticated by
 * GET /api/v1/public/branding). The root layout fetches them on the server for every page view, so the colours, title and sign-in
 * notice are in the first HTML the browser receives: no flash of the default look, and a sign-in page that still renders if the
 * backend is slow (a short timeout and the built-in defaults).
 */
export interface Branding {
  productName: string;
  tagline: string;
  accentColor: string;
  accentInk: string;
  accentColorDark: string;
  accentInkDark: string;
  loginNotice: string;
  supportContact: string;
  footerText: string;
  portalMessage: string;
  passwordMinLength: number;
  /** The sign-in page offers "Forgot your password?" (no email: the request goes to the administrators). */
  passwordResetRequests: boolean;
}

export const DEFAULT_BRANDING: Branding = {
  productName: 'Example Corp Identity',
  tagline: 'Single sign-on',
  accentColor: '#166534',
  accentInk: '#ffffff',
  accentColorDark: '#22c55e',
  accentInkDark: '#000000',
  loginNotice: '',
  supportContact: '',
  footerText: '© Example Corp · Secured by OpenID Connect',
  portalMessage: '',
  passwordMinLength: 8,
  passwordResetRequests: true,
};

const HEX = /^#[0-9a-f]{6}$/i;

/** Accepts only well-formed values from the backend: a colour is interpolated into a <style> block, so it must be exactly #rrggbb. */
export function sanitizeBranding(raw: Partial<Branding> | null | undefined): Branding {
  const d = DEFAULT_BRANDING;
  if (!raw) return d;
  const text = (v: unknown, fallback: string, max: number) => (typeof v === 'string' && v.length <= max ? v : fallback);
  const color = (v: unknown, fallback: string) => (typeof v === 'string' && HEX.test(v) ? v.toLowerCase() : fallback);
  const ink = (v: unknown, fallback: string) => (v === '#000000' || v === '#ffffff' ? v : fallback);
  return {
    productName: text(raw.productName, d.productName, 60) || d.productName,
    tagline: text(raw.tagline, d.tagline, 80),
    accentColor: color(raw.accentColor, d.accentColor),
    accentInk: ink(raw.accentInk, d.accentInk),
    accentColorDark: color(raw.accentColorDark, d.accentColorDark),
    accentInkDark: ink(raw.accentInkDark, d.accentInkDark),
    loginNotice: text(raw.loginNotice, '', 300),
    supportContact: text(raw.supportContact, '', 120),
    footerText: text(raw.footerText, d.footerText, 120),
    portalMessage: text(raw.portalMessage, '', 200),
    passwordMinLength: typeof raw.passwordMinLength === 'number' && raw.passwordMinLength >= 8 && raw.passwordMinLength <= 64 ? raw.passwordMinLength : d.passwordMinLength,
    // Only an explicit false hides the link: a backend that predates the setting (or a timeout and the defaults) keeps it, and the server answers either way.
    passwordResetRequests: raw.passwordResetRequests !== false,
  };
}

/**
 * The CSS that applies the accent to every theme. Only validated colours reach this string. The `html` prefix raises the
 * specificity above the theme blocks in globals.css, so the accent wins whichever stylesheet the browser reads last.
 */
export function brandingCss(b: Branding): string {
  const rule = (color: string, ink: string) =>
    `--brand:${color};--brand-ink:${ink};--brand-600:${color};--brand-700:color-mix(in srgb,${color} 82%,#000);--grad-2:color-mix(in srgb,${color} 78%,#000);--ring:color-mix(in srgb,${color} 35%,transparent);`;
  return (
    `html:root,html:root[data-theme='light']{${rule(b.accentColor, b.accentInk)}}` +
    `html:root[data-theme='dark-black'],html:root[data-theme='dark-blue']{${rule(b.accentColorDark, b.accentInkDark)}}`
  );
}

/** Server-side fetch for the root layout. Never throws and never waits long. */
export async function fetchBranding(): Promise<Branding> {
  const backend = (process.env.SSO_BACKEND_URL ?? 'http://localhost:7300').replace(/\/$/, '');
  try {
    const res = await fetch(`${backend}/api/v1/public/branding`, { cache: 'no-store', signal: AbortSignal.timeout(1500) });
    if (!res.ok) return DEFAULT_BRANDING;
    const json = (await res.json()) as { data?: Partial<Branding> };
    return sanitizeBranding(json.data);
  } catch {
    return DEFAULT_BRANDING;
  }
}

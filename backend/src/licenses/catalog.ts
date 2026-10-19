/**
 * The licence module catalogue (docs/operations/PLATFORM-LICENSING.md section 7).
 *
 * These are the GATEABLE module keys, the values an administrator ticks in the Licences form and that travel in the signed token's `modules`
 * claim. Core features are never gateable and are not listed. GMS and DMS keep the same keys next to their own route gating; the contract
 * document is the shared source, and tests/licenses-catalog.test.ts pins this list to it. SSO has nothing gateable (expiry and seats only).
 */
export const LICENSE_SYSTEMS = ['sso', 'gms', 'dms'] as const;
export type LicenseSystem = (typeof LICENSE_SYSTEMS)[number];

export interface ModuleDef {
  key: string;
  label: string;
  /** What switching it off takes away, in the words an administrator knows. */
  description: string;
}

export const SYSTEM_LABELS: Record<LicenseSystem, string> = {
  sso: 'SSO (identity provider)',
  gms: 'GMS (guest management)',
  dms: 'DMS (document management)',
};

export const MODULE_CATALOG: Record<LicenseSystem, readonly ModuleDef[]> = {
  sso: [],
  gms: [
    { key: 'visits', label: 'Visits', description: 'Visits, approvals, guests and hosts.' },
    { key: 'scheduling', label: 'Scheduling', description: 'Availability and visit scheduling.' },
    { key: 'checkin', label: 'Check-in', description: 'Check-in and the UniFi webhooks.' },
    { key: 'credentials', label: 'Credentials', description: 'Passes and credentials.' },
    { key: 'notifications', label: 'Notifications', description: 'Notifications and messages.' },
    { key: 'ocr', label: 'OCR', description: 'Document and ID scanning.' },
  ],
  dms: [
    { key: 'letters', label: 'Letters', description: 'Incoming and outgoing letters.' },
    { key: 'workflow', label: 'Workflow', description: 'Workflow and approvals.' },
    { key: 'esigning', label: 'E-signing', description: 'Electronic signing and signing requests.' },
    { key: 'legal_hold', label: 'Legal hold', description: 'Legal holds.' },
    { key: 'retention', label: 'Retention', description: 'Retention policies and disposal.' },
    { key: 'ai', label: 'AI', description: 'AI features and the assignment advisory.' },
    { key: 'ocr', label: 'OCR', description: 'Text recognition on scanned documents.' },
    { key: 'search', label: 'Search', description: 'Full-text search.' },
    { key: 'archive', label: 'Archive', description: 'The archive.' },
    { key: 'reports', label: 'Reports', description: 'Reports.' },
    { key: 'bundles', label: 'Bundles', description: 'Document bundles.' },
    { key: 'webhooks', label: 'Webhooks', description: 'Outbound webhooks.' },
    { key: 'forms', label: 'Forms', description: 'Forms.' },
  ],
};

export function isLicenseSystem(value: unknown): value is LicenseSystem {
  return typeof value === 'string' && (LICENSE_SYSTEMS as readonly string[]).includes(value);
}

export function moduleKeys(system: LicenseSystem): string[] {
  return MODULE_CATALOG[system].map((m) => m.key);
}

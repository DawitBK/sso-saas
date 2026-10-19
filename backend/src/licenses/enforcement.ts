/**
 * LICENSE_ENFORCEMENT (docs/operations/PLATFORM-LICENSING.md section 6): `enforce` (default) computes states and blocks, `warn` computes and
 * reports but never blocks, `off` does nothing at all. Dependency-free so config.ts can read it before anything else is loaded.
 *
 * An unrecognised value falls back to `enforce` (the documented default) and is reported as invalid so the boot log can say so: a typo in an
 * emergency switch must not be silent, and must not silently turn enforcement off either.
 */
export type LicenseEnforcement = 'enforce' | 'warn' | 'off';

export function parseLicenseEnforcement(raw: string | undefined): { mode: LicenseEnforcement; invalid: boolean } {
  const v = (raw ?? '').trim().toLowerCase();
  if (v === '') return { mode: 'enforce', invalid: false };
  if (v === 'enforce' || v === 'warn' || v === 'off') return { mode: v, invalid: false };
  return { mode: 'enforce', invalid: true };
}

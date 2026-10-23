/**
 * The audit trail records machine-readable action codes (`user.disable`, `client.secret.rotate`). The Audit page shows them as a
 * sentence an auditor can read, with the code still visible beside it. An action this list does not know is shown from its code
 * ("Group entitlements") rather than hidden, so a new action is never invisible while this file catches up.
 */
const LABELS: Record<string, string> = {
  'user.create': 'Created an account',
  'user.update': 'Edited an account',
  'user.disable': 'Disabled an account',
  'user.enable': 'Enabled an account',
  'user.password_reset': 'Reset a password',
  'user.password_change': 'Changed their own password',
  'user.mfa_reset': 'Reset two-factor sign-in',
  'user.mfa_disable': 'Turned off two-factor sign-in',
  'user.mfa_enroll': 'Turned on two-factor sign-in',
  'user.recovery_codes_regenerate': 'Created new recovery codes',
  'user.access': 'Changed application access and roles',
  'user.dms_permissions': 'Changed DMS permissions',
  'user.gms_roles.set': 'Set GMS roles',
  'user.gms_roles.revoke_failed': 'Could not take back a GMS role',
  'user.group.add': 'Added to a group',
  'user.group.remove': 'Removed from a group',
  'user.admin_group.add': 'Made an administrator',
  'user.admin_group.remove': 'Removed as an administrator',
  'user.signout_all': 'Signed a person out everywhere',
  'user.session_kill': 'Ended one session',
  'session.revoke': 'Ended a session',
  'session.kill': 'Ended a session',
  'group.entitlements': 'Changed which applications a group can open',
  'group.dms_role': 'Changed a group’s DMS role',
  'group.gms_role': 'Changed a group’s GMS role',
  'signing_key.generate': 'Rotated the signing key',
  'signing_key.retire': 'Withdrew a signing key',
  'setting.update': 'Changed a setting',
  'setting.reset': 'Reset a setting to its default',
  'client.uris.update': 'Changed an application’s addresses',
  'client.uris.restore': 'Restored an application’s configured addresses',
  'client.enable': 'Switched an application on',
  'client.disable': 'Switched an application off',
  'client.secret.rotate': 'Rotated an application’s secret',
  'security.incident': 'Security incident recorded',
  'license.create': 'Created a licence',
  'license.update': 'Changed a licence',
  'license.extend': 'Extended a licence',
  'license.revoke': 'Removed a licence',
  'users.export': 'Exported the user list',
  'audit.export': 'Exported the audit trail',
  'logins.export': 'Exported the sign-in log',
};

export function auditActionLabel(action: string): string {
  if (LABELS[action]) return LABELS[action];
  const words = action.replace(/[._]+/g, ' ').trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : action;
}

/** The family of an action for grouping the filter: `user.disable` -> `user`. */
export function auditFamily(action: string): string {
  return action.split('.')[0] ?? action;
}

const FAMILY_LABELS: Record<string, string> = {
  user: 'People',
  users: 'People (exports)',
  group: 'Groups',
  session: 'Sessions',
  signing_key: 'Signing keys',
  setting: 'Settings',
  client: 'Applications',
  audit: 'Audit trail',
  logins: 'Sign-in log',
};

export function auditFamilyLabel(family: string): string {
  return FAMILY_LABELS[family] ?? family;
}

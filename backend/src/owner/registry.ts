/**
 * THE list of owner-only operations: the one place a key, its plain-language label and its warning are defined. The routes name an operation by
 * key (requireOwnerAuthorisation('license.save')), the verification API returns the label and warning to the dialog, and the tests walk this list,
 * so an operation cannot be enforced without being described, nor described without being known to the tests.
 *
 * Adding an owner-only operation: add it here, put `requireOwnerAuthorisation(key)` (or `authoriseOwnerOperation` inline, for a conditional one) on its
 * route, and add the route to tests/owner-operations.test.ts. The warning is shown to the owner BEFORE they confirm: say what will happen and what it
 * can break, in plain words, with no jargon.
 *
 * `audience` is the system that will accept the ticket: 'sso' operations are performed here, 'dms' ones are performed in DMS, which verifies the same
 * kind of ticket against SSO's published keys. `needsTarget` means the ticket is also bound to what the operation acts on (a key id, a licence's
 * system, a client id, a setting), so an authorisation for one cannot be used on another.
 * `cli` marks an operation done at a terminal on the server, never over HTTP (it is protected there by the vault password); it is listed so the
 * list stays complete.
 */
import crypto from 'node:crypto';

export type OwnerAudience = 'sso' | 'dms';

export interface OwnerOperation {
  key: string;
  label: string;
  warning: string;
  audience: OwnerAudience;
  needsTarget: boolean;
  cli?: boolean;
}

const op = (key: string, label: string, warning: string, needsTarget = false, audience: OwnerAudience = 'sso', cli = false): OwnerOperation => ({
  key,
  label,
  warning,
  needsTarget,
  audience,
  ...(cli ? { cli: true } : {}),
});

export const OWNER_OPERATIONS: readonly OwnerOperation[] = [
  op(
    'signing_key.generate',
    'Create a new signing key',
    'Every sign-in token the platform issues from now on is signed with the new key. Systems pick it up on their own, but anything that holds a copy of the old key list for long may reject sign-ins until it refreshes.',
  ),
  op(
    'signing_key.retire',
    'Retire or withdraw a signing key',
    'Tokens signed with this key stop being accepted once it leaves the published key list. Withdrawing a key that is still in use signs people out of the systems that rely on it.',
    true,
  ),
  op(
    'idp_admin.change',
    'Change who is an identity administrator',
    'Identity administrators can see and change everyone’s access to every system. Only give or take this role from a person you have checked yourself.',
    true,
  ),
  op(
    'license.save',
    'Save a licence',
    'The licence decides whether a system may be used at all, for how long, by how many people and with which modules. A wrong date or limit can make a system read-only or stop it.',
    true,
  ),
  op(
    'license.extend',
    'Extend a licence',
    'This moves the licence’s end date. It is recorded in the licence history and in the audit log.',
    true,
  ),
  op(
    'license.revoke',
    'Remove a licence',
    'The system returns to having no licence. In production a system without a licence refuses everything except sign-in until a new licence is installed. No data is deleted.',
    true,
  ),
  op(
    'setting.change',
    'Change a platform setting',
    'Platform settings (password rules, sign-in lockout, two-factor, token lifetimes, how long logs are kept) apply to every person and every system straight away.',
    true,
  ),
  op(
    'client.uris.update',
    'Change an application’s sign-in addresses',
    'These addresses decide where sign-in results are sent. A wrong or hostile address can send people’s sign-ins to the wrong place, and a missing one stops the application from signing anyone in.',
    true,
  ),
  op(
    'client.uris.restore',
    'Restore an application’s configured sign-in addresses',
    'This replaces the application’s sign-in addresses with the ones in the server’s configuration. Anything added in the console is removed.',
    true,
  ),
  op(
    'client.active.set',
    'Switch an application on or off',
    'Switching an application off also ends every sign-in it holds, so people are signed out of it at once. Switching it on lets sign-ins through again.',
    true,
  ),
  op(
    'client.secret.rotate',
    'Give an application a new secret',
    'The application stops working until its own configuration is updated with the new secret, which is shown once.',
    true,
  ),
  op(
    'audit.chain.acknowledge',
    'Acknowledge a break in the audit log',
    'You are stating that a break in the tamper-evident audit log is known and harmless. The break stays listed, but the log is treated as explained from then on.',
    true,
  ),
  op(
    'owner.store.change',
    'Change the owner verification (questions, authenticator, mailbox address, recovery codes)',
    'This changes how the owner proves who they are. It is done on the server at a terminal with the vault password, never through the console.',
    false,
    'sso',
    true,
  ),
  op(
    'dms.tenant.create',
    'Create a tenant in DMS',
    'A tenant is a separate organisation inside the document system, with its own users, documents and settings. Creating one cannot be undone from the console.',
    false,
    'dms',
  ),
];

const BY_KEY = new Map(OWNER_OPERATIONS.map((o) => [o.key, o]));

export function findOperation(key: string): OwnerOperation | undefined {
  return BY_KEY.get(key);
}

/** The operations the HTTP API can authorise (everything except terminal-only ones). */
export function httpOperations(): OwnerOperation[] {
  return OWNER_OPERATIONS.filter((o) => !o.cli);
}

/**
 * The value a ticket is bound to: a hash of the operation and what it acts on, or null for an operation with no target. Hashing keeps the target
 * out of the ticket and the tables; the operation is in the hash so a target hash from one operation can never match another's.
 */
export function targetHash(operationKey: string, target: string | undefined | null): string | null {
  const o = BY_KEY.get(operationKey);
  if (!o || !o.needsTarget) return null;
  return crypto.createHash('sha256').update(`owner-target\n${operationKey}\n${String(target ?? '')}`).digest('hex');
}

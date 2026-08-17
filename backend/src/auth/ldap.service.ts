/**
 * Active Directory / LDAP authentication (AD-primary).
 *
 * Real `ldapts` implementation: bind as a service account, search for the user,
 * then re-bind as the user to verify the password, returning identity + group DNs.
 * If LDAP_URL is unset, AD is considered unavailable and callers fall back to the
 * local user store (see authenticate.ts).
 */

import { Client } from 'ldapts';
import { IDP_CONFIG } from '../config.js';

export interface ADUser {
  dn: string;
  email: string;
  givenName: string;
  familyName: string;
  adGroups: string[];
  emailVerified: boolean;
}

/** Is AD configured at all? */
export function isAdEnabled(): boolean {
  return Boolean(IDP_CONFIG.ldap.url);
}

function esc(value: string): string {
  // RFC 4515 filter escaping to prevent LDAP injection.
  return value.replace(/[\\*()\0]/g, (c) => '\\' + c.charCodeAt(0).toString(16).padStart(2, '0'));
}

/**
 * Authenticate against AD. Returns the user on success, null on bad credentials
 * or unknown user. Throws only on infrastructure errors (AD unreachable) so the
 * caller can decide whether to fall back.
 */
export async function authenticateAD(username: string, password: string): Promise<ADUser | null> {
  const { url, bindDN, bindPassword, searchBase, usernameAttr, timeoutMs } = IDP_CONFIG.ldap;
  if (!url) return null;

  const client = new Client({ url, timeout: timeoutMs, connectTimeout: timeoutMs });
  try {
    // 1) Bind as the service account to search.
    await client.bind(bindDN, bindPassword);

    const { searchEntries } = await client.search(searchBase, {
      scope: 'sub',
      filter: `(&(objectClass=user)(${usernameAttr}=${esc(username)}))`,
      attributes: ['dn', 'memberOf', 'mail', 'userPrincipalName', 'givenName', 'sn', 'displayName'],
    });
    const entry = searchEntries[0];
    if (!entry) return null;

    // 2) Verify the password by binding as the user.
    try {
      await client.bind(entry.dn as string, password);
    } catch {
      return null; // wrong password / disabled / locked
    }

    const asArray = (v: unknown): string[] =>
      Array.isArray(v) ? v.map(String) : v == null ? [] : [String(v)];

    return {
      dn: String(entry.dn),
      email: String(entry.mail ?? entry.userPrincipalName ?? username),
      givenName: String(entry.givenName ?? ''),
      familyName: String(entry.sn ?? ''),
      adGroups: asArray(entry.memberOf),
      emailVerified: true, // AD-provisioned accounts are treated as verified
    };
  } finally {
    await client.unbind().catch(() => undefined);
  }
}

/**
 * Look up a user's CURRENT AD group membership by email, using only the
 * service account — no user password involved. For the periodic AD-group
 * re-sync sweep (ad-resync.worker.ts, platform audit finding 4.7), which has
 * no password to check and only needs a fresh memberOf snapshot for someone
 * who already has a live session. Returns null if the user can't be found
 * (e.g. removed from AD entirely) so the caller can decide how to treat that
 * distinctly from "still a member of nothing."
 */
export async function lookupAdGroupsByEmail(email: string): Promise<string[] | null> {
  const { url, bindDN, bindPassword, searchBase, timeoutMs } = IDP_CONFIG.ldap;
  if (!url) return null;

  const client = new Client({ url, timeout: timeoutMs, connectTimeout: timeoutMs });
  try {
    await client.bind(bindDN, bindPassword);

    const { searchEntries } = await client.search(searchBase, {
      scope: 'sub',
      filter: `(&(objectClass=user)(|(mail=${esc(email)})(userPrincipalName=${esc(email)})))`,
      attributes: ['memberOf'],
    });
    const entry = searchEntries[0];
    if (!entry) return null;

    const asArray = (v: unknown): string[] =>
      Array.isArray(v) ? v.map(String) : v == null ? [] : [String(v)];
    return asArray(entry.memberOf);
  } finally {
    await client.unbind().catch(() => undefined);
  }
}

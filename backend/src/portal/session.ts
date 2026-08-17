/**
 * Portal session store — holds the signed-in user's identity for the portal UI,
 * keyed by the `idp_portal` cookie. Postgres-backed (idp_web_sessions), so
 * sessions survive restarts.
 */

import { putWebSession, getWebSession, dropWebSession } from '../db/web-sessions.js';

export interface PortalSession {
  accountId: string;
  name: string;
  email: string;
  groups: string[];
  /** Raw id_token from the portal's own OIDC login — used as id_token_hint for
   *  RP-initiated logout so "Sign out" ends the real SSO session, not just the
   *  portal's local one. */
  idToken?: string;
  createdAt: number;
}

const TTL_MS = 14 * 24 * 60 * 60_000; // match IdP SSO session

export async function putPortalSession(data: Omit<PortalSession, 'createdAt'>): Promise<string> {
  return putWebSession('portal', { ...data, createdAt: Date.now() }, TTL_MS);
}

export async function getPortalSession(key: string | undefined): Promise<PortalSession | undefined> {
  return getWebSession<PortalSession>('portal', key);
}

export async function dropPortalSession(key: string | undefined): Promise<void> {
  return dropWebSession('portal', key);
}

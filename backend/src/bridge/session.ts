/**
 * Gateway session store — holds the minted downstream (GMS) tokens server-side,
 * keyed by the `idp_gw` cookie / one-time handoff code, so the same-origin
 * gateway can inject `Authorization: Bearer` on proxied GMS API calls.
 * Postgres-backed (idp_web_sessions), so handoffs survive restarts.
 */

import { putWebSession, getWebSession, takeWebSession } from '../db/web-sessions.js';

export interface GatewaySession {
  gmsAccessToken: string;
  gmsRefreshToken: string;
  userId: number;
  roles: string[];
  officeId: number | null;
  /** Lowercased user email — lets revokeAllSessions find and kill these. */
  email: string;
  /** sha256 of a one-time token handed to the browser as an httpOnly cookie at
   *  mint time — redemption must present the matching cookie, so a code that
   *  merely leaks (a log line, a proxy, a link-scanner prefetch) can't be
   *  redeemed by anyone but the browser that started the handoff. */
  bindingHash: string;
  createdAt: number;
}

// This is a one-time bootstrap code meant to be redeemed within the same
// redirect chain (seconds), not a session lifetime — it previously reused the
// 8h GMS access TTL, leaving a stolen/logged code redeemable for hours.
const TTL_MS = 2 * 60_000;

export async function putGatewaySession(data: Omit<GatewaySession, 'createdAt'>): Promise<string> {
  return putWebSession('gateway', { ...data, createdAt: Date.now() }, TTL_MS);
}

export async function getGatewaySession(key: string | undefined): Promise<GatewaySession | undefined> {
  return getWebSession<GatewaySession>('gateway', key);
}

/** One-time redemption: return the session and delete it (used by the gateway handoff). */
export async function takeGatewaySession(key: string | undefined): Promise<GatewaySession | undefined> {
  return takeWebSession<GatewaySession>('gateway', key);
}

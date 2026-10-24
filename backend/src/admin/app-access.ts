/**
 * What an administrator sets for a person on the App access panel for the applications managed from the console (auth/app-roles.ts):
 * which role the person holds in each application, or none. No role means no access to that application.
 *
 * The same shape as the DMS and GMS role save, so the panel reads one way: validated before anything is written, applied per application,
 * audited, and, when the roles of an application changed for a person who already had some, the application is told (back-channel logout)
 * to end that person's sessions, so the new role, or the loss of access, is in force at once and not at the next natural sign-in.
 */

import type { Request } from 'express';
import { getGrantedRoles, setGrantedRoles } from '../auth/client-user-roles.js';
import { managedCatalog } from '../auth/app-roles.js';
import { notifyAppLogout } from '../auth/logout-notify.js';
import { logger } from '../logging/logger.js';
import { writeAudit } from './audit.js';

/** client id -> role names; an empty list means "no access to that application". */
export type AppRolesInput = Record<string, string[]>;

export type ParsedAppRoles = { ok: true; value: AppRolesInput } | { ok: false; message: string };

/** Check what the console sent. Absent means "leave the applications alone"; every client must be a managed application and every role one of its catalog. */
export async function parseAppRolesInput(raw: unknown): Promise<ParsedAppRoles> {
  if (raw === undefined || raw === null) return { ok: true, value: {} };
  if (typeof raw !== 'object' || Array.isArray(raw)) return { ok: false, message: 'app_roles must be an object: application -> list of roles.' };
  const catalog = new Map((await managedCatalog()).map((c) => [c.clientId, new Set(c.roles.map((r) => r.roleName))]));
  const value: AppRolesInput = {};
  for (const [clientId, roles] of Object.entries(raw as Record<string, unknown>)) {
    const known = catalog.get(clientId);
    if (!known) return { ok: false, message: `"${clientId}" is not an application managed from the console.` };
    if (!Array.isArray(roles) || !roles.every((r) => typeof r === 'string')) return { ok: false, message: `The roles for "${clientId}" must be a list of role names.` };
    const unique = Array.from(new Set(roles as string[]));
    const unknown = unique.filter((r) => !known.has(r));
    if (unknown.length > 0) return { ok: false, message: `Unknown role(s) for "${clientId}": ${unknown.join(', ')}.` };
    value[clientId] = unique;
  }
  return { ok: true, value };
}

export interface AppRolesChange {
  clientId: string;
  before: string[];
  after: string[];
}

const sameSet = (a: string[], b: string[]): boolean => a.length === b.length && [...a].sort().every((v, i) => v === [...b].sort()[i]);

/** Apply the roles. Only applications whose roles actually differ are written, audited and notified. Returns what changed. */
export async function applyAppRoles(
  req: Request,
  actorEmail: string,
  person: { accountId: string; email: string },
  desired: AppRolesInput,
): Promise<AppRolesChange[]> {
  const changes: AppRolesChange[] = [];
  for (const [clientId, after] of Object.entries(desired)) {
    const before = await getGrantedRoles(person.email, clientId);
    if (sameSet(before, after)) continue;
    await setGrantedRoles(person.email, clientId, after, actorEmail);
    await writeAudit(req, actorEmail, 'user.app_roles', person.email, { userId: person.accountId, clientId, before, after });
    changes.push({ clientId, before, after });
  }
  // End the person's sessions in the applications whose roles changed, when they could have had one (they held a role before).
  const toNotify = changes.filter((c) => c.before.length > 0);
  const results = await Promise.allSettled(toNotify.map((c) => notifyAppLogout(c.clientId, person.accountId, { queueOnFailure: true })));
  results.forEach((r, i) => {
    if (r.status === 'rejected') logger.warn({ err: r.reason, clientId: toNotify[i]!.clientId }, '[idp:access] could not tell the application to end the person\'s sessions; it is queued');
  });
  return changes;
}

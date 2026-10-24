import { IDP_CONFIG } from '../config.js';
import { createInternalApiClient } from '../infrastructure/internalApiClient.js';

export interface GmsOffice {
  id: number;
  name: string;
}

export interface GmsLiveStatus {
  exists: boolean;
  id: string | null;
  roles: string[];
  officeId: number | null;
  active: boolean | null;
}

export class GmsInternalApiError extends Error {
  status: number;
  code: string;

  constructor(message: string, status: number, code: string) {
    super(message);
    this.name = 'GmsInternalApiError';
    this.status = status;
    this.code = code;
  }
}

// Shared factory (infrastructure/internalApiClient.ts) — see Finding 6/10 of the
// PHASE-02-10-14 code review: this client previously had NO
// timeout at all, unlike its dms-internal-client.ts/bridge/gms.ts siblings.
// IDP_CONFIG.gms.internalTimeoutMs (new) closes that gap.
const client = createInternalApiClient({
  serviceLabel: 'GMS',
  baseUrl: () => IDP_CONFIG.gms.apiBase,
  getApiKey: () => IDP_CONFIG.gms.internalApiKey,
  timeoutMs: IDP_CONFIG.gms.internalTimeoutMs,
  notConfiguredMessage: 'GMS_INTERNAL_API_KEY is not configured — set it in .env to manage GMS access here.',
  createError: (message, status, code) => new GmsInternalApiError(message, status, code),
});

export async function listGmsOffices(requestId?: string): Promise<GmsOffice[]> {
  const result = await client.request<{ offices: GmsOffice[] }>('/internal/sso/offices', undefined, requestId);
  return result.offices;
}

export async function getGmsUserStatus(email: string, requestId?: string): Promise<GmsLiveStatus> {
  const result = await client.request<{
    exists: boolean;
    id: number | null;
    roles: string[];
    officeId: number | null;
    active: boolean | null;
  }>(`/internal/sso/users/by-email/${encodeURIComponent(email)}/status`, undefined, requestId);

  return {
    exists: result.exists,
    id: result.id === null ? null : String(result.id),
    roles: result.roles,
    officeId: result.officeId,
    active: result.active,
  };
}

import { IDP_CONFIG } from '../config.js';

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

function baseUrl(): string {
  return IDP_CONFIG.gms.apiBase.replace(/\/+$/, '');
}

async function request<T>(path: string): Promise<T> {
  if (!IDP_CONFIG.gms.internalApiKey) {
    throw new GmsInternalApiError(
      'GMS_INTERNAL_API_KEY is not configured — set it in .env to manage GMS access here.',
      503,
      'ERR-INTERNAL-API-DISABLED',
    );
  }

  const url = `${baseUrl()}${path}`;
  let res: Response;
  try {
    res = await fetch(url, {
      headers: {
        'content-type': 'application/json',
        'x-internal-api-key': IDP_CONFIG.gms.internalApiKey,
      },
    });
  } catch (err) {
    throw new GmsInternalApiError(`Could not reach GMS at ${url}: ${(err as Error).message}`, 503, 'ERR-GMS-UNREACHABLE');
  }

  const body = (await res.json().catch(() => null)) as {
    success?: boolean;
    data?: T;
    error?: { code?: string; message?: string };
  } | null;

  if (!res.ok || body?.success === false) {
    throw new GmsInternalApiError(
      body?.error?.message ?? `GMS internal API request failed with status ${res.status}`,
      res.status,
      body?.error?.code ?? 'ERR-UNKNOWN',
    );
  }

  return (body?.data ?? (body as unknown)) as T;
}

export async function listGmsOffices(): Promise<GmsOffice[]> {
  const result = await request<{ offices: GmsOffice[] }>('/internal/sso/offices');
  return result.offices;
}

export async function getGmsUserStatus(email: string): Promise<GmsLiveStatus> {
  const result = await request<{
    exists: boolean;
    id: number | null;
    roles: string[];
    officeId: number | null;
    active: boolean | null;
  }>(`/internal/sso/users/by-email/${encodeURIComponent(email)}/status`);

  return {
    exists: result.exists,
    id: result.id === null ? null : String(result.id),
    roles: result.roles,
    officeId: result.officeId,
    active: result.active,
  };
}

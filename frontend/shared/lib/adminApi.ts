import { apiPath } from '@shared/apiPath';
import { ownerFetch } from '@shared/owner/ownerClient';

/**
 * One way for the admin console to call the SSO backend's JSON API (`{ data, meta }` on success, `{ error: { code, message } }` on failure).
 *
 * Every page used to repeat the same fetch / res.json() / envelope-peeling, and most of them swallowed the server's own message
 * ("Failed to load") even though the backend says exactly what is wrong. This gives them the real message, the error code, and the
 * request id an administrator can quote when asking for help.
 */
export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code: string,
    public readonly requestId: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

interface Envelope<T> {
  data?: T;
  error?: { code?: string; message?: string };
  meta?: { requestId?: string };
}

export interface AdminFetchInit {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  /** Sent as JSON. */
  body?: unknown;
  signal?: AbortSignal;
}

/** Calls `path` (a root-relative backend path) and returns `data`. Throws ApiError with the server's own message. */
export async function adminFetch<T>(path: string, init: AdminFetchInit = {}): Promise<T> {
  let res: Response;
  try {
    // ownerFetch: identical to fetch unless the server answers that the action needs the owner's authorisation, in which case the
    // verification dialog runs and the same request is sent again with it.
    res = await ownerFetch(path, {
      method: init.method ?? 'GET',
      headers: init.body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      signal: init.signal,
      cache: 'no-store',
    });
  } catch (err) {
    if ((err as Error).name === 'AbortError') throw err;
    throw new ApiError('Could not reach the server. Check your connection and try again.', 0, 'ERR-NETWORK', '');
  }
  const json = (await res.json().catch(() => ({}))) as Envelope<T>;
  const requestId = json.meta?.requestId ?? res.headers.get('x-request-id') ?? '';
  if (res.status === 401) {
    // The session ended (or never started): go through the real sign-in, then come back.
    window.location.href = apiPath('/portal/login');
    throw new ApiError('Your session has ended. Signing you in again…', 401, 'ERR-NOT-AUTHENTICATED', requestId);
  }
  if (!res.ok || json.error) {
    throw new ApiError(json.error?.message ?? `The request failed (HTTP ${res.status}).`, res.status, json.error?.code ?? 'ERR-REQUEST', requestId);
  }
  return json.data as T;
}

/** A CSRF token for a mutation on a page whose own GET does not issue one (the cookie is set by the same call). */
export async function fetchCsrf(): Promise<string> {
  return (await adminFetch<{ csrf: string }>('/api/v1/admin/csrf')).csrf;
}

/** A message safe to show a person: the server's text for an ApiError, a generic one otherwise. */
export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.requestId ? `${err.message} (reference ${err.requestId.slice(0, 8)})` : err.message;
  return err instanceof Error ? err.message : 'Something went wrong.';
}

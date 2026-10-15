/**
 * Shared HTTP client factory for SSO's server-to-server "internal API" calls
 * into GMS and DMS (shared-secret auth via a fixed header, correlation-id
 * propagation, a bounded timeout, and JSON-envelope validation).
 *
 * Extracted from three call sites that had independently hand-rolled the same
 * logic and already drifted (Findings 6 & 10, PHASE-02-10-14 code review):
 *   - `admin/gms-internal-client.ts` — had NO timeout at all.
 *   - `admin/dms-internal-client.ts` — had a timeout, but only checked
 *     `!res.ok`, never the envelope's `success` field.
 *   - `bridge/gms.ts`'s `gmsRequest()` — had a timeout AND a `success`/`data`
 *     check, but always POSTs and always self-generates a correlation id.
 *
 * Envelope-validation choice: this factory checks `!res.ok || body?.success
 * === false`, matching the GMS admin client (the more complete of the two
 * admin clients) rather than the DMS client's `!res.ok`-only check. This is
 * safe to apply to DMS too — `body?.success` is `undefined` on responses that
 * never set the field, and `undefined === false` is `false`, so behavior for
 * DMS's existing envelopes (which don't set `success`) is unchanged; it only
 * adds detection for a `200` response that explicitly sets `success: false`,
 * which was previously missed.
 *
 * Each call site keeps its own exported `Error` subclass (`GmsInternalApiError`,
 * `DmsInternalApiError`) so existing `instanceof` checks in callers
 * (`admin/access.ts`, `api/v1/admin.router.ts`, `db/seed-users.ts`) keep
 * working unchanged — this factory takes a `createError` callback rather than
 * owning error identity itself.
 */

export interface InternalApiClientOptions {
  /** Human-readable label used in generated error messages/codes, e.g. 'GMS'/'DMS'. */
  serviceLabel: string;
  /** Lazily resolved so a caller can read a config value that isn't fixed at import time. */
  baseUrl: () => string;
  /** Defaults to 'x-internal-api-key' — the shared-secret header name every site uses today. */
  apiKeyHeaderName?: string;
  getApiKey: () => string | undefined;
  timeoutMs: number;
  /** Thrown when `getApiKey()` returns falsy, before any network call is made. */
  notConfiguredMessage: string;
  /**
   * When true, an envelope with `success: true` (or no `success` field) but no
   * `data` payload is ALSO treated as a failure. Needed only by bridge/gms.ts's
   * gmsRequest(), which historically required `payload.data` to be truthy;
   * the admin clients fall back to returning the whole parsed body when `data`
   * is absent, so they leave this false.
   */
  requireData?: boolean;
  /** Builds the thrown error; defaults to a generic InternalApiError. */
  createError?: (message: string, status: number, code: string) => Error;
}

export class InternalApiError extends Error {
  status: number;
  code: string;

  constructor(message: string, status: number, code: string) {
    super(message);
    this.name = 'InternalApiError';
    this.status = status;
    this.code = code;
  }
}

export interface InternalApiClient {
  request<T>(path: string, init?: RequestInit, requestId?: string): Promise<T>;
}

export function createInternalApiClient(options: InternalApiClientOptions): InternalApiClient {
  const apiKeyHeaderName = options.apiKeyHeaderName ?? 'x-internal-api-key';
  const labelUpper = options.serviceLabel.toUpperCase();
  const makeError = options.createError ?? ((message: string, status: number, code: string) => new InternalApiError(message, status, code));

  function resolvedBaseUrl(): string {
    return options.baseUrl().replace(/\/+$/, '');
  }

  async function request<T>(path: string, init?: RequestInit, requestId?: string): Promise<T> {
    const apiKey = options.getApiKey();
    if (!apiKey) {
      throw makeError(options.notConfiguredMessage, 503, 'ERR-INTERNAL-API-DISABLED');
    }

    const url = `${resolvedBaseUrl()}${path}`;
    const abort = new AbortController();
    const timeout = setTimeout(() => abort.abort(), options.timeoutMs);
    let res: Response;
    try {
      res = await fetch(url, {
        ...init,
        headers: {
          'content-type': 'application/json',
          [apiKeyHeaderName]: apiKey,
          // Same idiom across all three legacy clients: set both header names
          // since receivers disagree on which one they read first, and omit
          // both entirely when no id was supplied (the receiver mints its own).
          ...(requestId ? { 'x-request-id': requestId, 'x-correlation-id': requestId } : {}),
          ...(init?.headers as Record<string, string> | undefined),
        },
        signal: abort.signal,
      });
    } catch (err) {
      if ((err as Error).name === 'AbortError') {
        throw makeError(
          `${options.serviceLabel} internal API did not respond within ${options.timeoutMs}ms (${url})`,
          503,
          `ERR-${labelUpper}-TIMEOUT`,
        );
      }
      throw makeError(`Could not reach ${options.serviceLabel} at ${url}: ${(err as Error).message}`, 503, `ERR-${labelUpper}-UNREACHABLE`);
    } finally {
      clearTimeout(timeout);
    }

    const body = (await res.json().catch(() => null)) as
      | { success?: boolean; data?: T; error?: { code?: string; message?: string } }
      | null;

    const missingRequiredData = options.requireData === true && (body?.data === undefined || body?.data === null);

    if (!res.ok || body?.success === false || missingRequiredData) {
      throw makeError(
        body?.error?.message ?? `${options.serviceLabel} internal API request failed with status ${res.status}`,
        res.status,
        body?.error?.code ?? 'ERR-UNKNOWN',
      );
    }

    return (body?.data ?? (body as unknown)) as T;
  }

  return { request };
}

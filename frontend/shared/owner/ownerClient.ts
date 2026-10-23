import { apiPath } from '../apiPath';
import {
  OWNER_BASE,
  OWNER_CANCELLED_CODE,
  OWNER_CANCELLED_TEXT,
  OWNER_HEADER,
  mapFailure,
  parseRefusal,
  type Failure,
  type Refusal,
  type Ticket,
} from './ownerLogic';

/**
 * The browser side of owner verification.
 *
 * `ownerFetch` is a drop-in for `fetch` on a request the server may refuse with "this needs the owner's authorisation". It sends
 * the request; on that refusal it asks the verification dialog (mounted once, in the admin layout) to run the owner through the
 * steps, then sends the IDENTICAL request again with the one-use authorisation in a header. Anything else comes straight back.
 */

export type AuthoriseResult = { kind: 'ticket'; ticket: Ticket } | { kind: 'cancelled' } | { kind: 'not-enrolled' };
export type Authoriser = (refusal: Refusal) => Promise<AuthoriseResult>;

let authoriser: Authoriser | null = null;

/** The dialog provider registers itself here. Returns the function that unregisters it. */
export function registerOwnerAuthoriser(next: Authoriser): () => void {
  authoriser = next;
  return () => {
    if (authoriser === next) authoriser = null;
  };
}

/** One refusal, one dialog, one retry; a second refusal (the authorisation was used up or lapsed) gets one more go, then the answer is returned as it is. */
const MAX_ROUNDS = 3;

function cancelledResponse(): Response {
  return new Response(JSON.stringify({ error: { code: OWNER_CANCELLED_CODE, message: OWNER_CANCELLED_TEXT } }), {
    status: 403,
    headers: { 'Content-Type': 'application/json', 'X-Owner-Cancelled': '1' },
  });
}

/** True for the answer `ownerFetch` returns when the owner closed the dialog: a refusal, but not one to report as an error twice. */
export function isOwnerCancelled(res: Response): boolean {
  return res.headers.get('X-Owner-Cancelled') === '1';
}

async function refusalOf(res: Response): Promise<Refusal | null> {
  if (res.status !== 403) return null;
  const body: unknown = await res.clone().json().catch(() => null);
  return parseRefusal(res.status, body);
}

/** `fetch` that handles the owner's authorisation. A root-relative `input` is given the app's base path (already-prefixed ones pass through). */
export async function ownerFetch(input: string, init: RequestInit = {}): Promise<Response> {
  const url = apiPath(input);
  let res = await fetch(url, init);
  for (let round = 0; round < MAX_ROUNDS; round += 1) {
    const refusal = await refusalOf(res);
    if (!refusal || !authoriser) return res;
    const outcome = await authoriser(refusal);
    if (outcome.kind === 'cancelled') return cancelledResponse();
    if (outcome.kind === 'not-enrolled') return res;
    const headers = new Headers(init.headers);
    headers.set(OWNER_HEADER, outcome.ticket.ticket);
    res = await fetch(url, { ...init, headers });
  }
  return res;
}

// ---------------------------------------------------------------------------------------------------------------------
// The verification endpoints themselves
// ---------------------------------------------------------------------------------------------------------------------

export class OwnerCallError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code: string,
    public readonly extras: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'OwnerCallError';
  }
  toFailure(): Failure {
    return mapFailure(this.status, this.code, this.message, this.extras);
  }
}

export function toFailure(err: unknown): Failure {
  return err instanceof OwnerCallError ? err.toFailure() : mapFailure(0, 'ERR-NETWORK', '');
}

async function call<T>(path: string, init: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(apiPath(`${OWNER_BASE}${path}`), { ...init, cache: 'no-store' });
  } catch {
    throw new OwnerCallError('', 0, 'ERR-NETWORK', {});
  }
  const json = (await res.json().catch(() => ({}))) as { data?: T; error?: Record<string, unknown> };
  if (!res.ok || json.error) {
    const e = json.error ?? {};
    throw new OwnerCallError(typeof e.message === 'string' ? e.message : '', res.status, typeof e.code === 'string' ? e.code : 'ERR-REQUEST', e);
  }
  return json.data as T;
}

export function ownerGet<T>(path: string): Promise<T> {
  return call<T>(path, { method: 'GET' });
}

export function ownerPost<T>(path: string, body: Record<string, unknown>): Promise<T> {
  return call<T>(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}

/** A CSRF token for the verification endpoints (this call also sets the cookie it is checked against). */
export async function fetchOwnerCsrf(): Promise<string> {
  return (await ownerGet<{ csrf: string }>('/csrf')).csrf;
}

/** True when a refused call looks like a CSRF mismatch, so the caller can fetch a fresh token and try once more. */
export function isCsrfProblem(err: unknown): boolean {
  return err instanceof OwnerCallError && err.status === 403 && /csrf/i.test(err.code);
}

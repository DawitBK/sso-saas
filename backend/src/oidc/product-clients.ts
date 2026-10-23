/**
 * Extra OIDC clients and portal tiles for applications that sign in through this IdP but are not one of the three built-in systems (EDAMS, GMS, portal).
 *
 * Both lists come from the environment as JSON and are EMPTY unless set, so a deployment that sets nothing registers nothing (the Example Corp production
 * and mirror environments set nothing). Every secret and address is explicit: there are no fallbacks, a malformed list is a startup error, and the
 * production safety check (assertProdSafeDefaults) covers these clients exactly like the built-in ones (no dev secret, no localhost address).
 *
 *   PRODUCT_CLIENTS_JSON  [{ "client_id", "client_secret", "redirect_uris": [...], "post_logout_redirect_uris": [...], "name", "backchannel_logout_uri"? }]
 *   PRODUCT_APPS_JSON     [{ "rp", "label", "name", "url" }]   one launcher tile per application (rp = the client id)
 *   MOS_ENABLED=true      also registers the client "mos" (MOS_CLIENT_SECRET, MOS_REDIRECT_URIS, MOS_LOGOUT_URIS, all required) and, when MOS_PORTAL_URL is set,
 *                         its tile; MOS_BACKCHANNEL_LOGOUT_URI (optional) is where it is told that someone signed out; see config.ts and portal/catalog.ts
 */

export interface ProductClient {
  client_id: string;
  client_secret: string;
  scope: string;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  name: string;
  /** Where this IdP POSTs a signed logout token when the person's SSO session ends (server to server, so loopback is fine). Optional. */
  backchannel_logout_uri?: string;
}

export interface ProductTile {
  rp: string;
  label: string;
  name: string;
  url: string;
}

/** Ids that already mean something: the built-in systems and MOS. A product client may not take one of them over. */
const RESERVED_IDS = new Set(['edams', 'gms', 'portal', 'mos', 'idp-admin']);
const ID_RE = /^[a-z0-9][a-z0-9_-]{1,63}$/;
const MIN_SECRET_LENGTH = 16;

function parseList(raw: string | undefined, variable: string): unknown[] {
  if (raw === undefined || raw.trim() === '') return [];
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error(`${variable} is not valid JSON`);
  }
  if (!Array.isArray(value)) throw new Error(`${variable} must be a JSON list`);
  return value;
}

const isText = (v: unknown): v is string => typeof v === 'string' && v.trim() !== '';
const isTextList = (v: unknown): v is string[] => Array.isArray(v) && v.every(isText);

export function parseProductClients(raw: string | undefined): ProductClient[] {
  const seen = new Set<string>();
  return parseList(raw, 'PRODUCT_CLIENTS_JSON').map((entry, i) => {
    const where = `PRODUCT_CLIENTS_JSON[${i}]`;
    const c = (entry && typeof entry === 'object' ? entry : {}) as Record<string, unknown>;
    if (!isText(c.client_id) || !ID_RE.test(c.client_id)) throw new Error(`${where}: client_id must be lower-case letters, digits, "-" or "_" (2 to 64 characters)`);
    if (RESERVED_IDS.has(c.client_id)) throw new Error(`${where}: client_id "${c.client_id}" is reserved for a built-in system`);
    if (seen.has(c.client_id)) throw new Error(`${where}: client_id "${c.client_id}" is listed twice`);
    seen.add(c.client_id);
    if (!isText(c.client_secret) || c.client_secret.length < MIN_SECRET_LENGTH) throw new Error(`${where}: client_secret is required (at least ${MIN_SECRET_LENGTH} characters)`);
    if (!isText(c.name)) throw new Error(`${where}: name is required`);
    if (!isTextList(c.redirect_uris) || c.redirect_uris.length === 0) throw new Error(`${where}: redirect_uris must be a non-empty list of addresses`);
    if (!isTextList(c.post_logout_redirect_uris)) throw new Error(`${where}: post_logout_redirect_uris must be a list of addresses`);
    if (c.backchannel_logout_uri !== undefined && !(isText(c.backchannel_logout_uri) && /^https?:\/\//i.test(c.backchannel_logout_uri))) {
      throw new Error(`${where}: backchannel_logout_uri must be an http(s) address`);
    }
    return {
      client_id: c.client_id,
      client_secret: c.client_secret,
      scope: 'openid profile email',
      redirect_uris: c.redirect_uris,
      post_logout_redirect_uris: c.post_logout_redirect_uris,
      name: c.name,
      ...(c.backchannel_logout_uri !== undefined ? { backchannel_logout_uri: c.backchannel_logout_uri } : {}),
    };
  });
}

export function parseProductTiles(raw: string | undefined): ProductTile[] {
  const seen = new Set<string>();
  return parseList(raw, 'PRODUCT_APPS_JSON').map((entry, i) => {
    const where = `PRODUCT_APPS_JSON[${i}]`;
    const t = (entry && typeof entry === 'object' ? entry : {}) as Record<string, unknown>;
    if (!isText(t.rp) || !ID_RE.test(t.rp)) throw new Error(`${where}: rp must be the application's client id`);
    if (RESERVED_IDS.has(t.rp)) throw new Error(`${where}: rp "${t.rp}" is reserved for a built-in system`);
    if (seen.has(t.rp)) throw new Error(`${where}: rp "${t.rp}" is listed twice`);
    seen.add(t.rp);
    if (!isText(t.label) || !isText(t.name)) throw new Error(`${where}: label and name are required`);
    if (!isText(t.url) || !/^https?:\/\//i.test(t.url)) throw new Error(`${where}: url must be an http(s) address`);
    return { rp: t.rp, label: t.label, name: t.name, url: t.url };
  });
}

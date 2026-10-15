'use client';

import { useCallback, useEffect, useState, useSyncExternalStore } from 'react';
import toast from 'react-hot-toast';
import { Copy, KeyRound, Archive } from 'lucide-react';
import { apiPath } from '@shared/apiPath';
import { ErrorState, PageSkeleton } from '@shared/ui/States';
import { useConfirm } from '@shared/ui/Confirm';

/** `useSyncExternalStore` subscribe for a value that never changes after mount. */
const SUBSCRIBE_NEVER = () => () => {};

interface KeyPair {
  kid: string;
  isActive: boolean;
  createdAt: string;
  retiredAt: string | null;
  /** Still in the published JWKS — i.e. tokens signed with it still verify. */
  published: boolean;
}

interface KeysData {
  keys: KeyPair[];
  csrf: string;
  /** Only the platform administrator may rotate or withdraw keys. */
  canManage?: boolean;
}

export default function KeysPage() {
  const confirmDialog = useConfirm();
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [data, setData] = useState<KeysData | null>(null);
  // 403: this page is the platform administrator's alone.
  const [restricted, setRestricted] = useState(false);
  // /jwks is same-origin now (next.config.ts rewrites it to the backend) — no
  // backend field for this, it's a well-known static path, computed here.
  // apiPath() adds the /sso basePath in production — omitting it here would
  // display a technically-unreachable URL to admins (the real endpoint lives
  // under /sso/jwks, not the bare origin).
  //
  // Read through useSyncExternalStore rather than an effect that setStates the
  // origin in. window.location is browser-only state with a different value
  // during SSR, and this is React's supported way to express exactly that: the
  // server snapshot renders the relative path, hydration matches it, and the
  // absolute URL appears on the first client render. The previous effect did
  // the same thing by setting state synchronously in an effect body, which
  // react-hooks/set-state-in-effect rejects outright under eslint-config-next 16.
  const jwksUri = useSyncExternalStore(
    SUBSCRIBE_NEVER,
    () => `${window.location.origin}${apiPath('/jwks')}`,
    () => apiPath('/jwks'),
  );

  // Same split as admin/groups/detail and admin/users/[id]: `load` must not
  // raise the loading flag synchronously, because it is called from an effect
  // and react-hooks/set-state-in-effect is an error under eslint-config-next
  // 16. `loading` already starts `true` for the mount fetch; the post-rotation
  // reload goes through `refresh()`, an event handler, which may set it.
  //
  // Kept as a promise chain rather than async/await on purpose: the rule reads
  // every setState in an async function body — including one in a `finally`,
  // which can only run after an await — as synchronous, so the await form is
  // rejected here even though it is equivalent. In a `.then()` callback the
  // setState is unambiguously deferred and the rule is satisfied.
  const load = useCallback(() => {
    fetch(apiPath('/api/v1/admin/keys'))
      .then(async (res) => {
        const json = await res.json().catch(() => ({}));
        if (res.status === 403) setRestricted(true);
        return json;
      })
      .then((json) => {
        setData(json.data ?? null);
        setLoading(false);
      })
      .catch(() => {
        toast.error('Failed to load keys');
        setLoading(false);
      });
  }, []);

  const refresh = useCallback(() => {
    load();
  }, [load]);

  useEffect(() => {
    load();
  }, [load]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard');
  };

  // Both mutations already existed on the backend
  // (api/v1/admin-mutations.router.ts) and were audited and wired to
  // reloadProviderKeys — they simply had no button anywhere, which left key
  // rotation, the one control an identity provider must have on the day a
  // key is suspected compromised, reachable only by hand-crafting a request.
  async function mutate(path: string, successMsg: string) {
    if (!data) return;
    setBusy(true);
    try {
      const res = await fetch(apiPath(path), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ csrf: data.csrf }),
      });
      const json = await res.json();
      if (!res.ok) {
        toast.error(json?.error?.message ?? 'Request failed');
        return;
      }
      toast.success(successMsg);
      refresh();
    } catch {
      toast.error('Request failed');
    } finally {
      setBusy(false);
    }
  }

  async function handleRotate() {
    const ok = await confirmDialog({
      title: 'Rotate the signing key?',
      message: (
        <>
          <p>A new signing key becomes the active one. The current key stays published in JWKS as a retired key, so tokens already issued keep verifying.</p>
          <p>Nobody is signed out.</p>
        </>
      ),
      confirmLabel: 'Rotate signing key',
    });
    if (ok) void mutate('/api/v1/admin/keys/generate', 'New signing key is now active');
  }

  async function handleWithdraw(kid: string) {
    const ok = await confirmDialog({
      title: 'Withdraw this key now?',
      message: (
        <>
          <p>Key <code className="admin-code">{kid}</code> was rotated out but is still published so tokens signed just before the rotation keep working. Withdrawing it early removes it immediately: anyone still holding a token signed with it is signed out and must sign in again.</p>
          <p>Do this when the key is believed compromised. Otherwise let it expire on its own.</p>
        </>
      ),
      confirmLabel: 'Withdraw key',
      danger: true,
    });
    if (ok) void mutate(`/api/v1/admin/keys/${encodeURIComponent(kid)}/retire`, 'Key withdrawn from JWKS');
  }

  if (loading) {
    return <PageSkeleton rows={2} />;
  }

  if (restricted) {
    return (
      <>
        <div className="admin-page-header">
          <div>
            <h1>Signing Keys</h1>
          </div>
        </div>
        <div className="admin-card" role="note">
          <p className="admin-hint" style={{ margin: 0 }}>
            Signing keys are visible and managed by the platform administrator only. Rotating or
            withdrawing a key can sign every user out of every system, so this page sits above the IdP
            administrator group.
          </p>
        </div>
      </>
    );
  }

  if (!data) {
    return <ErrorState error={new Error('The page could not be loaded. Check your connection and try again.')} onRetry={() => window.location.reload()} title="Could not load keys" />;
  }

  return (
    <>
      <div className="admin-page-header">
        <div>
          <h1>Signing Keys</h1>
          <p>Public keys used to sign JWTs and verify tokens.</p>
        </div>
        {data.canManage ? (
          <button type="button" className="admin-btn" disabled={busy} onClick={() => void handleRotate()}>
            <KeyRound size={14} /> Rotate signing key
          </button>
        ) : null}
      </div>

      {!data.canManage && (
        <div className="admin-card" style={{ marginBottom: '18px' }} role="note">
          <p className="admin-hint" style={{ margin: 0 }}>
            Rotating or withdrawing a signing key is reserved to the platform administrator.
          </p>
        </div>
      )}

      <div className="admin-card" style={{ marginBottom: '18px' }}>
        <div className="admin-section-title" style={{ margin: '0 0 8px' }}>
          JWKS Endpoint
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <code className="admin-code" style={{ flex: 1, fontSize: '13px', padding: '8px 12px', borderRadius: 'var(--radius-md)' }}>
            {jwksUri}
          </code>
          <button
            onClick={() => copyToClipboard(jwksUri)}
            className="admin-btn secondary"
            style={{ flexShrink: 0 }}
          >
            <Copy size={14} />
          </button>
        </div>
        <p className="admin-hint">
          Every relying party (DMS, GMS, the portal) fetches this URL to verify tokens. Rotating adds
          a new active key and leaves the previous one published so in-flight tokens keep working;
          retiring removes a key from this document and invalidates anything still signed with it.
        </p>
      </div>

      <div className="admin-card">
        {data.keys.length === 0 ? (
          <p className="admin-empty-row">No keys found.</p>
        ) : (
          <table className="admin-table">
            <thead>
              <tr>
                <th>Key ID</th>
                <th>Algorithm</th>
                <th>Status</th>
                <th>In JWKS</th>
                <th>Created</th>
                <th>Retired</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {data.keys.map((key) => (
                <tr key={key.kid}>
                  <td>
                    <code className="admin-code">{key.kid}</code>
                  </td>
                  {/* Every key is RS256/RSA-2048 (jwks.ts's generateSigningKey) — no
                      per-key variation exists to show. */}
                  <td>RS256</td>
                  <td>
                    <span className={`admin-badge ${key.isActive ? 'on' : 'off'}`}>
                      {key.isActive ? 'Active' : 'Retired'}
                    </span>
                  </td>
                  <td>
                    {/* The column that actually answers "do tokens signed with
                        this key still work?" — which "Retired" alone does not. */}
                    <span className={`admin-badge ${key.published ? 'on' : 'off'}`}>
                      {key.published ? 'Published' : 'Withdrawn'}
                    </span>
                  </td>
                  <td style={{ color: 'var(--muted)' }}>
                    {new Date(key.createdAt).toLocaleDateString()}
                  </td>
                  <td style={{ color: 'var(--muted)' }}>
                    {key.retiredAt ? new Date(key.retiredAt).toLocaleDateString() : '—'}
                  </td>
                  <td>
                    {/* Offered only where it would do something: the active key
                        must be rotated rather than withdrawn (the backend
                        refuses it), and a key already out of the JWKS has
                        nothing left to withdraw. */}
                    {data.canManage && !key.isActive && key.published ? (
                      <button
                        type="button"
                        className="admin-btn danger"
                        disabled={busy}
                        onClick={() => void handleWithdraw(key.kid)}
                      >
                        <Archive size={13} /> Withdraw now
                      </button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}

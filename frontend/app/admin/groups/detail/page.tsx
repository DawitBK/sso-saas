'use client';

import { Suspense, useCallback, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import toast from 'react-hot-toast';
import { apiPath } from '@shared/apiPath';
import { ErrorState, PageSkeleton } from '@shared/ui/States';
import { useConfirm } from '@shared/ui/Confirm';
import { groupName } from '../groupName';

interface Member {
  id: string;
  email: string;
}
interface App {
  rp: string;
  label: string;
}
interface GroupDetailData {
  dn: string;
  members: Member[];
  entitled: string[];
  apps: App[];
  // Roles this group currently asserts (0, 1 or many — DMS's own user_roles
  // is many-to-many, so a group can legitimately grant more than one).
  selectedDmsRoles: string[];
  dmsError: string | null;
  dmsRoles: string[];
  gmsRole: string | null;
  gmsRoles: string[];
  csrf: string;
}

export default function GroupDetailPage() {
  return (
    <Suspense fallback={<PageSkeleton rows={2} />}>
      <GroupDetailInner />
    </Suspense>
  );
}

function GroupDetailInner() {
  const searchParams = useSearchParams();
  const dn = searchParams.get('dn') ?? '';
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<GroupDetailData | null>(null);
  const [entitledApps, setEntitledApps] = useState<Set<string>>(new Set());
  const [dmsRoles, setDmsRoles] = useState<Set<string>>(new Set());
  const [gmsRole, setGmsRole] = useState('');
  const [saving, setSaving] = useState(false);
  const confirm = useConfirm();

  // `load` deliberately does NOT raise the loading flag itself. It is called
  // from an effect, and react-hooks/set-state-in-effect — an ERROR under
  // eslint-config-next 16, only a lint warning before it — rejects a
  // synchronous setState in an effect body. `loading` already starts `true`,
  // which covers the mount fetch; the post-mutation path goes through
  // `refresh()`, which is an event handler and may set it freely.
  //
  // Kept as a promise chain rather than async/await on purpose: the rule reads
  // every setState in an async function body — including one in a `finally`,
  // which can only run after an await — as synchronous, so the await form is
  // rejected here even though it is equivalent.
  const load = useCallback(() => {
    fetch(apiPath(`/api/v1/admin/groups/detail?dn=${encodeURIComponent(dn)}`))
      .then((res) => res.json())
      .then((json) => {
        const body: GroupDetailData | undefined = json.data;
        setData(body ?? null);
        if (body) {
          setEntitledApps(new Set(body.entitled));
          setDmsRoles(new Set(body.selectedDmsRoles ?? []));
          setGmsRole(body.gmsRole ?? '');
        }
        setLoading(false);
      })
      .catch(() => {
        toast.error('Failed to load group');
        setLoading(false);
      });
  }, [dn]);

  const refresh = useCallback(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (dn) load();
  }, [dn, load]);

  const sameSet = (a: Set<string>, b: string[]) => a.size === b.length && b.every((x) => a.has(x));
  const accessChanged = data ? !sameSet(entitledApps, data.entitled) : false;
  const dmsChanged = data ? !sameSet(dmsRoles, data.selectedDmsRoles ?? []) : false;
  const gmsChanged = data ? gmsRole !== (data.gmsRole ?? '') : false;

  /** A change to what a group reaches signs its members out (the server does it, only when something really changed). Ask first, and say how many. */
  async function save(path: string, body: Record<string, unknown>, what: string) {
    const count = data?.members.length ?? 0;
    if (count > 0) {
      const sure = await confirm({
        title: `Save the ${what}?`,
        message: (
          <>
            <p>
              {count === 1 ? 'The 1 person' : `The ${count} people`} in this group will be signed out of every application now and will need to sign in again to get the new access.
            </p>
            <p>Nothing else about them changes.</p>
          </>
        ),
        confirmLabel: 'Save and sign them out',
        danger: true,
      });
      if (!sure) return;
    }
    await post(path, body);
  }

  async function post(path: string, body: Record<string, unknown>) {
    setSaving(true);
    try {
      const res = await fetch(apiPath(path), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...body, csrf: data?.csrf }),
      });
      const json = await res.json();
      if (!res.ok) {
        toast.error(json?.error?.message ?? 'Save failed');
      } else {
        toast.success('Saved');
        refresh();
      }
    } catch {
      toast.error('Save failed');
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <PageSkeleton rows={2} />;
  if (!data) return <ErrorState error={new Error('The page could not be loaded. Check your connection and try again.')} onRetry={() => window.location.reload()} title="Could not load group" />;

  return (
    <>
      <p className="sub" style={{ marginBottom: '6px' }}>
        <Link href="/admin/groups" className="admin-link">
          ← All groups
        </Link>
      </p>
      <div className="admin-page-header">
        <div>
          <h1 style={{ wordBreak: 'break-word' }}>{groupName(data.dn)}</h1>
          <p>
            {data.members.length} member{data.members.length === 1 ? '' : 's'} · <code className="admin-code" style={{ fontSize: 11, wordBreak: 'break-all' }}>{data.dn}</code>
          </p>
        </div>
      </div>

      <h2 className="admin-section-title">App access</h2>
      <div className="admin-card">
        <p className="sub" style={{ margin: '0 0 4px' }}>
          Which apps this group&apos;s members can see and open from the portal.
        </p>
        <div className="admin-checks" style={{ flexWrap: 'wrap' }}>
          {data.apps.map((a) => (
            <label key={a.rp}>
              <input
                type="checkbox"
                checked={entitledApps.has(a.rp)}
                onChange={(e) => {
                  const next = new Set(entitledApps);
                  if (e.target.checked) next.add(a.rp);
                  else next.delete(a.rp);
                  setEntitledApps(next);
                }}
              />
              {a.label}
            </label>
          ))}
        </div>
        <button
          type="button"
          className="admin-btn"
          disabled={saving || !accessChanged}
          onClick={() => save('/api/v1/admin/groups/entitlements', { dn: data.dn, rp: [...entitledApps] }, 'application access')}
        >
          {accessChanged ? 'Save access' : 'No changes to save'}
        </button>
      </div>

      <h2 className="admin-section-title">DMS (EDAMS) role(s)</h2>
      <div className="admin-card">
        {data.dmsError ? (
          <p style={{ margin: 0, color: 'var(--danger)' }}>{data.dmsError}</p>
        ) : (
          <>
            <p className="sub" style={{ margin: '0 0 4px' }}>
              The role(s) DMS assigns to this group&apos;s members when they sign in via SSO — a group can grant more
              than one role at once, same as DMS&apos;s own user-role assignment.
            </p>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', margin: '8px 0 4px' }}>
              <span className="sub">
                {dmsRoles.size}/{data.dmsRoles.length} selected — no role selected defaults to EMPLOYEE
              </span>
              <button
                type="button"
                className="admin-link"
                style={{ background: 'none', border: 'none', cursor: 'pointer' }}
                onClick={() =>
                  setDmsRoles(dmsRoles.size === data.dmsRoles.length ? new Set() : new Set(data.dmsRoles))
                }
              >
                {dmsRoles.size === data.dmsRoles.length ? 'Clear all' : 'Select all'}
              </button>
            </div>
            <div className="admin-checks" style={{ flexWrap: 'wrap', marginBottom: '10px' }}>
              {data.dmsRoles.map((r) => (
                <label key={r}>
                  <input
                    type="checkbox"
                    checked={dmsRoles.has(r)}
                    onChange={(e) => {
                      const next = new Set(dmsRoles);
                      if (e.target.checked) next.add(r);
                      else next.delete(r);
                      setDmsRoles(next);
                    }}
                  />
                  {r}
                </label>
              ))}
            </div>
            <button
              type="button"
              className="admin-btn"
              disabled={saving || !dmsChanged}
              onClick={() => save('/api/v1/admin/groups/dms-role', { dn: data.dn, roles: [...dmsRoles] }, 'DMS roles')}
            >
              {dmsChanged ? 'Save DMS role(s)' : 'No changes to save'}
            </button>
          </>
        )}
      </div>

      <h2 className="admin-section-title">GMS role</h2>
      <div className="admin-card">
        <p className="sub" style={{ margin: '0 0 4px' }}>
          The role the GMS token bridge mints for this group&apos;s members. Guests are never assigned here — they
          use GMS&apos;s own native sign-in.
        </p>
        <p className="sub" style={{ margin: '0 0 10px', color: 'var(--warning-text)' }}>
          admin / reception / host also need an office, which is set per-user (not per-group) — set it on each
          member&apos;s own user page.
        </p>
        <div style={{ display: 'flex', gap: '10px', alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div>
            <label className="admin-label" htmlFor="gms-role">
              Role
            </label>
            <select id="gms-role" value={gmsRole} onChange={(e) => setGmsRole(e.target.value)}>
              <option value="">— no role (defaults to guest) —</option>
              {data.gmsRoles.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </div>
          <button
            type="button"
            className="admin-btn"
            disabled={saving || !gmsChanged}
            onClick={() => save('/api/v1/admin/groups/gms-role', { dn: data.dn, role: gmsRole }, 'GMS role')}
          >
            {gmsChanged ? 'Save GMS role' : 'No changes to save'}
          </button>
        </div>
      </div>

      <h2 className="admin-section-title">Members</h2>
      <div className="admin-card">
        {data.members.length === 0 ? (
          <p className="admin-empty-row">No users are in this group yet.</p>
        ) : (
          <table className="admin-table">
            <thead>
              <tr>
                <th>Email</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {data.members.map((m) => (
                <tr key={m.id}>
                  <td>{m.email}</td>
                  <td style={{ textAlign: 'right' }}>
                    <Link href={`/admin/users/${m.id}`} className="admin-link">
                      Manage →
                    </Link>
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

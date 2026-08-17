'use client';

import { Suspense, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import toast from 'react-hot-toast';
import { apiPath } from '@shared/apiPath';

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
  dmsRole: string | null;
  dmsError: string | null;
  dmsRoles: string[];
  gmsRole: string | null;
  gmsRoles: string[];
  csrf: string;
}

export default function GroupDetailPage() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
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
  const [dmsRole, setDmsRole] = useState('');
  const [gmsRole, setGmsRole] = useState('');
  const [saving, setSaving] = useState(false);

  const load = () => {
    setLoading(true);
    fetch(apiPath(`/api/v1/admin/groups/detail?dn=${encodeURIComponent(dn)}`))
      .then((res) => res.json())
      .then((json) => {
        const body: GroupDetailData | undefined = json.data;
        setData(body ?? null);
        if (body) {
          setEntitledApps(new Set(body.entitled));
          setDmsRole(body.dmsRole ?? '');
          setGmsRole(body.gmsRole ?? '');
        }
        setLoading(false);
      })
      .catch(() => {
        toast.error('Failed to load group');
        setLoading(false);
      });
  };

  useEffect(() => {
    if (dn) load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dn]);

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
        load();
      }
    } catch {
      toast.error('Save failed');
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <div>Loading...</div>;
  if (!data) return <div>Failed to load group</div>;

  return (
    <>
      <p className="sub" style={{ marginBottom: '6px' }}>
        <Link href="/admin/groups" className="admin-link">
          ← All groups
        </Link>
      </p>
      <h1 style={{ fontSize: '16px', wordBreak: 'break-all' }}>
        <code className="admin-code">{data.dn}</code>
      </h1>
      <p className="sub" style={{ margin: '8px 0 20px' }}>
        {data.members.length} member{data.members.length === 1 ? '' : 's'}
      </p>

      <h2 style={{ fontSize: '16px', margin: '28px 0 10px' }}>App access</h2>
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
          disabled={saving}
          onClick={() => post('/api/v1/admin/groups/entitlements', { dn: data.dn, rp: [...entitledApps] })}
        >
          Save access
        </button>
      </div>

      <h2 style={{ fontSize: '16px', margin: '28px 0 10px' }}>DMS (EDAMS) role</h2>
      <div className="admin-card">
        {data.dmsError ? (
          <p className="admin-badge off" style={{ margin: 0 }}>
            {data.dmsError}
          </p>
        ) : (
          <>
            <p className="sub" style={{ margin: '0 0 4px' }}>
              The role DMS assigns to this group&apos;s members when they sign in via SSO.
            </p>
            <div style={{ display: 'flex', gap: '10px', alignItems: 'flex-end', flexWrap: 'wrap' }}>
              <div>
                <label className="admin-label" htmlFor="dms-role">
                  Role
                </label>
                <select id="dms-role" value={dmsRole} onChange={(e) => setDmsRole(e.target.value)}>
                  <option value="">— no role (defaults to EMPLOYEE) —</option>
                  {data.dmsRoles.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
              </div>
              <button
                type="button"
                className="admin-btn"
                disabled={saving}
                onClick={() => post('/api/v1/admin/groups/dms-role', { dn: data.dn, role: dmsRole })}
              >
                Save DMS role
              </button>
            </div>
          </>
        )}
      </div>

      <h2 style={{ fontSize: '16px', margin: '28px 0 10px' }}>GMS role</h2>
      <div className="admin-card">
        <p className="sub" style={{ margin: '0 0 4px' }}>
          The role the GMS token bridge mints for this group&apos;s members. Guests are never assigned here — they
          use GMS&apos;s own native sign-in.
        </p>
        <p className="sub" style={{ margin: '0 0 10px', color: '#b45309' }}>
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
            disabled={saving}
            onClick={() => post('/api/v1/admin/groups/gms-role', { dn: data.dn, role: gmsRole })}
          >
            Save GMS role
          </button>
        </div>
      </div>

      <h2 style={{ fontSize: '16px', margin: '28px 0 10px' }}>Members</h2>
      <div className="admin-card">
        {data.members.length === 0 ? (
          <p style={{ color: 'var(--muted)' }}>No users are in this group yet.</p>
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

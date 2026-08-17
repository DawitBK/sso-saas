'use client';

import { Suspense, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import toast from 'react-hot-toast';
import { apiPath } from '@shared/apiPath';

interface PermissionOption {
  value: string;
  label: string;
}
interface PermissionGroup {
  group: string;
  permissions: PermissionOption[];
}
interface DmsRoleDetailData {
  roleId: string;
  roleName: string;
  error: string | null;
  checked: string[];
  groups: PermissionGroup[];
  tenant: string;
  csrf: string;
}

export default function DmsRoleDetailPage() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <DmsRoleDetailInner />
    </Suspense>
  );
}

function DmsRoleDetailInner() {
  const searchParams = useSearchParams();
  const roleId = searchParams.get('roleId') ?? '';
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<DmsRoleDetailData | null>(null);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!roleId) return;
    fetch(apiPath(`/api/v1/admin/dms-roles/detail?roleId=${encodeURIComponent(roleId)}`))
      .then((res) => res.json())
      .then((json) => {
        const body: DmsRoleDetailData | undefined = json.data;
        setData(body ?? null);
        if (body) setChecked(new Set(body.checked));
        setLoading(false);
      })
      .catch(() => {
        toast.error('Failed to load role');
        setLoading(false);
      });
  }, [roleId]);

  async function save() {
    if (!data) return;
    setSaving(true);
    try {
      const res = await fetch(apiPath('/api/v1/admin/dms-roles/detail'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ roleId: data.roleId, permissions: [...checked], csrf: data.csrf }),
      });
      const json = await res.json();
      if (!res.ok) toast.error(json?.error?.message ?? 'Save failed');
      else toast.success('Role permissions saved');
    } catch {
      toast.error('Save failed');
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <div>Loading...</div>;
  if (!data) return <div>Failed to load role</div>;

  return (
    <>
      <p className="sub" style={{ marginBottom: '6px' }}>
        <Link href="/admin/dms-roles" className="admin-link">
          ← All DMS roles
        </Link>
      </p>
      <h1>{data.roleName || data.roleId}</h1>
      <p className="sub" style={{ margin: '8px 0 20px' }}>
        Default permissions for this role — tenant <code className="admin-code">{data.tenant}</code>.
      </p>

      <div className="admin-card">
        {data.error ? (
          <p style={{ margin: 0, color: 'var(--danger)' }}>{data.error}</p>
        ) : (
          <>
            <p className="sub" style={{ margin: '0 0 14px' }}>
              This is a full replace — every user with this role gets exactly this permission set, except users with
              their own per-user override (see &quot;Customize DMS permissions&quot; on their user page).
            </p>
            {data.groups.map((g) => (
              <div key={g.group} style={{ marginBottom: '14px' }}>
                <p
                  style={{
                    margin: '0 0 6px',
                    fontWeight: 700,
                    fontSize: '12px',
                    textTransform: 'uppercase',
                    letterSpacing: '.04em',
                    color: 'var(--muted)',
                  }}
                >
                  {g.group}
                </p>
                <div className="admin-checks" style={{ flexWrap: 'wrap' }}>
                  {g.permissions.map((p) => (
                    <label key={p.value}>
                      <input
                        type="checkbox"
                        checked={checked.has(p.value)}
                        onChange={(e) => {
                          const next = new Set(checked);
                          if (e.target.checked) next.add(p.value);
                          else next.delete(p.value);
                          setChecked(next);
                        }}
                      />
                      {p.label}
                    </label>
                  ))}
                </div>
              </div>
            ))}
            <button type="button" className="admin-btn" disabled={saving} onClick={save}>
              Save role permissions
            </button>
          </>
        )}
      </div>
    </>
  );
}

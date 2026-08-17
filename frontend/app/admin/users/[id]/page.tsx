'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import toast from 'react-hot-toast';
import { apiPath } from '@shared/apiPath';

interface User {
  id: string;
  email: string;
  given_name: string | null;
  family_name: string | null;
  is_active: boolean;
  source: string;
  must_change_password: boolean;
  totp_enabled: boolean;
}
interface LiveAppStatus {
  exists: boolean;
  id: string | null;
  roles: string[];
  officeId: number | null;
  active: boolean | null;
  error: string | null;
}
interface Access {
  dmsRole: string | null;
  dmsError: string | null;
  gmsRole: string | null;
  officeId: number | null;
}
interface Office {
  id: number;
  name: string;
}
interface PermissionOption {
  value: string;
  label: string;
}
interface PermissionGroup {
  group: string;
  permissions: PermissionOption[];
}
interface DmsPermissions {
  effective: string[];
}
interface HistoryEntry {
  actor_email: string;
  action: string;
  detail: unknown;
  created_at: string;
}
interface UserDetailData {
  user: User;
  groups: string[];
  knownGroups: string[];
  isAdmin: boolean;
  liveDms: LiveAppStatus;
  liveGms: LiveAppStatus;
  access: Access;
  offices: Office[];
  officesError: string | null;
  dmsPermissions: DmsPermissions | null;
  dmsPermissionsError: string | null;
  dmsPermissionGroups: PermissionGroup[];
  dmsRoles: string[];
  gmsRoles: string[];
  gmsOfficeScopedRoles: string[];
  dmsConnected: boolean;
  history: HistoryEntry[];
  csrf: string;
}

export default function UserDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<UserDetailData | null>(null);

  const [dmsRole, setDmsRole] = useState('');
  const [gmsRole, setGmsRole] = useState('');
  const [officeId, setOfficeId] = useState('');
  const [isAdminChecked, setIsAdminChecked] = useState(false);
  const [dmsPermsChecked, setDmsPermsChecked] = useState<Set<string>>(new Set());
  const [newGroupDn, setNewGroupDn] = useState('');
  const [tempPassword, setTempPassword] = useState('');
  const [saving, setSaving] = useState(false);

  const load = () => {
    setLoading(true);
    fetch(apiPath(`/api/v1/admin/users/${id}`))
      .then((res) => res.json())
      .then((json) => {
        const body: UserDetailData | undefined = json.data;
        setData(body ?? null);
        if (body) {
          setDmsRole(body.access.dmsRole ?? '');
          setGmsRole(body.access.gmsRole ?? '');
          setOfficeId(body.access.officeId ? String(body.access.officeId) : '');
          setIsAdminChecked(body.isAdmin);
          setDmsPermsChecked(new Set(body.dmsPermissions?.effective ?? []));
        }
        setLoading(false);
      })
      .catch(() => {
        toast.error('Failed to load user');
        setLoading(false);
      });
  };

  useEffect(() => {
    if (id) load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  async function post(path: string, body: Record<string, unknown>, successMsg = 'Saved') {
    if (!data) return false;
    setSaving(true);
    try {
      const res = await fetch(apiPath(path), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...body, csrf: data.csrf }),
      });
      const json = await res.json();
      if (!res.ok) {
        toast.error(json?.error?.message ?? 'Save failed');
        return false;
      }
      toast.success(successMsg);
      load();
      return true;
    } catch {
      toast.error('Save failed');
      return false;
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <div>Loading...</div>;
  if (!data) return <div>Failed to load user</div>;

  const { user } = data;
  const officeScoped = data.gmsOfficeScopedRoles.includes(gmsRole);

  return (
    <>
      <p className="sub" style={{ marginBottom: '6px' }}>
        <Link href="/admin/users" className="admin-link">
          ← All users
        </Link>
      </p>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h1>{user.email}</h1>
          <p className="sub" style={{ margin: '0 0 20px' }}>
            {[user.given_name, user.family_name].filter(Boolean).join(' ') || 'No name set'} ·{' '}
            <span className={`admin-badge ${user.is_active ? 'on' : 'off'}`}>{user.is_active ? 'Active' : 'Disabled'}</span>{' '}
            · source: {user.source}
          </p>
        </div>
        <button
          type="button"
          className={`admin-btn ${user.is_active ? 'danger' : 'secondary'}`}
          disabled={saving}
          onClick={() => post(`/api/v1/admin/users/${id}/toggle-active`, {})}
        >
          {user.is_active ? 'Disable account' : 'Re-enable account'}
        </button>
      </div>

      <h2 style={{ fontSize: '16px', margin: '28px 0 10px' }}>
        Live status in each system{' '}
        <span className="sub" style={{ fontWeight: 400, fontSize: '12px' }}>
          (authoritative — read from the app&apos;s own database)
        </span>
      </h2>
      <div className="admin-card">
        <p className="sub" style={{ margin: '0 0 12px' }}>
          Each system owns its users after their first sign-in. Roles revoked or granted inside DMS or GMS stick,
          apply to the next SSO login automatically, and are shown here.
        </p>
        {!user.is_active && (
          <p
            className="sub"
            style={{
              margin: '0 0 12px',
              padding: '10px 12px',
              background: '#fff7ed',
              border: '1px solid #fdba74',
              borderRadius: '6px',
              color: '#9a3412',
            }}
          >
            <strong>Note:</strong> disabling this account ends its IdP/portal session and stops new sign-ins, but a
            bearer token already issued to it before disabling is stateless and keeps working until it naturally
            expires — up to <strong>1 hour</strong> for a DMS access token or <strong>8 hours</strong> for a GMS one.
            &quot;Disabled&quot; here and &quot;Active&quot; in the tables below at the same time is expected during
            that window, not a sync bug.
          </p>
        )}
        <table className="admin-table">
          <thead>
            <tr>
              <th>System</th>
              <th>Account</th>
              <th>Current roles</th>
              <th>Office</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>DMS (EDAMS)</td>
              {data.liveDms.error ? (
                <td colSpan={3} style={{ color: 'var(--danger)' }}>
                  {data.liveDms.error}
                </td>
              ) : !data.liveDms.exists ? (
                <td colSpan={3} style={{ color: 'var(--muted)' }}>
                  Not provisioned yet — created automatically at first SSO sign-in.
                </td>
              ) : (
                <>
                  <td>
                    <span className={`admin-badge ${data.liveDms.active ? 'on' : 'off'}`}>
                      {data.liveDms.active ? 'Active' : 'Disabled'}
                    </span>
                  </td>
                  <td>
                    <strong>{data.liveDms.roles.length ? data.liveDms.roles.join(', ') : '(none)'}</strong>
                  </td>
                  <td style={{ color: 'var(--muted)' }}>—</td>
                </>
              )}
            </tr>
            <tr>
              <td>GMS</td>
              {data.liveGms.error ? (
                <td colSpan={3} style={{ color: 'var(--danger)' }}>
                  {data.liveGms.error}
                </td>
              ) : !data.liveGms.exists ? (
                <td colSpan={3} style={{ color: 'var(--muted)' }}>
                  Not provisioned yet — created automatically at first SSO sign-in.
                </td>
              ) : (
                <>
                  <td>
                    <span className={`admin-badge ${data.liveGms.active ? 'on' : 'off'}`}>
                      {data.liveGms.active ? 'Active' : 'Disabled'}
                    </span>
                  </td>
                  <td>
                    <strong>{data.liveGms.roles.length ? data.liveGms.roles.join(', ') : '(none)'}</strong>
                  </td>
                  <td>
                    {data.liveGms.officeId === null
                      ? '—'
                      : data.offices.find((o) => o.id === data.liveGms.officeId)?.name ?? `office #${data.liveGms.officeId}`}
                  </td>
                </>
              )}
            </tr>
          </tbody>
        </table>
      </div>

      <h2 style={{ fontSize: '16px', margin: '28px 0 10px' }}>
        Initial system access <span className="sub" style={{ fontWeight: 400, fontSize: '12px' }}>(first sign-in defaults)</span>
      </h2>
      <div className="admin-card">
        <p className="sub" style={{ margin: '0 0 14px' }}>
          The role each system assigns this user at their <strong>first</strong> SSO sign-in. Once provisioned, the
          system itself owns the assignment.
        </p>
        <div style={{ display: 'flex', gap: '10px', alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div>
            <label className="admin-label" htmlFor="dms_role">
              DMS (EDAMS) role
            </label>
            <select id="dms_role" value={dmsRole} onChange={(e) => setDmsRole(e.target.value)} disabled={!data.dmsConnected}>
              <option value="">— No access —</option>
              {data.dmsRoles.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="admin-label" htmlFor="gms_role">
              GMS role
            </label>
            <select id="gms_role" value={gmsRole} onChange={(e) => setGmsRole(e.target.value)}>
              <option value="">— No access —</option>
              {data.gmsRoles.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </div>
          {officeScoped && (
            <div>
              <label className="admin-label" htmlFor="office_id">
                Office <span style={{ fontWeight: 400 }}>(required for admin/reception/host)</span>
              </label>
              {data.officesError ? (
                <p style={{ color: 'var(--danger)', margin: 0 }}>{data.officesError}</p>
              ) : (
                <select id="office_id" value={officeId} onChange={(e) => setOfficeId(e.target.value)}>
                  <option value="">— Select an office —</option>
                  {data.offices.map((o) => (
                    <option key={o.id} value={o.id}>
                      {o.name}
                    </option>
                  ))}
                </select>
              )}
            </div>
          )}
          <div>
            <label className="admin-label" htmlFor="is_admin">
              IdP Administrator
            </label>
            <label style={{ fontWeight: 400, display: 'flex', alignItems: 'center', gap: '6px', margin: 0, padding: '9px 0' }}>
              <input
                type="checkbox"
                id="is_admin"
                checked={isAdminChecked}
                onChange={(e) => setIsAdminChecked(e.target.checked)}
              />{' '}
              Grant admin console access
            </label>
          </div>
          <button
            type="button"
            className="admin-btn"
            disabled={saving}
            onClick={() =>
              post(`/api/v1/admin/users/${id}/access`, {
                dms_role: dmsRole,
                gms_role: gmsRole,
                office_id: officeId || null,
                is_admin: isAdminChecked,
              })
            }
          >
            Save access
          </button>
        </div>
        <p className="sub" style={{ margin: '12px 0 0' }}>
          Initial defaults: DMS — <strong>{data.access.dmsRole || 'no access'}</strong> · GMS —{' '}
          <strong>{data.access.gmsRole || 'no access'}</strong>
          {data.access.gmsRole && data.access.officeId ? ` @ office #${data.access.officeId}` : ''}
        </p>
      </div>

      {data.access.dmsRole && data.liveDms.exists && (
        <>
          <h2 style={{ fontSize: '16px', margin: '28px 0 10px' }}>
            Customize DMS permissions{' '}
            <span className="sub" style={{ fontWeight: 400, fontSize: '12px' }}>
              (grants/revokes on top of the {data.access.dmsRole} role&apos;s defaults)
            </span>
          </h2>
          <div className="admin-card">
            {data.dmsPermissionsError ? (
              <p style={{ margin: 0, color: 'var(--danger)' }}>{data.dmsPermissionsError}</p>
            ) : data.dmsPermissions ? (
              <>
                <p className="sub" style={{ margin: '0 0 14px' }}>
                  Checked = this user effectively has the permission. Unchecking a role default revokes it for this
                  user only; checking an extra one grants it for this user only.
                </p>
                {data.dmsPermissionGroups.map((g) => (
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
                            checked={dmsPermsChecked.has(p.value)}
                            onChange={(e) => {
                              const next = new Set(dmsPermsChecked);
                              if (e.target.checked) next.add(p.value);
                              else next.delete(p.value);
                              setDmsPermsChecked(next);
                            }}
                          />
                          {p.label}
                        </label>
                      ))}
                    </div>
                  </div>
                ))}
                <button
                  type="button"
                  className="admin-btn"
                  disabled={saving}
                  onClick={() => post(`/api/v1/admin/users/${id}/dms-permissions`, { permissions: [...dmsPermsChecked] })}
                >
                  Save DMS permissions
                </button>
              </>
            ) : null}
          </div>
        </>
      )}

      <h2 style={{ fontSize: '16px', margin: '28px 0 10px' }}>Security</h2>
      <div className="admin-card">
        <p className="sub" style={{ margin: '0 0 12px' }}>
          Resetting the password signs the user out of everything (SSO, portal, GMS) and forces them to choose a new
          password at their next sign-in.
        </p>
        <div style={{ display: 'flex', gap: '10px', alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div>
            <label className="admin-label" htmlFor="reset_password">
              Temporary password
            </label>
            <input
              id="reset_password"
              type="text"
              autoComplete="off"
              required
              minLength={8}
              placeholder="At least 8 characters"
              style={{ width: '280px' }}
              value={tempPassword}
              onChange={(e) => setTempPassword(e.target.value)}
            />
          </div>
          <button
            type="button"
            className="admin-btn danger"
            disabled={saving || tempPassword.length < 8}
            onClick={async () => {
              const ok = await post(`/api/v1/admin/users/${id}/reset-password`, { password: tempPassword }, 'Password reset');
              if (ok) setTempPassword('');
            }}
          >
            Reset password &amp; sign out everywhere
          </button>
        </div>
        {user.must_change_password && (
          <p className="sub" style={{ margin: '12px 0 0', color: '#b45309' }}>
            A reset is pending — this user must set a new password at their next sign-in.
          </p>
        )}
        <hr style={{ border: 'none', borderTop: '1px solid var(--border)', margin: '16px 0' }} />
        <p className="sub" style={{ margin: '0 0 8px' }}>
          Two-factor auth: <strong>{user.totp_enabled ? 'ON' : 'off'}</strong>
          {!user.totp_enabled && <span style={{ color: 'var(--muted)' }}> (users enroll themselves at Portal → Security)</span>}
        </p>
        {user.totp_enabled && (
          <button type="button" className="admin-btn secondary" disabled={saving} onClick={() => post(`/api/v1/admin/users/${id}/mfa-reset`, {}, 'MFA reset')}>
            Remove two-factor auth (lost device)
          </button>
        )}
      </div>

      <h2 style={{ fontSize: '16px', margin: '28px 0 10px' }}>
        Change history <span className="sub" style={{ fontWeight: 400, fontSize: '12px' }}>(admin actions affecting this user)</span>
      </h2>
      <div className="admin-card">
        {data.history.length === 0 ? (
          <p style={{ color: 'var(--muted)' }}>No recorded changes yet.</p>
        ) : (
          <table className="admin-table">
            <thead>
              <tr>
                <th>When</th>
                <th>By</th>
                <th>Action</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {data.history.map((h, i) => (
                <tr key={i}>
                  <td style={{ color: 'var(--muted)', whiteSpace: 'nowrap' }}>{new Date(h.created_at).toLocaleString()}</td>
                  <td>{h.actor_email}</td>
                  <td>
                    <code className="admin-code">{h.action}</code>
                  </td>
                  <td style={{ color: 'var(--muted)', fontSize: '12px', wordBreak: 'break-all' }}>{JSON.stringify(h.detail)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <h2 style={{ fontSize: '16px', margin: '28px 0 10px' }}>
        Additional shared groups <span className="sub" style={{ fontWeight: 400, fontSize: '12px' }}>(advanced)</span>
      </h2>
      <div className="admin-card">
        <p className="sub" style={{ margin: '0 0 12px' }}>
          For AD groups or team-wide access shared by many users. Most users only need the System access section
          above.
        </p>
        {data.groups.length === 0 ? (
          <p style={{ color: 'var(--muted)', marginBottom: '14px' }}>Not in any additional group.</p>
        ) : (
          <table className="admin-table" style={{ marginBottom: '14px' }}>
            <thead>
              <tr>
                <th>Group</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {data.groups.map((g) => (
                <tr key={g}>
                  <td>
                    <code className="admin-code">{g}</code>{' '}
                    <Link href={`/admin/groups/detail?dn=${encodeURIComponent(g)}`} className="admin-link" style={{ marginLeft: '8px', fontSize: '12px' }}>
                      configure →
                    </Link>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <button
                      type="button"
                      className="admin-btn danger"
                      style={{ padding: '4px 10px', fontSize: '12px' }}
                      disabled={saving}
                      onClick={() => post(`/api/v1/admin/users/${id}/groups/remove`, { group_dn: g }, 'Removed')}
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <div style={{ display: 'flex', gap: '10px', alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div>
            <label className="admin-label" htmlFor="group_dn">
              Add to group
            </label>
            <select id="group_dn" style={{ width: '420px' }} value={newGroupDn} onChange={(e) => setNewGroupDn(e.target.value)}>
              <option value="">— Select a group —</option>
              {data.knownGroups.map((g) => (
                <option key={g} value={g}>
                  {g}
                </option>
              ))}
            </select>
          </div>
          <button
            type="button"
            className="admin-btn secondary"
            disabled={saving || !newGroupDn}
            onClick={async () => {
              const ok = await post(`/api/v1/admin/users/${id}/groups`, { group_dn: newGroupDn }, 'Added');
              if (ok) setNewGroupDn('');
            }}
          >
            Add
          </button>
        </div>
      </div>
    </>
  );
}

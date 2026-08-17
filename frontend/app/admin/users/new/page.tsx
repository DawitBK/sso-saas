'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import toast from 'react-hot-toast';
import { apiPath } from '@shared/apiPath';

interface RoleCatalog {
  dmsRoles: string[];
  gmsRoles: string[];
  gmsOfficeScopedRoles: string[];
}
interface Office {
  id: number;
  name: string;
}

export default function NewUserPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [catalog, setCatalog] = useState<RoleCatalog | null>(null);
  const [offices, setOffices] = useState<Office[]>([]);
  const [officesError, setOfficesError] = useState<string | null>(null);
  const [dmsConnected, setDmsConnected] = useState(false);
  const [csrf, setCsrf] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [email, setEmail] = useState('');
  const [givenName, setGivenName] = useState('');
  const [familyName, setFamilyName] = useState('');
  const [password, setPassword] = useState('');
  const [dmsRole, setDmsRole] = useState('');
  const [gmsRole, setGmsRole] = useState('');
  const [officeId, setOfficeId] = useState('');

  useEffect(() => {
    Promise.all([
      fetch(apiPath('/api/v1/admin/role-catalog')).then((r) => r.json()),
      fetch(apiPath('/api/v1/admin/offices')).then((r) => r.json()).catch(() => null),
    ])
      .then(([roleCatalogJson, officesJson]) => {
        setCatalog(roleCatalogJson.data ?? null);
        if (officesJson?.data) {
          setOffices(officesJson.data.offices ?? []);
        } else {
          setOfficesError('GMS_INTERNAL_API_KEY is not configured — offices cannot be listed.');
        }
        setDmsConnected(Boolean(roleCatalogJson.data?.dmsConnected));
        setCsrf(roleCatalogJson.data?.csrf ?? '');
        setLoading(false);
      })
      .catch(() => {
        toast.error('Failed to load form');
        setLoading(false);
      });
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError(null);
    try {
      const res = await fetch(apiPath('/api/v1/admin/users'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email,
          given_name: givenName,
          family_name: familyName,
          password,
          dms_role: dmsRole,
          gms_role: gmsRole,
          office_id: officeId || null,
          csrf,
        }),
      });
      const json = await res.json();
      if (!res.ok) {
        setError(json?.error?.message ?? 'Could not create user');
        setSaving(false);
        return;
      }
      toast.success('User created');
      router.push(`/admin/users/${json.data.id}`);
    } catch {
      setError('Could not create user');
      setSaving(false);
    }
  }

  if (loading || !catalog) return <div>Loading...</div>;

  const officeScoped = catalog.gmsOfficeScopedRoles.includes(gmsRole);

  return (
    <>
      <h1>Register a new user</h1>
      <p className="sub">
        For service accounts or staff without an AD account. AD users never need to be created here — they
        authenticate directly against LDAP.
      </p>

      <div className="admin-card" style={{ maxWidth: '520px' }}>
        {error && <div className="sso-error">{error}</div>}
        <form onSubmit={submit}>
          <label className="admin-label" htmlFor="email">
            Email
          </label>
          <input
            id="email"
            type="email"
            required
            autoFocus
            style={{ width: '100%' }}
            placeholder="person@examplecorp.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <label className="admin-label" htmlFor="given_name">
            First name
          </label>
          <input id="given_name" type="text" style={{ width: '100%' }} value={givenName} onChange={(e) => setGivenName(e.target.value)} />
          <label className="admin-label" htmlFor="family_name">
            Last name
          </label>
          <input id="family_name" type="text" style={{ width: '100%' }} value={familyName} onChange={(e) => setFamilyName(e.target.value)} />
          <label className="admin-label" htmlFor="password">
            Password
          </label>
          <input
            id="password"
            type="password"
            required
            minLength={8}
            style={{ width: '100%' }}
            placeholder="At least 8 characters"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />

          <h2 style={{ marginTop: '22px' }}>System access (optional — set now or later)</h2>
          <p className="sub" style={{ margin: '0 0 10px' }}>
            Pick which systems this user can sign into and what role they get in each.
          </p>

          <label className="admin-label" htmlFor="dms_role">
            DMS (EDAMS) role
          </label>
          <select id="dms_role" style={{ width: '100%' }} value={dmsRole} onChange={(e) => setDmsRole(e.target.value)} disabled={!dmsConnected}>
            <option value="">— No DMS access —</option>
            {catalog.dmsRoles.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
          {!dmsConnected && (
            <p className="sub" style={{ margin: '4px 0 0', color: 'var(--danger)' }}>
              DMS_INTERNAL_API_KEY is not configured — DMS access can&apos;t be set until it is.
            </p>
          )}

          <label className="admin-label" htmlFor="gms_role">
            GMS role
          </label>
          <select id="gms_role" style={{ width: '100%' }} value={gmsRole} onChange={(e) => setGmsRole(e.target.value)}>
            <option value="">— No GMS access —</option>
            {catalog.gmsRoles.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>

          {officeScoped && (
            <>
              <label className="admin-label" htmlFor="office_id">
                Office <span style={{ fontWeight: 400 }}>(required for admin/reception/host)</span>
              </label>
              {officesError ? (
                <p className="sub" style={{ color: 'var(--danger)' }}>
                  {officesError}
                </p>
              ) : (
                <select id="office_id" style={{ width: '100%' }} value={officeId} onChange={(e) => setOfficeId(e.target.value)}>
                  <option value="">— Select an office —</option>
                  {offices.map((o) => (
                    <option key={o.id} value={o.id}>
                      {o.name}
                    </option>
                  ))}
                </select>
              )}
            </>
          )}

          <div style={{ marginTop: '18px', display: 'flex', gap: '10px' }}>
            <button className="admin-btn" type="submit" disabled={saving}>
              Create user
            </button>
            <Link className="admin-btn secondary" href="/admin/users">
              Cancel
            </Link>
          </div>
        </form>
      </div>
    </>
  );
}

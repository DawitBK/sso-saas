"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import toast from "react-hot-toast";
import { apiPath } from "@shared/apiPath";
import { PageSkeleton } from '@shared/ui/States';

interface RoleCatalog {
  dmsRoles: string[];
  /** Whether this administrator may make the new person an IdP administrator (the platform administrator only). */
  canGrantIdpAdmin?: boolean;
  gmsRoles: string[];
  gmsOfficeScopedRoles: string[];
  /** What the server enforces (and the table also checks); the inputs below stop at the same numbers instead of carrying their own. */
  limits: { email: number; name: number; passwordMinLength: number; passwordMaxLength: number };
}
interface Office {
  id: number;
  name: string;
}
interface DmsDepartment {
  id: string;
  code: string;
  name: string;
  orgUnitId: string;
  orgUnitCode: string;
  orgUnitName: string;
}

export default function NewUserPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [catalog, setCatalog] = useState<RoleCatalog | null>(null);
  const [departments, setDepartments] = useState<DmsDepartment[]>([]);
  const [departmentsError, setDepartmentsError] = useState<string | null>(null);
  const [offices, setOffices] = useState<Office[]>([]);
  const [officesError, setOfficesError] = useState<string | null>(null);
  const [dmsConnected, setDmsConnected] = useState(false);
  const [csrf, setCsrf] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [email, setEmail] = useState("");
  const [givenName, setGivenName] = useState("");
  const [familyName, setFamilyName] = useState("");
  const [password, setPassword] = useState("");
  const [dmsRoles, setDmsRoles] = useState<Set<string>>(new Set());
  const [dmsDepartmentIds, setDmsDepartmentIds] = useState<Set<string>>(
    new Set(),
  );
  const [gmsRole, setGmsRole] = useState("");
  const [officeId, setOfficeId] = useState("");
  const [isIdpAdmin, setIsIdpAdmin] = useState(false);

  useEffect(() => {
    Promise.all([
      fetch(apiPath("/api/v1/admin/role-catalog")).then((r) => r.json()),
      fetch(apiPath("/api/v1/admin/offices"))
        .then((r) => r.json())
        .catch(() => null),
      fetch(apiPath("/api/v1/admin/dms-departments"))
        .then((r) => r.json())
        .catch(() => null),
    ])
      .then(([roleCatalogJson, officesJson, departmentsJson]) => {
        setCatalog(roleCatalogJson.data ?? null);
        if (officesJson?.data) {
          setOffices(officesJson.data.offices ?? []);
        } else {
          setOfficesError(
            "GMS_INTERNAL_API_KEY is not configured — offices cannot be listed.",
          );
        }
        setDmsConnected(Boolean(roleCatalogJson.data?.dmsConnected));
        if (departmentsJson?.data?.departments)
          setDepartments(departmentsJson.data.departments);
        else
          setDepartmentsError(
            departmentsJson?.error?.message ??
              "DMS departments could not be loaded.",
          );
        setCsrf(roleCatalogJson.data?.csrf ?? "");
        setLoading(false);
      })
      .catch(() => {
        toast.error("Failed to load form");
        setLoading(false);
      });
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setError(null);
    try {
      const res = await fetch(apiPath("/api/v1/admin/users"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          given_name: givenName,
          family_name: familyName,
          password,
          dms_role: [...dmsRoles],
          dms_department_ids: [...dmsDepartmentIds],
          gms_role: gmsRole,
          office_id: officeId || null,
          is_admin: catalog?.canGrantIdpAdmin ? isIdpAdmin : false,
          csrf,
        }),
      });
      const json = await res.json();
      if (!res.ok) {
        const problems: Array<{ message?: string }> = json?.error?.details ?? [];
        setError(
          problems.length > 1
            ? problems.map((p) => p.message).join(" ")
            : (json?.error?.message ?? "Could not create user"),
        );
        setSaving(false);
        return;
      }
      toast.success("User created");
      router.push(`/admin/users/${json.data.id}`);
    } catch {
      setError("Could not create user");
      setSaving(false);
    }
  }

  if (loading || !catalog) return <PageSkeleton rows={2} />;

  const officeScoped = catalog.gmsOfficeScopedRoles.includes(gmsRole);
  const departmentsByOrgUnit = departments.reduce<
    Record<string, DmsDepartment[]>
  >((groups, department) => {
    (groups[department.orgUnitId] ??= []).push(department);
    return groups;
  }, {});

  return (
    <>
      <div className="admin-page-header">
        <div>
          <h1>Register a new user</h1>
          <p>
            For service accounts or staff without an AD account. AD users never
            need to be created here — they authenticate directly against LDAP.
          </p>
        </div>
      </div>

      <div className="admin-card" style={{ maxWidth: "520px" }}>
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
            maxLength={catalog.limits.email}
            className="ui-input"
            placeholder="person@examplecorp.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <label className="admin-label" htmlFor="given_name">
            First name
          </label>
          <input
            id="given_name"
            type="text"
            maxLength={catalog.limits.name}
            className="ui-input"
            value={givenName}
            onChange={(e) => setGivenName(e.target.value)}
          />
          <label className="admin-label" htmlFor="family_name">
            Last name
          </label>
          <input
            id="family_name"
            type="text"
            maxLength={catalog.limits.name}
            className="ui-input"
            value={familyName}
            onChange={(e) => setFamilyName(e.target.value)}
          />
          <label className="admin-label" htmlFor="password">
            Temporary password
          </label>
          <input
            id="password"
            type="password"
            required
            minLength={catalog.limits.passwordMinLength}
            maxLength={catalog.limits.passwordMaxLength}
            className="ui-input"
            placeholder={`At least ${catalog.limits.passwordMinLength} characters`}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <p className="sub" style={{ margin: "4px 0 10px" }}>
            Give it to the person yourself. They must choose their own password
            at their first sign-in.
          </p>

          <h2 className="admin-section-title" style={{ marginTop: "22px" }}>
            System access{" "}
            <span style={{ textTransform: "none", fontWeight: 400 }}>
              (optional — set now or later)
            </span>
          </h2>
          <p className="sub" style={{ margin: "0 0 10px" }}>
            Pick which systems this user can sign into and what role they get in
            each.
          </p>
          <p className="sub" style={{ margin: "0 0 10px" }}>
            Shared groups are optional. They are only needed for team-wide
            AD/group access; a local account can be created with system access
            alone.
          </p>

          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <label
              className="admin-label"
              htmlFor="dms_role"
              style={{ margin: 0 }}
            >
              DMS (EDAMS) role(s)
            </label>
            {dmsConnected && catalog.dmsRoles.length > 0 && (
              <button
                type="button"
                className="admin-link"
                style={{
                  background: "none",
                  border: "none",
                  cursor: "pointer",
                }}
                onClick={() =>
                  setDmsRoles(
                    dmsRoles.size === catalog.dmsRoles.length
                      ? new Set()
                      : new Set(catalog.dmsRoles),
                  )
                }
              >
                {dmsRoles.size === catalog.dmsRoles.length
                  ? "Clear all"
                  : "Select all"}
              </button>
            )}
          </div>
          <div
            id="dms_role"
            className="admin-checks"
            style={{ flexWrap: "wrap" }}
          >
            {catalog.dmsRoles.map((r) => (
              <label key={r}>
                <input
                  type="checkbox"
                  checked={dmsRoles.has(r)}
                  disabled={!dmsConnected}
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
          <div style={{ marginTop: "14px" }}>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: "8px",
              }}
            >
              <label className="admin-label" style={{ margin: 0 }}>
                DMS departments{" "}
                <span style={{ textTransform: "none", fontWeight: 400 }}>
                  (optional)
                </span>
              </label>
              {departments.length > 0 && (
                <button
                  type="button"
                  className="admin-link"
                  style={{
                    background: "none",
                    border: "none",
                    cursor: "pointer",
                    fontSize: "12px",
                  }}
                  onClick={() =>
                    setDmsDepartmentIds(
                      dmsDepartmentIds.size === departments.length
                        ? new Set()
                        : new Set(departments.map((d) => d.id)),
                    )
                  }
                >
                  {dmsDepartmentIds.size === departments.length
                    ? "Clear all"
                    : "Select all"}
                </button>
              )}
            </div>
            <p className="sub" style={{ margin: "4px 0 8px" }}>
              Departments control DMS membership and document scope. They can be
              assigned before first sign-in and will be applied when DMS
              provisions the account.
            </p>
            {departmentsError ? (
              <p className="sub" style={{ color: "var(--danger)" }}>
                {departmentsError}
              </p>
            ) : departments.length === 0 ? (
              <p className="sub">No active DMS departments are available.</p>
            ) : (
              Object.entries(departmentsByOrgUnit).map(([orgUnitId, items]) => (
                <div key={orgUnitId} style={{ marginBottom: "10px" }}>
                  <div
                    className="sub"
                    style={{ fontWeight: 700, marginBottom: "4px" }}
                  >
                    {items[0].orgUnitCode} · {items[0].orgUnitName}
                  </div>
                  <div className="admin-checks" style={{ flexWrap: "wrap" }}>
                    {items.map((department) => (
                      <label key={department.id}>
                        <input
                          type="checkbox"
                          checked={dmsDepartmentIds.has(department.id)}
                          disabled={!dmsConnected || dmsRoles.size === 0}
                          onChange={(e) => {
                            const next = new Set(dmsDepartmentIds);
                            if (e.target.checked) next.add(department.id);
                            else next.delete(department.id);
                            setDmsDepartmentIds(next);
                          }}
                        />
                        {department.code} · {department.name}
                      </label>
                    ))}
                  </div>
                </div>
              ))
            )}
          </div>
          {!dmsConnected && (
            <p
              className="sub"
              style={{ margin: "4px 0 0", color: "var(--danger)" }}
            >
              DMS_INTERNAL_API_KEY is not configured — DMS access can&apos;t be
              set until it is.
            </p>
          )}

          {catalog.canGrantIdpAdmin && (
            <div style={{ marginTop: "14px" }}>
              <label className="admin-label" htmlFor="is_admin">
                IdP administrator{" "}
                <span style={{ textTransform: "none", fontWeight: 400 }}>
                  (optional)
                </span>
              </label>
              <label
                style={{
                  fontWeight: 400,
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  margin: 0,
                  padding: "6px 0",
                }}
              >
                <input
                  type="checkbox"
                  id="is_admin"
                  checked={isIdpAdmin}
                  onChange={(e) => setIsIdpAdmin(e.target.checked)}
                />{" "}
                Grant admin console access
              </label>
              <p className="admin-hint" style={{ margin: "0 0 8px" }}>
                A limited administrator: users, groups, access, sessions, sign-ins and audit. They cannot see or change licences, tenants,
                signing keys, sign-in clients or who else is an administrator, and the platform administrator is invisible to them.
              </p>
            </div>
          )}

          <label className="admin-label" htmlFor="gms_role">
            GMS role
          </label>
          <select
            id="gms_role"
            className="ui-input"
            value={gmsRole}
            onChange={(e) => setGmsRole(e.target.value)}
          >
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
                Office{" "}
                <span style={{ fontWeight: 400 }}>
                  (required for admin/reception/host)
                </span>
              </label>
              {officesError ? (
                <p className="sub" style={{ color: "var(--danger)" }}>
                  {officesError}
                </p>
              ) : (
                <select
                  id="office_id"
                  className="ui-input"
                  value={officeId}
                  onChange={(e) => setOfficeId(e.target.value)}
                >
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

          <div style={{ marginTop: "18px", display: "flex", gap: "10px" }}>
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

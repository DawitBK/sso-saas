"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import toast from "react-hot-toast";
import { apiPath } from "@shared/apiPath";
import { ErrorState, PageSkeleton } from '@shared/ui/States';
import { useConfirm } from '@shared/ui/Confirm';
import { formatDateTime, timeAgo } from '@shared/lib/format';
import { loginReasonLabel } from '@shared/lib/loginReasons';
import { auditActionLabel } from '@shared/lib/auditLabels';

interface User {
  id: string;
  email: string;
  given_name: string | null;
  family_name: string | null;
  is_active: boolean;
  source: string;
  must_change_password: boolean;
  totp_enabled: boolean;
  failed_logins?: number;
  locked_until?: string | null;
  last_login_at?: string | null;
  created_at?: string;
}
interface LiveAppStatus {
  exists: boolean;
  id: string | null;
  roles: string[];
  departmentIds: string[];
  pendingDepartmentIds: string[];
  officeId: number | null;
  active: boolean | null;
  error: string | null;
}
interface Access {
  // 0, 1 or many — DMS's own user_roles is many-to-many, so this user's
  // groups/per-user override can legitimately grant more than one role.
  dmsRoles: string[];
  dmsError: string | null;
  gmsRole: string | null;
  officeId: number | null;
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
  /** True when this is the signed-in administrator's own account. */
  isSelf?: boolean;
  /** Only the platform administrator may change who is an IdP administrator. */
  canChangeAdminGroup?: boolean;
  liveDms: LiveAppStatus;
  liveGms: LiveAppStatus;
  access: Access;
  offices: Office[];
  officesError: string | null;
  dmsPermissions: DmsPermissions | null;
  dmsPermissionsError: string | null;
  dmsPermissionGroups: PermissionGroup[];
  dmsRoles: string[];
  dmsDepartments: DmsDepartment[];
  dmsDepartmentsError: string | null;
  gmsRoles: string[];
  gmsOfficeScopedRoles: string[];
  dmsConnected: boolean;
  history: HistoryEntry[];
  /** The account is locked out of signing in right now. */
  isLocked: boolean;
  recentLogins: Array<{ success: boolean; reason: string | null; ip: string | null; user_agent: string | null; created_at: string }>;
  /** Unspent two-factor recovery codes (a count only). */
  recoveryCodesRemaining: number;
  /** The platform setting for the shortest acceptable password. */
  passwordMinLength: number;
  csrf: string;
}

export default function UserDetailPage() {
  const { id } = useParams<{ id: string }>();
  const confirm = useConfirm();
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<UserDetailData | null>(null);

  const [dmsRoles, setDmsRoles] = useState<Set<string>>(new Set());
  const [dmsDepartmentIds, setDmsDepartmentIds] = useState<Set<string>>(
    new Set(),
  );
  const [gmsRole, setGmsRole] = useState("");
  const [officeId, setOfficeId] = useState("");
  const [isAdminChecked, setIsAdminChecked] = useState(false);
  const [dmsPermsChecked, setDmsPermsChecked] = useState<Set<string>>(
    new Set(),
  );
  const [newGroupDn, setNewGroupDn] = useState("");
  const [tempPassword, setTempPassword] = useState("");
  const [givenName, setGivenName] = useState("");
  const [familyName, setFamilyName] = useState("");
  const [saving, setSaving] = useState(false);

  // See the matching note in admin/groups/detail: `load` must not raise the
  // loading flag synchronously, because it is called from an effect and
  // react-hooks/set-state-in-effect is an error under eslint-config-next 16.
  // `loading` starts `true` for the mount fetch; `refresh()` covers the
  // post-mutation reload from an event handler. The promise-chain form is also
  // deliberate — see the longer note in admin/groups/detail.
  const load = useCallback(() => {
    fetch(apiPath(`/api/v1/admin/users/${id}`))
      .then((res) => res.json())
      .then((json) => {
        const body: UserDetailData | undefined = json.data;
        setData(body ?? null);
        if (body) {
          setDmsRoles(new Set(body.access.dmsRoles ?? []));
          setDmsDepartmentIds(
            new Set(
              body.liveDms.exists
                ? body.liveDms.departmentIds
                : body.liveDms.pendingDepartmentIds,
            ),
          );
          setGmsRole(body.access.gmsRole ?? "");
          setOfficeId(body.access.officeId ? String(body.access.officeId) : "");
          setIsAdminChecked(body.isAdmin);
          setDmsPermsChecked(new Set(body.dmsPermissions?.effective ?? []));
          setGivenName(body.user.given_name ?? "");
          setFamilyName(body.user.family_name ?? "");
        }
        setLoading(false);
      })
      .catch(() => {
        toast.error("Failed to load user");
        setLoading(false);
      });
  }, [id]);

  const refresh = useCallback(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (id) load();
  }, [id, load]);

  async function post(
    path: string,
    body: Record<string, unknown>,
    successMsg = "Saved",
    method: "POST" | "PUT" = "POST",
  ) {
    if (!data) return false;
    setSaving(true);
    try {
      const res = await fetch(apiPath(path), {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...body, csrf: data.csrf }),
      });
      const json = await res.json();
      if (!res.ok) {
        toast.error(json?.error?.message ?? "Save failed");
        return false;
      }
      toast.success(successMsg);
      // The server can attach a warning to a success (e.g. a disable that did not reach DMS or GMS).
      if (typeof json?.data?.warning === "string") {
        toast.error(json.data.warning, { duration: 15000 });
      }
      refresh();
      return true;
    } catch {
      toast.error("Save failed");
      return false;
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <PageSkeleton rows={2} />;
  if (!data) return <ErrorState error={new Error('The page could not be loaded. Check your connection and try again.')} onRetry={() => window.location.reload()} title="Could not load user" />;

  const { user } = data;
  const officeScoped = data.gmsOfficeScopedRoles.includes(gmsRole);
  const departmentsByOrgUnit = data.dmsDepartments.reduce<
    Record<string, DmsDepartment[]>
  >((groups, department) => {
    (groups[department.orgUnitId] ??= []).push(department);
    return groups;
  }, {});

  return (
    <>
      <p className="sub" style={{ marginBottom: "6px" }}>
        <Link href="/admin/users" className="admin-link">
          ← All users
        </Link>
      </p>
      <div className="admin-page-header">
        <div>
          <h1>{user.email}</h1>
          <p>
            {[user.given_name, user.family_name].filter(Boolean).join(" ") ||
              "No name set"}{" "}
            ·{" "}
            <span className={`admin-badge ${user.is_active ? "on" : "off"}`}>
              {user.is_active ? "Active" : "Disabled"}
            </span>{" "}
            · source: {user.source}
          </p>
        </div>
        <button
          type="button"
          className={`admin-btn ${user.is_active ? "danger" : "secondary"}`}
          disabled={saving || Boolean(data.isSelf)}
          title={
            data.isSelf
              ? "You cannot disable your own account — ask another administrator."
              : undefined
          }
          onClick={() => post(`/api/v1/admin/users/${id}/toggle-active`, {})}
        >
          {user.is_active ? "Disable account" : "Re-enable account"}
        </button>
      </div>

      {/* PUT /api/v1/admin/users/:id has always accepted given_name/family_name;
          nothing in the console called it, so a name typed wrong at creation
          (or arriving badly from a directory import) could never be corrected
          from the UI — and the name is what every other system displays after
          it JIT-provisions the account from the id_token. */}
      <h2 className="admin-section-title">Profile</h2>
      <div className="admin-card">
        <div
          style={{
            display: "flex",
            gap: "12px",
            flexWrap: "wrap",
            alignItems: "flex-end",
          }}
        >
          <label
            style={{
              display: "flex",
              flexDirection: "column",
              gap: "4px",
              flex: "1 1 180px",
            }}
          >
            <span className="sub">First name</span>
            <input
              className="ui-input"
              value={givenName}
              disabled={saving}
              onChange={(e) => setGivenName(e.target.value)}
            />
          </label>
          <label
            style={{
              display: "flex",
              flexDirection: "column",
              gap: "4px",
              flex: "1 1 180px",
            }}
          >
            <span className="sub">Last name</span>
            <input
              className="ui-input"
              value={familyName}
              disabled={saving}
              onChange={(e) => setFamilyName(e.target.value)}
            />
          </label>
          <button
            type="button"
            className="admin-btn"
            disabled={
              saving ||
              (givenName === (user.given_name ?? "") &&
                familyName === (user.family_name ?? ""))
            }
            onClick={() =>
              post(
                `/api/v1/admin/users/${id}`,
                { given_name: givenName, family_name: familyName },
                "Profile updated",
                "PUT",
              )
            }
          >
            Save profile
          </button>
        </div>
        <p className="admin-hint">
          The email address is the account&apos;s identity across DMS, GMS and
          the portal and cannot be changed here — create a new account and
          disable this one instead.
        </p>
      </div>

      <h2 className="admin-section-title">
        Live status in each system{" "}
        <span style={{ textTransform: "none", fontWeight: 400 }}>
          (authoritative — read from the app&apos;s own database)
        </span>
      </h2>
      <div className="admin-card">
        <p className="sub" style={{ margin: "0 0 12px" }}>
          These rows are each system&apos;s own record of this person, read from
          its database. SSO applies its list of roles (&quot;System access
          assigned by SSO&quot;, below) at every sign-in. A role edit made
          inside DMS stands only while SSO&apos;s list for this person is
          unchanged since; when SSO&apos;s list changes, SSO&apos;s list is
          applied again at the next sign-in.
        </p>
        {!user.is_active && (
          <p
            className="sub"
            style={{
              margin: "0 0 12px",
              padding: "10px 12px",
              background: "var(--warning-bg)",
              border: "1px solid var(--warning-border)",
              borderRadius: "var(--radius-md)",
              color: "var(--warning-text)",
            }}
          >
            <strong>Note:</strong> disabling this account has already ended its
            SSO, portal and GMS sessions and stops every new sign-in. DMS keeps
            its own tokens, so SSO sends it a signed notice to end this
            person&apos;s sessions (tried up to three times); if the console
            warned you that DMS or GMS could not be reached, that system may
            keep an existing session until its token expires, and you should
            sign the person out there by hand. The Audit entry for the
            disable records whether DMS confirmed. The tables below are each
            system&apos;s own record, which SSO does not edit, so
            &quot;Active&quot; there beside &quot;Disabled&quot; here is
            expected and is not a sync bug.
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
                <td colSpan={3} style={{ color: "var(--danger)" }}>
                  {data.liveDms.error}
                </td>
              ) : !data.liveDms.exists ? (
                <td colSpan={3} style={{ color: "var(--muted)" }}>
                  Not provisioned yet — created automatically at first SSO
                  sign-in.
                </td>
              ) : (
                <>
                  <td>
                    <span
                      className={`admin-badge ${data.liveDms.active ? "on" : "off"}`}
                    >
                      {data.liveDms.active ? "Active" : "Disabled"}
                    </span>
                  </td>
                  <td>
                    <strong>
                      {data.liveDms.roles.length
                        ? data.liveDms.roles.join(", ")
                        : "(none)"}
                    </strong>
                    {data.liveDms.departmentIds.length > 0 && (
                      <div className="sub" style={{ marginTop: "4px" }}>
                        Departments:{" "}
                        {data.liveDms.departmentIds
                          .map(
                            (departmentId) =>
                              data.dmsDepartments.find(
                                (department) => department.id === departmentId,
                              )?.code ?? departmentId,
                          )
                          .join(", ")}
                      </div>
                    )}
                    {data.access.dmsRoles.length > 0 &&
                      data.access.dmsRoles.join(",") !==
                        data.liveDms.roles.join(",") && (
                        <div
                          className="sub"
                          style={{
                            marginTop: "4px",
                            color: "var(--warning-text)",
                          }}
                        >
                          SSO will assign at next sign-in:{" "}
                          {data.access.dmsRoles.join(", ")}
                        </div>
                      )}
                  </td>
                  <td style={{ color: "var(--muted)" }}>—</td>
                </>
              )}
            </tr>
            <tr>
              <td>GMS</td>
              {data.liveGms.error ? (
                <td colSpan={3} style={{ color: "var(--danger)" }}>
                  {data.liveGms.error}
                </td>
              ) : !data.liveGms.exists ? (
                <td colSpan={3} style={{ color: "var(--muted)" }}>
                  Not provisioned yet — created automatically at first SSO
                  sign-in.
                </td>
              ) : (
                <>
                  <td>
                    <span
                      className={`admin-badge ${data.liveGms.active ? "on" : "off"}`}
                    >
                      {data.liveGms.active ? "Active" : "Disabled"}
                    </span>
                  </td>
                  <td>
                    <strong>
                      {data.liveGms.roles.length
                        ? data.liveGms.roles.join(", ")
                        : "(none)"}
                    </strong>
                    {data.access.gmsRole &&
                      data.access.gmsRole !== data.liveGms.roles[0] && (
                        <div
                          className="sub"
                          style={{
                            marginTop: "4px",
                            color: "var(--warning-text)",
                          }}
                        >
                          SSO will assign at next sign-in: {data.access.gmsRole}
                        </div>
                      )}
                  </td>
                  <td>
                    {data.liveGms.officeId === null
                      ? "—"
                      : (data.offices.find(
                          (o) => o.id === data.liveGms.officeId,
                        )?.name ?? `office #${data.liveGms.officeId}`)}
                  </td>
                </>
              )}
            </tr>
          </tbody>
        </table>
      </div>

      <h2 className="admin-section-title">
        System access assigned by SSO{" "}
        <span style={{ textTransform: "none", fontWeight: 400 }}>
          (applied at every sign-in)
        </span>
      </h2>
      <div className="admin-card">
        <p className="sub" style={{ margin: "0 0 14px" }}>
          The roles and office SSO sends to each system for this person. DMS
          applies this list at <strong>every</strong> sign-in: SSO&apos;s list
          wins, unless a DMS administrator edited this person&apos;s roles
          inside DMS and SSO&apos;s list has not changed since, in which case
          the DMS edit stands until SSO&apos;s list next changes. When a save
          changes something, the person is{" "}
          <strong>signed out of everything</strong> so it applies at their next
          sign-in. Saving does not delete documents or app-owned history.
        </p>
        <div
          style={{
            display: "flex",
            gap: "10px",
            alignItems: "flex-start",
            flexWrap: "wrap",
          }}
        >
          <div>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: "8px",
              }}
            >
              <label
                className="admin-label"
                htmlFor="dms_role"
                style={{ margin: 0 }}
              >
                DMS (EDAMS) role(s)
              </label>
              {data.dmsConnected && data.dmsRoles.length > 0 && (
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
                    setDmsRoles(
                      dmsRoles.size === data.dmsRoles.length
                        ? new Set()
                        : new Set(data.dmsRoles),
                    )
                  }
                >
                  {dmsRoles.size === data.dmsRoles.length
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
              {data.dmsRoles.map((r) => (
                <label key={r}>
                  <input
                    type="checkbox"
                    checked={dmsRoles.has(r)}
                    disabled={!data.dmsConnected}
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
            <div style={{ marginTop: "14px", flexBasis: "100%" }}>
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
                    (optional; tenant-scoped)
                  </span>
                </label>
                {data.dmsDepartments.length > 0 && (
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
                        dmsDepartmentIds.size === data.dmsDepartments.length
                          ? new Set()
                          : new Set(
                              data.dmsDepartments.map(
                                (department) => department.id,
                              ),
                            ),
                      )
                    }
                  >
                    {dmsDepartmentIds.size === data.dmsDepartments.length
                      ? "Clear all"
                      : "Select all"}
                  </button>
                )}
              </div>
              <p className="sub" style={{ margin: "4px 0 8px" }}>
                This replaces only the SSO-managed DMS department set. Existing
                documents, ACLs, and app-owned data are preserved.
              </p>
              {data.dmsDepartmentsError ? (
                <p className="sub" style={{ color: "var(--danger)" }}>
                  {data.dmsDepartmentsError}
                </p>
              ) : (
                Object.entries(departmentsByOrgUnit).map(
                  ([orgUnitId, departments]) => (
                    <div key={orgUnitId} style={{ marginBottom: "10px" }}>
                      <div
                        className="sub"
                        style={{ fontWeight: 700, marginBottom: "4px" }}
                      >
                        {departments[0].orgUnitCode} ·{" "}
                        {departments[0].orgUnitName}
                      </div>
                      <div
                        className="admin-checks"
                        style={{ flexWrap: "wrap" }}
                      >
                        {departments.map((department) => (
                          <label key={department.id}>
                            <input
                              type="checkbox"
                              checked={dmsDepartmentIds.has(department.id)}
                              disabled={
                                !data.dmsConnected || dmsRoles.size === 0
                              }
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
                  ),
                )
              )}
              {!data.liveDms.exists && dmsDepartmentIds.size > 0 && (
                <p className="sub" style={{ color: "var(--warning-text)" }}>
                  Pending: these departments will be applied when the user first
                  signs in to DMS.
                </p>
              )}
            </div>
          </div>
          <div>
            <label className="admin-label" htmlFor="gms_role">
              GMS role
            </label>
            <select
              id="gms_role"
              value={gmsRole}
              onChange={(e) => setGmsRole(e.target.value)}
            >
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
                Office{" "}
                <span style={{ fontWeight: 400 }}>
                  (required for admin/reception/host)
                </span>
              </label>
              {data.officesError ? (
                <p style={{ color: "var(--danger)", margin: 0 }}>
                  {data.officesError}
                </p>
              ) : (
                <select
                  id="office_id"
                  value={officeId}
                  onChange={(e) => setOfficeId(e.target.value)}
                >
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
            <label
              style={{
                fontWeight: 400,
                display: "flex",
                alignItems: "center",
                gap: "6px",
                margin: 0,
                padding: "9px 0",
              }}
            >
              <input
                type="checkbox"
                id="is_admin"
                checked={isAdminChecked}
                disabled={!data.canChangeAdminGroup}
                onChange={(e) => setIsAdminChecked(e.target.checked)}
              />{" "}
              Grant admin console access
            </label>
            {!data.canChangeAdminGroup && (
              <p className="admin-hint" style={{ margin: "0 0 8px" }}>
                Who is an IdP administrator is decided by the platform administrator only.
              </p>
            )}
          </div>
          <button
            type="button"
            className="admin-btn"
            // Saving while DMS could not be read would post an EMPTY role/department
            // set (the form is filled from that read) and wipe the user's real access.
            disabled={saving || Boolean(data.access.dmsError) || Boolean(data.liveDms.error)}
            title={
              data.access.dmsError || data.liveDms.error
                ? "DMS could not be read, so this form is not showing the user's real DMS access. Reload once DMS is reachable."
                : undefined
            }
            onClick={() =>
              post(`/api/v1/admin/users/${id}/access`, {
                dms_role: [...dmsRoles],
                dms_department_ids: [...dmsDepartmentIds],
                gms_role: gmsRole,
                office_id: officeId || null,
                is_admin: isAdminChecked,
              })
            }
          >
            Save access
          </button>
        </div>
        <p className="sub" style={{ margin: "12px 0 0" }}>
          Initial defaults: DMS —{" "}
          <strong>
            {data.access.dmsRoles.length > 0
              ? data.access.dmsRoles.join(", ")
              : "no access"}
          </strong>{" "}
          · GMS — <strong>{data.access.gmsRole || "no access"}</strong>
          {data.access.gmsRole && data.access.officeId
            ? ` @ office #${data.access.officeId}`
            : ""}
        </p>
      </div>

      {data.access.dmsRoles.length > 0 && data.liveDms.exists && (
        <>
          <h2 className="admin-section-title">
            Customize DMS permissions{" "}
            <span style={{ textTransform: "none", fontWeight: 400 }}>
              (grants/revokes on top of the {data.access.dmsRoles.join(", ")}{" "}
              role&apos;s defaults)
            </span>
          </h2>
          <div className="admin-card">
            {data.dmsPermissionsError ? (
              <p style={{ margin: 0, color: "var(--danger)" }}>
                {data.dmsPermissionsError}
              </p>
            ) : data.dmsPermissions ? (
              <>
                <p className="sub" style={{ margin: "0 0 4px" }}>
                  Checked = this user effectively has the permission. Unchecking
                  a role default revokes it for this user only; checking an
                  extra one grants it for this user only.
                </p>
                {(() => {
                  const allPerms = data.dmsPermissionGroups.flatMap((g) =>
                    g.permissions.map((p) => p.value),
                  );
                  const allChecked =
                    allPerms.length > 0 &&
                    allPerms.every((p) => dmsPermsChecked.has(p));
                  return (
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "flex-end",
                        margin: "0 0 10px",
                      }}
                    >
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
                          setDmsPermsChecked(
                            allChecked ? new Set() : new Set(allPerms),
                          )
                        }
                      >
                        {allChecked ? "Clear all" : "Select all"} (
                        {dmsPermsChecked.size}/{allPerms.length})
                      </button>
                    </div>
                  );
                })()}
                {data.dmsPermissionGroups.map((g) => {
                  const groupValues = g.permissions.map((p) => p.value);
                  const groupChecked =
                    groupValues.length > 0 &&
                    groupValues.every((v) => dmsPermsChecked.has(v));
                  return (
                    <div key={g.group} style={{ marginBottom: "14px" }}>
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                          margin: "0 0 6px",
                        }}
                      >
                        <p
                          style={{
                            margin: 0,
                            fontWeight: 700,
                            fontSize: "12px",
                            textTransform: "uppercase",
                            letterSpacing: ".04em",
                            color: "var(--muted)",
                          }}
                        >
                          {g.group}
                        </p>
                        <button
                          type="button"
                          className="admin-link"
                          style={{
                            background: "none",
                            border: "none",
                            cursor: "pointer",
                            fontSize: "12px",
                          }}
                          onClick={() => {
                            const next = new Set(dmsPermsChecked);
                            if (groupChecked)
                              groupValues.forEach((v) => next.delete(v));
                            else groupValues.forEach((v) => next.add(v));
                            setDmsPermsChecked(next);
                          }}
                        >
                          {groupChecked ? "Clear group" : "Select group"}
                        </button>
                      </div>
                      <div
                        className="admin-checks"
                        style={{ flexWrap: "wrap" }}
                      >
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
                  );
                })}
                <button
                  type="button"
                  className="admin-btn"
                  disabled={saving}
                  onClick={() =>
                    post(`/api/v1/admin/users/${id}/dms-permissions`, {
                      permissions: [...dmsPermsChecked],
                    })
                  }
                >
                  Save DMS permissions
                </button>
              </>
            ) : null}
          </div>
        </>
      )}

      <h2 className="admin-section-title">Security</h2>
      <div className="admin-card">
        <p className="sub" style={{ margin: "0 0 12px" }}>
          Last signed in: <strong>{user.last_login_at ? `${timeAgo(user.last_login_at)} (${formatDateTime(user.last_login_at)})` : "never"}</strong>
          {typeof user.failed_logins === "number" && user.failed_logins > 0 ? (
            <span style={{ color: "var(--warning-text)" }}> · {user.failed_logins} wrong password{user.failed_logins === 1 ? "" : "s"} since the last good sign-in</span>
          ) : null}
          {data.isLocked && user.locked_until ? (
            <span style={{ color: "var(--warning-text)" }}> · locked until {formatDateTime(user.locked_until)}</span>
          ) : null}
        </p>
        {user.source !== "local" ? (
          <p className="sub" style={{ margin: "0 0 12px" }}>
            This account signs in with Active Directory, so its password is
            managed in AD and cannot be reset here. Reset it in AD; a password
            set in SSO would be a second, SSO-only credential that outlives the
            AD one.
          </p>
        ) : (
          <>
        <p className="sub" style={{ margin: "0 0 12px" }}>
          Resetting the password signs the user out of everything (SSO, portal,
          GMS) and forces them to choose a new password at their next sign-in.
        </p>
        <div
          style={{
            display: "flex",
            gap: "10px",
            alignItems: "flex-end",
            flexWrap: "wrap",
          }}
        >
          <div>
            <label className="admin-label" htmlFor="reset_password">
              Temporary password
            </label>
            <input
              id="reset_password"
              type="text"
              autoComplete="off"
              required
              minLength={data.passwordMinLength}
              placeholder={`At least ${data.passwordMinLength} characters`}
              style={{ width: "280px" }}
              value={tempPassword}
              onChange={(e) => setTempPassword(e.target.value)}
            />
          </div>
          <button
            type="button"
            className="admin-btn secondary"
            disabled={saving}
            title="Fill in a strong random password you can read out to the person"
            onClick={() => {
              const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
              const bytes = new Uint32Array(Math.max(14, data.passwordMinLength));
              crypto.getRandomValues(bytes);
              setTempPassword(Array.from(bytes, (b) => alphabet[b % alphabet.length]).join(""));
            }}
          >
            Generate
          </button>
          <button
            type="button"
            className="admin-btn danger"
            disabled={saving || tempPassword.length < data.passwordMinLength}
            onClick={async () => {
              const sure = await confirm({
                title: `Reset the password for ${user.email}?`,
                message: (
                  <>
                    <p>They are signed out of SSO, the portal, DMS and GMS on every device now, and must choose a new password at their next sign-in.</p>
                    <p>Give them the temporary password in person or by phone, not in a message that stays around.</p>
                  </>
                ),
                confirmLabel: "Reset password",
                danger: true,
              });
              if (!sure) return;
              const ok = await post(
                `/api/v1/admin/users/${id}/reset-password`,
                { password: tempPassword },
                "Password reset",
              );
              if (ok) setTempPassword("");
            }}
          >
            Reset password &amp; sign out everywhere
          </button>
        </div>
          </>
        )}
        {user.source === "local" && user.must_change_password && (
          <p
            className="sub"
            style={{ margin: "12px 0 0", color: "var(--warning-text)" }}
          >
            A temporary password is pending — this user must set a new password
            at their next sign-in.
          </p>
        )}
        <hr
          style={{
            border: "none",
            borderTop: "1px solid var(--border)",
            margin: "16px 0",
          }}
        />
        <p className="sub" style={{ margin: "0 0 8px" }}>
          Two-factor auth: <strong>{user.totp_enabled ? "ON" : "off"}</strong>
          {user.totp_enabled && (
            <span style={{ color: data.recoveryCodesRemaining === 0 ? "var(--warning-text)" : "var(--muted)" }}>
              {" "}
              ({data.recoveryCodesRemaining} recovery code{data.recoveryCodesRemaining === 1 ? "" : "s"} left)
            </span>
          )}
          {!user.totp_enabled && (
            <span style={{ color: "var(--muted)" }}>
              {" "}
              (users enroll themselves at Portal → Security)
            </span>
          )}
        </p>
        {user.totp_enabled && (
          <button
            type="button"
            className="admin-btn secondary"
            disabled={saving}
            onClick={async () => {
              const sure = await confirm({
                title: `Remove two-factor sign-in for ${user.email}?`,
                message: (
                  <>
                    <p>Their authenticator and all their recovery codes stop working. They can sign in with the password alone until they set two-factor up again.</p>
                    <p>Only do this once you are sure it is really them asking (for example, they lost their phone and their recovery codes).</p>
                  </>
                ),
                confirmLabel: "Remove two-factor",
                danger: true,
              });
              if (sure) await post(`/api/v1/admin/users/${id}/mfa-reset`, {}, "MFA reset");
            }}
          >
            Remove two-factor auth (lost device and recovery codes)
          </button>
        )}
      </div>

      <h2 className="admin-section-title">
        Recent sign-in attempts{" "}
        <Link href={`/admin/logins?q=${encodeURIComponent(user.email)}`} className="admin-link" style={{ textTransform: "none", fontWeight: 400 }}>
          see all →
        </Link>
      </h2>
      <div className="admin-card">
        {data.recentLogins.length === 0 ? (
          <p className="admin-empty-row">No sign-in attempts recorded.</p>
        ) : (
          <table className="admin-table">
            <thead>
              <tr>
                <th>When</th>
                <th>Result</th>
                <th>Address</th>
                <th>What happened</th>
              </tr>
            </thead>
            <tbody>
              {data.recentLogins.map((l, i) => (
                <tr key={i}>
                  <td style={{ color: "var(--muted)", whiteSpace: "nowrap" }}>{formatDateTime(l.created_at)}</td>
                  <td><span className={`admin-badge ${l.success ? "on" : "off"}`}>{l.success ? "Success" : "Failed"}</span></td>
                  <td style={{ fontFamily: "monospace", fontSize: "12px" }}>{l.ip || "—"}</td>
                  <td style={{ color: "var(--muted)", fontSize: "12px" }} title={l.user_agent || undefined}>{loginReasonLabel(l.success, l.reason)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <h2 className="admin-section-title">
        Change history{" "}
        <span style={{ textTransform: "none", fontWeight: 400 }}>
          (admin actions affecting this user)
        </span>
      </h2>
      <div className="admin-card">
        {data.history.length === 0 ? (
          <p className="admin-empty-row">No recorded changes yet.</p>
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
                  <td style={{ color: "var(--muted)", whiteSpace: "nowrap" }}>
                    {new Date(h.created_at).toLocaleString()}
                  </td>
                  <td>{h.actor_email}</td>
                  <td>
                    {auditActionLabel(h.action)}
                    <div><code className="admin-code" style={{ fontSize: 11 }}>{h.action}</code></div>
                  </td>
                  <td
                    style={{
                      color: "var(--muted)",
                      fontSize: "12px",
                      wordBreak: "break-all",
                    }}
                  >
                    {JSON.stringify(h.detail)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <h2 className="admin-section-title">
        Additional shared groups{" "}
        <span style={{ textTransform: "none", fontWeight: 400 }}>
          (advanced)
        </span>
      </h2>
      <div className="admin-card">
        <p className="sub" style={{ margin: "0 0 12px" }}>
          For AD groups or team-wide access shared by many users. Most users
          only need the System access section above.
        </p>
        {data.groups.length === 0 ? (
          <p className="admin-empty-row">Not in any additional group.</p>
        ) : (
          <table className="admin-table" style={{ marginBottom: "14px" }}>
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
                    <code className="admin-code">{g}</code>{" "}
                    <Link
                      href={`/admin/groups/detail?dn=${encodeURIComponent(g)}`}
                      className="admin-link"
                      style={{ marginLeft: "8px", fontSize: "12px" }}
                    >
                      configure →
                    </Link>
                  </td>
                  <td style={{ textAlign: "right" }}>
                    <button
                      type="button"
                      className="admin-btn danger"
                      style={{ padding: "4px 10px", fontSize: "12px" }}
                      disabled={saving}
                      onClick={() =>
                        post(
                          `/api/v1/admin/users/${id}/groups/remove`,
                          { group_dn: g },
                          "Removed",
                        )
                      }
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <div
          style={{
            display: "flex",
            gap: "10px",
            alignItems: "flex-end",
            flexWrap: "wrap",
          }}
        >
          <div>
            <label className="admin-label" htmlFor="group_dn">
              Add to group
            </label>
            <select
              id="group_dn"
              style={{ width: "420px" }}
              value={newGroupDn}
              onChange={(e) => setNewGroupDn(e.target.value)}
            >
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
              const ok = await post(
                `/api/v1/admin/users/${id}/groups`,
                { group_dn: newGroupDn },
                "Added",
              );
              if (ok) setNewGroupDn("");
            }}
          >
            Add
          </button>
        </div>
      </div>
    </>
  );
}

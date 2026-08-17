-- GMS token-bridge support (Phase 6). Lives in the IdP DB, not GMS.
-- Maps AD/local group DNs → GMS role names for provisioning/minting.

CREATE TABLE IF NOT EXISTS idp_gms_role_mappings (
  group_dn  TEXT NOT NULL,
  role_name TEXT NOT NULL,   -- GMS role: super_admin | admin | reception | host | ...
  PRIMARY KEY (group_dn, role_name)
);

-- Optional per-user office pin, so office-scoped GMS roles (admin/reception/host)
-- can be minted with a valid office_id without touching GMS.
CREATE TABLE IF NOT EXISTS idp_gms_user_office (
  email     TEXT PRIMARY KEY,
  office_id INT  NOT NULL
);

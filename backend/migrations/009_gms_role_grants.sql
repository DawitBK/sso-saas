-- Per-user client-scoped role grants (platform directive §6.3, follow-up to 008).
--
-- 008 seeded idp_client_roles as a catalog of *valid* role names per relying
-- party, with assignment still flowing through idp_gms_role_mappings
-- (AD group -> role) alone. That covers staff whose access is driven by an
-- AD group; it has no way to grant a role directly to one person. This table
-- adds that: an explicit, per-user grant that takes precedence over any group
-- mapping. Keyed on email (lowercased), matching every other GMS-identity
-- table in this schema (idp_gms_user_office, bridge/gms.ts) rather than a
-- synthetic SSO subject id. Multi-row per user is intentional — GMS assigns
-- more than one role to a single account in practice (e.g. super_admin +
-- admin together at bootstrap).

CREATE TABLE IF NOT EXISTS idp_client_user_roles (
  email        TEXT NOT NULL,
  client_id    TEXT NOT NULL,
  role_name    TEXT NOT NULL,
  granted_by   TEXT NOT NULL,
  granted_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (email, client_id, role_name),
  FOREIGN KEY (client_id, role_name) REFERENCES idp_client_roles (client_id, role_name)
);

CREATE INDEX IF NOT EXISTS idp_client_user_roles_lookup_idx
  ON idp_client_user_roles (client_id, email);

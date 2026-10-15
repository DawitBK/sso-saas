-- P1-2: per-client scope allowlist.
--
-- claims.profile in oidc/provider.ts carried AD_GROUPS_CLAIM, GMS_ROLES_CLAIM and
-- EDAMS_ROLES_CLAIM together, and loadClients() never set a per-client `scope`,
-- so oidc-provider applied no restriction: every relying party's id_token carried
-- every other relying party's roles. The gms client saw the user's DMS roles, the
-- edams client saw their GMS roles, and the portal saw both. Those role names are
-- another system's internal authorization model crossing a trust boundary for no
-- reason.
--
-- The role claims now live under their own scopes (gms_roles / edams_roles), and
-- this column is what stops a client asking for a scope that isn't its business.
--
-- NULL means "no restriction" — which is exactly today's behaviour — so a
-- deployment where this migration has not yet run keeps working unchanged rather
-- than failing authorize with invalid_scope. Every row is seeded below, and
-- seedClients() keeps them current on boot.
ALTER TABLE idp_clients
  ADD COLUMN IF NOT EXISTS scope TEXT;

-- ad_groups goes to all three on purpose, not by oversight: the portal computes
-- entitlements and the admin tile from the AD group list (portal/catalog.ts), the
-- GMS bridge maps groups to GMS roles (bridge/gms.ts), and DMS uses them for its
-- idp_role_mappings fallback. The separation being bought here is role-claim
-- separation between relying parties, not hiding the directory from all of them.
UPDATE idp_clients SET scope = 'openid profile email ad_groups edams_roles' WHERE client_id = 'edams' AND (scope IS NULL OR scope = '');
UPDATE idp_clients SET scope = 'openid profile email ad_groups gms_roles'   WHERE client_id = 'gms'   AND (scope IS NULL OR scope = '');
UPDATE idp_clients SET scope = 'openid profile email ad_groups'             WHERE client_id = 'portal' AND (scope IS NULL OR scope = '');

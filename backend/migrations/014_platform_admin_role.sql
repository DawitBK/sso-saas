-- Adds PLATFORM_ADMIN to the edams (DMS) role catalog SSO is the system of
-- record for (see 008_client_scoped_roles.sql's header). This is presentation/
-- admin-console-catalog only -- applyAccess()/putDmsRoleMapping() do not
-- gate on this table, they just write idp_role_mappings and let DMS's own
-- internal API validate the role name against DMS's own `roles` table
-- (DMS/backend/migrations/20260914000001-platform-admin-role.sql). This row
-- just makes the role selectable/visible in the admin console's own DMS
-- access UI, same as every other edams role already listed here.
--
-- sort_order 5 (lower than SYSTEM_ADMIN's 10) so it lists first, matching
-- DMS's own ROLE_RANK ordering (config/permissions.ts).
INSERT INTO idp_client_roles (client_id, role_name, display_name, office_scoped, sort_order) VALUES
  ('edams', 'PLATFORM_ADMIN', 'Platform Admin (cross-tenant)', FALSE, 5)
ON CONFLICT (client_id, role_name) DO NOTHING;

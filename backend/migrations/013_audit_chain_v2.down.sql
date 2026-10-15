DROP TABLE IF EXISTS idp_admin_audit_anchor;
ALTER TABLE idp_admin_audit DROP COLUMN IF EXISTS hash_version;

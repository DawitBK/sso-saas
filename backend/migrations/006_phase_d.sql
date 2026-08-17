-- Phase D: MFA brute-force lockout (mirrors the password lockout columns) +
-- audit-trail lookup indexes (the per-user history query was a sequential scan).

ALTER TABLE idp_users ADD COLUMN IF NOT EXISTS mfa_failed_attempts INT NOT NULL DEFAULT 0;
ALTER TABLE idp_users ADD COLUMN IF NOT EXISTS mfa_locked_until TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idp_admin_audit_target_idx ON idp_admin_audit (target);
CREATE INDEX IF NOT EXISTS idp_admin_audit_detail_userid_idx ON idp_admin_audit ((detail->>'userId'));

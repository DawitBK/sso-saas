-- Platform settings: the policy and branding values the console can change at run time (settings/registry.ts lists every key).
--
-- A row exists only for a value somebody CHANGED; "no row" means "use the default" (the environment value, or the built-in one),
-- so an existing installation behaves exactly as before until an administrator edits something. Resetting a setting deletes its row.
-- Every change is also written to the admin audit chain (idp_admin_audit) with the old and new value.

CREATE TABLE IF NOT EXISTS idp_settings (
  key        TEXT PRIMARY KEY,
  value      JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- The administrator's email, or the literal 'platform' for the platform administrator (who must stay anonymous, see auth/platform-admin.ts).
  updated_by TEXT NOT NULL DEFAULT ''
);

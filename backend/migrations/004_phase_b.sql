-- Phase B: user lifecycle. Admin-reset passwords must be changed at next login.
ALTER TABLE idp_users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE;

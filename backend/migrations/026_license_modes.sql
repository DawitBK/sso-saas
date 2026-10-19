-- Per-application licensing (docs/operations/PLATFORM-LICENSING.md section 9): which deployment shapes a licence authorises.
--
-- ADDITIVE ONLY: one new column with a default, so every existing row keeps working unchanged. 'sso' = the system runs behind this identity provider
-- (the shape every deployment has today); 'standalone' = it may also run without SSO. A system that finds itself in a shape its token does not list
-- is unlicensed when LICENSE_REQUIRED is true.
ALTER TABLE licenses
  ADD COLUMN IF NOT EXISTS modes TEXT[] NOT NULL DEFAULT ARRAY['sso']::TEXT[]
  CHECK (cardinality(modes) >= 1 AND modes <@ ARRAY['sso', 'standalone']::TEXT[]);

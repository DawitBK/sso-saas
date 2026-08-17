-- "Log out everywhere" (revokeAllSessions), the metrics endpoint's active-session
-- count, and the login-events purge job all filter oidc_artifacts / idp_web_sessions
-- by JSONB expressions (payload->>'accountId', payload->>'email') that had no
-- supporting index — every call forced a sequential scan + per-row JSONB
-- extraction across tables that only grow. Partial indexes (WHERE ... IS NOT
-- NULL) keep them small, since most oidc_artifacts kinds do carry an accountId
-- but not every row type does.

CREATE INDEX IF NOT EXISTS oidc_artifacts_account_idx
  ON oidc_artifacts ((payload->>'accountId'))
  WHERE payload->>'accountId' IS NOT NULL;

CREATE INDEX IF NOT EXISTS idp_web_sessions_account_idx
  ON idp_web_sessions ((payload->>'accountId'))
  WHERE payload->>'accountId' IS NOT NULL;

CREATE INDEX IF NOT EXISTS idp_web_sessions_email_idx
  ON idp_web_sessions ((payload->>'email'))
  WHERE payload->>'email' IS NOT NULL;

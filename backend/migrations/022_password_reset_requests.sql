-- "I forgot my password", with no mail server.
--
-- There is no SMTP on the server, so SSO cannot email a reset link. What it can do is let a person say so on the sign-in page and put the request in front of
-- the administrators who can reset the password (Admin > Users). One OPEN request per person at a time: asking again refreshes it rather than piling up.
--
-- The public form never reveals whether an address has an account (it always answers the same), so a request exists only for a real, active local account;
-- an Active Directory account is reset in the directory, and the platform administrator is not offered this at all.

CREATE TABLE IF NOT EXISTS idp_password_reset_requests (
  id            BIGSERIAL PRIMARY KEY,
  user_id       UUID        NOT NULL REFERENCES idp_users(id) ON DELETE CASCADE,
  email         TEXT        NOT NULL,
  -- What the person typed to help the administrator recognise them ("Maria, reception, Block B"). Plain text, shown escaped, capped at 200.
  note          TEXT        NOT NULL DEFAULT '' CHECK (char_length(note) <= 200),
  requested_ip  TEXT        NOT NULL DEFAULT '',
  status        TEXT        NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'done', 'dismissed')),
  requested_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- 'platform' for the platform administrator (never named, see auth/platform-admin.ts).
  handled_by    TEXT,
  handled_at    TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idp_password_reset_requests_one_open ON idp_password_reset_requests (user_id) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idp_password_reset_requests_status ON idp_password_reset_requests (status, requested_at DESC);

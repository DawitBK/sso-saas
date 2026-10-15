-- Rolls back 022. Open requests are forgotten; people ask again (or an administrator resets the password anyway).
DROP TABLE IF EXISTS idp_password_reset_requests;

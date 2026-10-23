-- Rolls back 027. The owner's enrolment (questions, address, authenticator secret, recovery codes) is lost with the store and must be repeated
-- with `npm run owner:enroll`. While OWNER_VERIFICATION_REQUIRED is true, owner-only operations are refused until that is done.
DROP TABLE IF EXISTS owner_verification_audit;
DROP TABLE IF EXISTS owner_verification_tickets;
DROP TABLE IF EXISTS owner_verification_challenges;
DROP TABLE IF EXISTS owner_verification_state;
DROP TABLE IF EXISTS owner_recovery_codes_used;
DROP TABLE IF EXISTS owner_verification_store;

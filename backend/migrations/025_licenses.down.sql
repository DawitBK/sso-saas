-- Rolls back 025. Every system returns to `unconfigured` (no licence, nothing enforced). The licence history is lost with the table; the
-- admin audit chain keeps its own record of every licence change.
DROP TABLE IF EXISTS license_events;
DROP TABLE IF EXISTS licenses;

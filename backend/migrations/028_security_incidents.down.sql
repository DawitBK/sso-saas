-- Rolls back 028. The incident history is lost with the table (the admin audit chain keeps its own `security.incident` rows).
DROP TABLE IF EXISTS security_incidents;
DROP FUNCTION IF EXISTS security_incidents_refuse_change();
DROP TABLE IF EXISTS security_state;

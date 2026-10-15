-- Rolls back 021. Known breaks in the audit chain read as open (unexplained) again; nothing in the chain itself changes.
DROP TABLE IF EXISTS idp_audit_chain_acknowledgements;

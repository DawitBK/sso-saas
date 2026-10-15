-- Rolls back 020. A sign-out notification that failed is then simply forgotten (the administrator's warning still says so).
DROP TABLE IF EXISTS idp_pending_notifications;

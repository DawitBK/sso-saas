-- Client-scoped role catalog (platform directive §6.3).
-- SSO is the system of record for which roles exist per relying party.
-- Assignments continue to use idp_gms_role_mappings / DMS internal mappings
-- until a later migration moves grants fully onto this catalog.

CREATE TABLE IF NOT EXISTS idp_client_roles (
  client_id     TEXT NOT NULL,
  role_name     TEXT NOT NULL,
  display_name  TEXT NOT NULL DEFAULT '',
  office_scoped BOOLEAN NOT NULL DEFAULT FALSE,
  sort_order    INT NOT NULL DEFAULT 0,
  PRIMARY KEY (client_id, role_name)
);

CREATE INDEX IF NOT EXISTS idp_client_roles_client_idx
  ON idp_client_roles (client_id, sort_order, role_name);

-- GMS staff roles only (guest remains a GMS business record, not an SSO identity).
INSERT INTO idp_client_roles (client_id, role_name, display_name, office_scoped, sort_order) VALUES
  ('gms', 'super_admin',      'Super Admin',      FALSE, 10),
  ('gms', 'admin',            'Admin',            TRUE,  20),
  ('gms', 'super_reception',  'Super Reception',  FALSE, 30),
  ('gms', 'reception',        'Reception',        TRUE,  40),
  ('gms', 'super_host',       'Super Host',       FALSE, 50),
  ('gms', 'host',             'Host',             TRUE,  60)
ON CONFLICT (client_id, role_name) DO NOTHING;

-- DMS coarse platform roles (fine-grained ACL stays in DMS).
INSERT INTO idp_client_roles (client_id, role_name, display_name, office_scoped, sort_order) VALUES
  ('edams', 'SYSTEM_ADMIN',    'System Admin',     FALSE, 10),
  ('edams', 'DEPT_MANAGER',    'Dept Manager',     FALSE, 20),
  ('edams', 'RECORDS_OFFICER', 'Records Officer',  FALSE, 30),
  ('edams', 'APPROVER',        'Approver',         FALSE, 40),
  ('edams', 'EMPLOYEE',        'Employee',         FALSE, 50),
  ('edams', 'AUDITOR',         'Auditor',          FALSE, 60),
  ('edams', 'EXECUTIVE',       'Executive',        FALSE, 70)
ON CONFLICT (client_id, role_name) DO NOTHING;

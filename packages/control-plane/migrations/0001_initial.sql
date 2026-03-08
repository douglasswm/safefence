-- SafeFence Control Plane: Initial schema migration
-- Includes Row Level Security (RLS) policies for multi-tenant isolation.

-- Enable RLS on all tenant-scoped tables
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE instance_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_current ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_role_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_platform_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_role_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_bots ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_bot_capabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE rbac_mutations ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_versions ENABLE ROW LEVEL SECURITY;

-- RLS policies: each table filtered by current_setting('app.current_org_id')
CREATE POLICY org_isolation ON organizations
  USING (id = current_setting('app.current_org_id', true));

CREATE POLICY org_isolation ON instance_groups
  USING (org_id = current_setting('app.current_org_id', true));

CREATE POLICY org_isolation ON instances
  USING (org_id = current_setting('app.current_org_id', true));

CREATE POLICY org_isolation ON policy_current
  USING (org_id = current_setting('app.current_org_id', true));

CREATE POLICY org_isolation ON policy_versions
  USING (org_id = current_setting('app.current_org_id', true));

CREATE POLICY org_isolation ON cloud_roles
  USING (org_id = current_setting('app.current_org_id', true));

CREATE POLICY org_isolation ON cloud_role_permissions
  USING (org_id = current_setting('app.current_org_id', true));

CREATE POLICY org_isolation ON cloud_users
  USING (org_id = current_setting('app.current_org_id', true));

CREATE POLICY org_isolation ON cloud_platform_identities
  USING (org_id = current_setting('app.current_org_id', true));

CREATE POLICY org_isolation ON cloud_role_assignments
  USING (org_id = current_setting('app.current_org_id', true));

CREATE POLICY org_isolation ON cloud_bots
  USING (org_id = current_setting('app.current_org_id', true));

CREATE POLICY org_isolation ON cloud_bot_capabilities
  USING (org_id = current_setting('app.current_org_id', true));

CREATE POLICY org_isolation ON rbac_mutations
  USING (org_id = current_setting('app.current_org_id', true));

CREATE POLICY org_isolation ON audit_events
  USING (org_id = current_setting('app.current_org_id', true));

CREATE POLICY org_isolation ON org_versions
  USING (org_id = current_setting('app.current_org_id', true));

-- Service role bypasses RLS (for the control plane API process)
-- Run as superuser: GRANT safefence_service TO safefence;
-- ALTER TABLE ... FORCE ROW LEVEL SECURITY; -- only if using same role

-- Audit events partitioning (by month) - to be added when data volume requires it
-- CREATE TABLE audit_events_2026_03 PARTITION OF audit_events
--   FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

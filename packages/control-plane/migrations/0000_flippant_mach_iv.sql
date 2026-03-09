CREATE TABLE "audit_events" (
	"id" text PRIMARY KEY NOT NULL,
	"org_id" text NOT NULL,
	"instance_id" text NOT NULL,
	"seq" bigint NOT NULL,
	"timestamp" timestamp with time zone NOT NULL,
	"bot_instance_id" text,
	"actor_user_id" text,
	"actor_platform" text,
	"actor_platform_id" text,
	"im_channel_id" text,
	"event_type" text NOT NULL,
	"decision" text,
	"denied_by" text,
	"permission_category" text,
	"permission_action" text,
	"details" jsonb,
	"project_id" text,
	"prev_hash" text,
	"event_hash" text
);
--> statement-breakpoint
CREATE TABLE "cloud_bot_capabilities" (
	"bot_id" text NOT NULL,
	"org_id" text NOT NULL,
	"permission_id" text NOT NULL,
	"effect" text DEFAULT 'allow' NOT NULL,
	CONSTRAINT "cloud_bot_capabilities_bot_id_permission_id_pk" PRIMARY KEY("bot_id","permission_id")
);
--> statement-breakpoint
CREATE TABLE "cloud_bots" (
	"id" text PRIMARY KEY NOT NULL,
	"org_id" text NOT NULL,
	"project_id" text NOT NULL,
	"owner_id" text NOT NULL,
	"name" text,
	"platform" text NOT NULL,
	"platform_bot_id" text,
	"access_policy" text DEFAULT 'owner_only' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "cloud_platform_identities" (
	"platform" text NOT NULL,
	"platform_id" text NOT NULL,
	"org_id" text NOT NULL,
	"user_id" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "cloud_platform_identities_platform_platform_id_org_id_pk" PRIMARY KEY("platform","platform_id","org_id")
);
--> statement-breakpoint
CREATE TABLE "cloud_role_assignments" (
	"id" text PRIMARY KEY NOT NULL,
	"org_id" text NOT NULL,
	"user_id" text NOT NULL,
	"role_id" text NOT NULL,
	"scope_type" text DEFAULT 'project' NOT NULL,
	"scope_id" text NOT NULL,
	"bot_instance_id" text,
	"granted_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "cloud_role_permissions" (
	"role_id" text NOT NULL,
	"org_id" text NOT NULL,
	"permission_id" text NOT NULL,
	"effect" text DEFAULT 'allow' NOT NULL,
	CONSTRAINT "cloud_role_permissions_role_id_permission_id_pk" PRIMARY KEY("role_id","permission_id")
);
--> statement-breakpoint
CREATE TABLE "cloud_roles" (
	"id" text PRIMARY KEY NOT NULL,
	"org_id" text NOT NULL,
	"project_id" text NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"is_system" boolean DEFAULT false NOT NULL,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "cloud_users" (
	"id" text PRIMARY KEY NOT NULL,
	"org_id" text NOT NULL,
	"display_name" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "instance_groups" (
	"id" text PRIMARY KEY NOT NULL,
	"org_id" text NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "instances" (
	"id" text PRIMARY KEY NOT NULL,
	"org_id" text NOT NULL,
	"group_id" text,
	"plugin_version" text,
	"tags" jsonb DEFAULT '[]'::jsonb,
	"status" text DEFAULT 'registered' NOT NULL,
	"policy_version" integer DEFAULT 0 NOT NULL,
	"rbac_version" integer DEFAULT 0 NOT NULL,
	"audit_cursor" bigint DEFAULT 0 NOT NULL,
	"last_heartbeat_at" timestamp with time zone,
	"last_metrics" jsonb,
	"registered_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "org_versions" (
	"org_id" text PRIMARY KEY NOT NULL,
	"policy_version" integer DEFAULT 0 NOT NULL,
	"rbac_version" integer DEFAULT 0 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "organizations" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"api_key_hash" text NOT NULL,
	"api_key_prefix" text,
	"plan_tier" text DEFAULT 'free' NOT NULL,
	"max_instances" integer DEFAULT 5 NOT NULL,
	"max_audit_retention_days" integer DEFAULT 90 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "policy_current" (
	"id" text PRIMARY KEY NOT NULL,
	"org_id" text NOT NULL,
	"key" text NOT NULL,
	"value" jsonb NOT NULL,
	"scope" text DEFAULT 'org' NOT NULL,
	"scope_id" text,
	"version" integer DEFAULT 1 NOT NULL,
	"updated_by" text,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "policy_versions" (
	"id" text PRIMARY KEY NOT NULL,
	"org_id" text NOT NULL,
	"policy_id" text NOT NULL,
	"key" text NOT NULL,
	"value" jsonb NOT NULL,
	"scope" text NOT NULL,
	"scope_id" text,
	"version" integer NOT NULL,
	"changed_by" text,
	"changed_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "rbac_mutations" (
	"id" text PRIMARY KEY NOT NULL,
	"org_id" text NOT NULL,
	"version" integer NOT NULL,
	"mutation_type" text NOT NULL,
	"payload" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cloud_bot_capabilities" ADD CONSTRAINT "cloud_bot_capabilities_bot_id_cloud_bots_id_fk" FOREIGN KEY ("bot_id") REFERENCES "public"."cloud_bots"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cloud_bot_capabilities" ADD CONSTRAINT "cloud_bot_capabilities_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cloud_bots" ADD CONSTRAINT "cloud_bots_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cloud_platform_identities" ADD CONSTRAINT "cloud_platform_identities_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cloud_platform_identities" ADD CONSTRAINT "cloud_platform_identities_user_id_cloud_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."cloud_users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cloud_role_assignments" ADD CONSTRAINT "cloud_role_assignments_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cloud_role_assignments" ADD CONSTRAINT "cloud_role_assignments_user_id_cloud_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."cloud_users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cloud_role_assignments" ADD CONSTRAINT "cloud_role_assignments_role_id_cloud_roles_id_fk" FOREIGN KEY ("role_id") REFERENCES "public"."cloud_roles"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cloud_role_permissions" ADD CONSTRAINT "cloud_role_permissions_role_id_cloud_roles_id_fk" FOREIGN KEY ("role_id") REFERENCES "public"."cloud_roles"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cloud_role_permissions" ADD CONSTRAINT "cloud_role_permissions_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cloud_roles" ADD CONSTRAINT "cloud_roles_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cloud_users" ADD CONSTRAINT "cloud_users_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "instance_groups" ADD CONSTRAINT "instance_groups_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "instances" ADD CONSTRAINT "instances_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "instances" ADD CONSTRAINT "instances_group_id_instance_groups_id_fk" FOREIGN KEY ("group_id") REFERENCES "public"."instance_groups"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "org_versions" ADD CONSTRAINT "org_versions_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_current" ADD CONSTRAINT "policy_current_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_versions" ADD CONSTRAINT "policy_versions_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policy_versions" ADD CONSTRAINT "policy_versions_policy_id_policy_current_id_fk" FOREIGN KEY ("policy_id") REFERENCES "public"."policy_current"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "rbac_mutations" ADD CONSTRAINT "rbac_mutations_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_audit_org_time" ON "audit_events" USING btree ("org_id","timestamp");--> statement-breakpoint
CREATE INDEX "idx_audit_instance" ON "audit_events" USING btree ("instance_id","seq");--> statement-breakpoint
CREATE INDEX "idx_audit_event_type" ON "audit_events" USING btree ("org_id","event_type");--> statement-breakpoint
CREATE INDEX "idx_cloud_bots_org" ON "cloud_bots" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_cloud_identities_user" ON "cloud_platform_identities" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_cloud_assignments_org" ON "cloud_role_assignments" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_cloud_assignments_user" ON "cloud_role_assignments" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_cloud_role_perms_org" ON "cloud_role_permissions" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_cloud_roles_org" ON "cloud_roles" USING btree ("org_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_cloud_roles_name" ON "cloud_roles" USING btree ("org_id","project_id","name");--> statement-breakpoint
CREATE INDEX "idx_cloud_users_org" ON "cloud_users" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_groups_org" ON "instance_groups" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_instances_org" ON "instances" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_instances_group" ON "instances" USING btree ("group_id");--> statement-breakpoint
CREATE INDEX "idx_instances_heartbeat" ON "instances" USING btree ("last_heartbeat_at");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_policy_unique" ON "policy_current" USING btree ("org_id","key","scope","scope_id");--> statement-breakpoint
CREATE INDEX "idx_policy_org" ON "policy_current" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_policy_versions_org" ON "policy_versions" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_policy_versions_policy" ON "policy_versions" USING btree ("policy_id");--> statement-breakpoint
CREATE INDEX "idx_rbac_mutations_org_version" ON "rbac_mutations" USING btree ("org_id","version");
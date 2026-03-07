#!/usr/bin/env node

/**
 * SafeFence CLI — reads SQLite directly (no server needed).
 *
 * Usage:
 *   safefence bot register --project <id> --platform telegram --bot-id 12345 --owner telegram:67890 "Bot Name"
 *   safefence bot cap set --bot <id> tool_use:exec deny
 *   safefence bot access --bot <id> project_members
 *   safefence role create --project <id> "moderator"
 *   safefence role grant-perm --role <id> tool_use:read data_access:public
 *   safefence assign --user telegram:11111 --role <id> --bot <botId> --channel telegram:-1001234
 *   safefence effective --user telegram:11111 --bot <botId> --channel telegram:-1001234
 *   safefence audit --bot <botId> --last 24h
 */

import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { extractFlag } from "../utils/args.js";

function main(): void {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === "help" || command === "--help") {
    printHelp();
    return;
  }

  const dbPath = extractFlag(args, "--db") ?? resolve(process.cwd(), ".safefence/rbac.db");
  const auditDbPath = extractFlag(args, "--audit-db") ?? resolve(process.cwd(), ".safefence/audit.db");

  // Dynamic require to avoid loading better-sqlite3 until needed
  let SqliteRoleStore: typeof import("../core/sqlite-role-store.js").SqliteRoleStore;
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    SqliteRoleStore = require("../core/sqlite-role-store.js").SqliteRoleStore;
  } catch {
    console.error("Error: better-sqlite3 is required for the CLI. Install it with: npm install better-sqlite3");
    process.exit(1);
  }

  const store = new SqliteRoleStore(dbPath, auditDbPath);

  try {
    switch (command) {
      case "bot":
        handleBot(args.slice(1), store);
        break;
      case "role":
        handleRole(args.slice(1), store);
        break;
      case "assign":
        handleAssign(args.slice(1), store);
        break;
      case "revoke":
        handleRevoke(args.slice(1), store);
        break;
      case "effective":
        handleEffective(args.slice(1), store);
        break;
      case "audit":
        handleAudit(args.slice(1), store);
        break;
      case "user":
        handleUser(args.slice(1), store);
        break;
      case "channel":
        handleChannel(args.slice(1), store);
        break;
      default:
        console.error(`Unknown command: ${command}`);
        printHelp();
        process.exit(1);
    }
  } finally {
    store.close();
  }
}

function printHelp(): void {
  console.log(`
SafeFence CLI — RBAC management for OpenClaw guardrails

Commands:
  bot register|cap|access|list   Manage bot instances
  role create|delete|list|grant-perm|revoke-perm  Manage roles
  assign                         Assign a role to a user
  revoke                         Revoke a role assignment
  effective                      Show effective permissions
  audit                          Query audit log
  user create|link               Manage users
  channel link|unlink            Manage IM channels

Global options:
  --db <path>        Path to rbac.db (default: .safefence/rbac.db)
  --audit-db <path>  Path to audit.db (default: .safefence/audit.db)
  --help             Show this help
`);
}

function handleBot(args: string[], store: import("../core/sqlite-role-store.js").SqliteRoleStore): void {
  const sub = args[0];
  switch (sub) {
    case "register": {
      const project = extractFlag(args, "--project") ?? "default-project";
      const platform = extractFlag(args, "--platform") ?? "unknown";
      const botId = extractFlag(args, "--bot-id") ?? "";
      const owner = extractFlag(args, "--owner") ?? "";
      const name = getPositional(args, 1);
      if (!owner) { console.error("--owner is required"); process.exit(1); }
      store.ensureUser(owner);
      store.ensureProject(project, "default-org", "Default");
      const bot = store.registerBot(project, owner, platform, botId, name ?? undefined);
      console.log(`Bot registered: ${JSON.stringify(bot, null, 2)}`);
      break;
    }
    case "cap": {
      const action = args[1];
      if (action === "set") {
        const botId = extractFlag(args, "--bot") ?? "";
        const perm = getPositional(args, 2);
        const effect = getPositional(args, 3) as "allow" | "deny";
        if (!botId || !perm || !effect) { console.error("Usage: bot cap set --bot <id> <perm> allow|deny"); process.exit(1); }
        store.setBotCapability(botId, perm, effect);
        console.log(`Set ${perm} = ${effect} on bot ${botId}`);
      } else if (action === "list") {
        const botId = extractFlag(args, "--bot") ?? "";
        if (!botId) { console.error("--bot is required"); process.exit(1); }
        const caps = store.getBotCapabilities(botId);
        console.log(JSON.stringify(caps, null, 2));
      }
      break;
    }
    case "access": {
      const botId = extractFlag(args, "--bot") ?? "";
      const policy = getPositional(args, 1) as "owner_only" | "project_members" | "explicit";
      if (!botId || !policy) { console.error("Usage: bot access --bot <id> <policy>"); process.exit(1); }
      store.setBotAccessPolicy(botId, policy);
      console.log(`Set access policy to ${policy} on bot ${botId}`);
      break;
    }
    case "list": {
      const project = extractFlag(args, "--project") ?? "default-project";
      const bots = store.listBots(project);
      console.log(JSON.stringify(bots, null, 2));
      break;
    }
    default:
      console.error("Usage: safefence bot register|cap|access|list");
  }
}

function handleRole(args: string[], store: import("../core/sqlite-role-store.js").SqliteRoleStore): void {
  const sub = args[0];
  const project = extractFlag(args, "--project") ?? "default-project";
  switch (sub) {
    case "create": {
      const name = getPositional(args, 1);
      if (!name) { console.error("Usage: role create <name>"); process.exit(1); }
      store.ensureProject(project, "default-org", "Default");
      const role = store.createRole(project, name, []);
      console.log(`Role created: ${JSON.stringify(role, null, 2)}`);
      break;
    }
    case "delete": {
      const roleId = extractFlag(args, "--role") ?? getPositional(args, 1) ?? "";
      store.deleteRole(roleId);
      console.log(`Role deleted: ${roleId}`);
      break;
    }
    case "list": {
      store.ensureProject(project, "default-org", "Default");
      const roles = store.listRoles(project);
      console.log(JSON.stringify(roles, null, 2));
      break;
    }
    case "grant-perm": {
      const roleId = extractFlag(args, "--role") ?? "";
      const perms = args.filter((a) => !a.startsWith("--") && a !== "grant-perm" && a !== roleId);
      if (!roleId || perms.length === 0) {
        console.error("Usage: role grant-perm --role <id> <perm1> [perm2...]");
        process.exit(1);
      }
      for (const perm of perms) {
        store.grantRolePermission(roleId, perm, "allow");
        console.log(`Granted ${perm} to role ${roleId}`);
      }
      break;
    }
    case "revoke-perm": {
      const roleId = extractFlag(args, "--role") ?? "";
      const perms = args.filter((a) => !a.startsWith("--") && a !== "revoke-perm" && a !== roleId);
      if (!roleId || perms.length === 0) {
        console.error("Usage: role revoke-perm --role <id> <perm1> [perm2...]");
        process.exit(1);
      }
      for (const perm of perms) {
        store.revokeRolePermission(roleId, perm);
        console.log(`Revoked ${perm} from role ${roleId}`);
      }
      break;
    }
    default:
      console.error("Usage: safefence role create|delete|list|grant-perm|revoke-perm");
  }
}

function handleAssign(args: string[], store: import("../core/sqlite-role-store.js").SqliteRoleStore): void {
  const userId = extractFlag(args, "--user") ?? "";
  const roleId = extractFlag(args, "--role") ?? "";
  const botId = extractFlag(args, "--bot") ?? undefined;
  const channel = extractFlag(args, "--channel") ?? undefined;
  const project = extractFlag(args, "--project") ?? "default-project";

  if (!userId || !roleId) {
    console.error("Usage: safefence assign --user <id> --role <id> [--bot <id>] [--project <id>]");
    process.exit(1);
  }

  store.ensureUser(userId);
  const scopeType = channel ? "im_channel" as const : "project" as const;
  const scopeId = channel ?? project;
  const assignment = store.assignRole(userId, roleId, scopeType, scopeId, botId);
  console.log(`Assigned: ${JSON.stringify(assignment, null, 2)}`);
}

function handleRevoke(args: string[], store: import("../core/sqlite-role-store.js").SqliteRoleStore): void {
  const assignmentId = getPositional(args, 0) ?? extractFlag(args, "--id") ?? "";
  if (!assignmentId) {
    console.error("Usage: safefence revoke <assignmentId>");
    process.exit(1);
  }
  store.revokeRole(assignmentId);
  console.log(`Revoked: ${assignmentId}`);
}

function handleEffective(args: string[], store: import("../core/sqlite-role-store.js").SqliteRoleStore): void {
  const user = extractFlag(args, "--user") ?? "";
  const bot = extractFlag(args, "--bot") ?? "";
  const channel = extractFlag(args, "--channel") ?? undefined;

  if (!user || !bot) {
    console.error("Usage: safefence effective --user <platform:id> --bot <platform:id> [--channel <platform:id>]");
    process.exit(1);
  }

  const [userPlatform, userId] = splitPlatformId(user);
  const [botPlatform, botId] = splitPlatformId(bot);
  const channelParts = channel ? splitPlatformId(channel) : undefined;

  const result = store.resolveEffective({
    senderPlatform: userPlatform,
    senderId: userId,
    botPlatform,
    botPlatformId: botId,
    platformChannelId: channelParts ? channelParts[1] : undefined
  });
  console.log(JSON.stringify(result, null, 2));
}

function handleAudit(args: string[], store: import("../core/sqlite-role-store.js").SqliteRoleStore): void {
  const bot = extractFlag(args, "--bot") ?? undefined;
  const user = extractFlag(args, "--user") ?? undefined;
  const type = extractFlag(args, "--type") ?? undefined;
  const project = extractFlag(args, "--project") ?? undefined;
  const limitStr = extractFlag(args, "--limit");
  const limit = limitStr ? parseInt(limitStr, 10) : 50;

  const entries = store.queryAudit({ botInstanceId: bot, actorUserId: user, eventType: type, projectId: project, limit });
  console.log(JSON.stringify(entries, null, 2));
}

function handleUser(args: string[], store: import("../core/sqlite-role-store.js").SqliteRoleStore): void {
  const sub = args[0];
  switch (sub) {
    case "create": {
      const id = extractFlag(args, "--id") ?? getPositional(args, 1) ?? "";
      const name = extractFlag(args, "--name") ?? undefined;
      if (!id) { console.error("Usage: user create <id> [--name <name>]"); process.exit(1); }
      store.ensureUser(id, name);
      console.log(`User created: ${id}`);
      break;
    }
    case "link": {
      const userId = extractFlag(args, "--user") ?? "";
      const platform = extractFlag(args, "--platform") ?? "";
      const platformId = extractFlag(args, "--platform-id") ?? "";
      if (!userId || !platform || !platformId) {
        console.error("Usage: user link --user <id> --platform <p> --platform-id <pid>");
        process.exit(1);
      }
      store.linkPlatformIdentity(platform, platformId, userId);
      console.log(`Linked ${platform}:${platformId} -> ${userId}`);
      break;
    }
    default:
      console.error("Usage: safefence user create|link");
  }
}

function handleChannel(args: string[], store: import("../core/sqlite-role-store.js").SqliteRoleStore): void {
  const sub = args[0];
  switch (sub) {
    case "link": {
      const project = extractFlag(args, "--project") ?? "default-project";
      const platform = extractFlag(args, "--platform") ?? "";
      const channelId = extractFlag(args, "--channel-id") ?? "";
      const name = extractFlag(args, "--name") ?? undefined;
      if (!platform || !channelId) {
        console.error("Usage: channel link --platform <p> --channel-id <id> [--project <id>]");
        process.exit(1);
      }
      store.linkChannel(randomUUID(), project, platform, channelId, name);
      console.log(`Channel linked: ${platform}:${channelId} -> ${project}`);
      break;
    }
    case "unlink": {
      const platform = extractFlag(args, "--platform") ?? "";
      const channelId = extractFlag(args, "--channel-id") ?? "";
      if (!platform || !channelId) {
        console.error("Usage: channel unlink --platform <p> --channel-id <id>");
        process.exit(1);
      }
      store.unlinkChannel(platform, channelId);
      console.log(`Channel unlinked: ${platform}:${channelId}`);
      break;
    }
    default:
      console.error("Usage: safefence channel link|unlink");
  }
}

// Helpers — extractFlag imported from ../utils/args.js

function getPositional(args: string[], index: number): string | null {
  let pos = 0;
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith("--")) {
      i++; // skip flag value
      continue;
    }
    if (pos === index) return args[i];
    pos++;
  }
  return null;
}

function splitPlatformId(combined: string): [string, string] {
  const idx = combined.indexOf(":");
  if (idx === -1) return ["unknown", combined];
  return [combined.substring(0, idx), combined.substring(idx + 1)];
}

main();

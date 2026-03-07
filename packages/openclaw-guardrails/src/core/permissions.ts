/**
 * Shared tool-to-permission mapping used by both the principal-authz detector
 * and the ConfigRoleStore backward-compatibility layer.
 */

/**
 * Maps a tool name to the corresponding RBAC action string.
 * Returns "read" for unknown tools (safe default).
 */
export function toolToAction(tool: string): string {
  switch (tool) {
    case "read":
    case "search":
      return "read";
    case "write":
    case "edit":
      return "write";
    case "exec":
    case "process":
      return "exec";
    case "apply_patch":
      return "apply_patch";
    case "skills.install":
      return "skills_install";
    default:
      return "read";
  }
}

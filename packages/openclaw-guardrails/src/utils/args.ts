/**
 * Shared CLI argument parsing utilities.
 * Used by both the plugin extension (/sf commands) and the standalone CLI.
 */

/** Extract a flag value from an args array: `--flag value` → `"value"`. */
export function extractFlag(args: string[], flag: string): string | null {
  const idx = args.indexOf(flag);
  if (idx === -1 || idx + 1 >= args.length) return null;
  return args[idx + 1];
}

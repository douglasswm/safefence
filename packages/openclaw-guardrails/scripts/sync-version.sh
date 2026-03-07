#!/usr/bin/env bash
# Syncs the version from package.json to all other locations.
# Called automatically by `npm version` via the "version" lifecycle script.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PKG_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$PKG_DIR/../.." && pwd)"

VERSION="$(node -p "require('$PKG_DIR/package.json').version")"

echo "Syncing version $VERSION across all files..."

# 1. openclaw.plugin.json
sed -i '' "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" "$PKG_DIR/openclaw.plugin.json"

# 2. src/plugin/version.ts
cat > "$PKG_DIR/src/plugin/version.ts" << EOF
export const PLUGIN_VERSION = "$VERSION";
EOF

# 3. Root README.md — "Current version: \`X.Y.Z\`"
sed -i '' "s/Current version: \`[^\`]*\`/Current version: \`$VERSION\`/" "$REPO_ROOT/README.md"

# Stage the synced files so they're included in npm version's auto-commit
git add \
  "$PKG_DIR/openclaw.plugin.json" \
  "$PKG_DIR/src/plugin/version.ts" \
  "$REPO_ROOT/README.md"

echo "Version $VERSION synced to all files."

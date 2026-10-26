#!/usr/bin/env bash
# Bump VERSION and prepend a CHANGELOG.md entry in one step.
# Usage: ./scripts/bump-version.sh <major|minor|patch> "Short description" ["Second bullet"] ...
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_FILE="$ROOT_DIR/VERSION"
CHANGELOG_FILE="$ROOT_DIR/CHANGELOG.md"

PART="${1:-}"
shift || true
if [[ -z "$PART" || $# -eq 0 ]]; then
  echo "Usage: $0 <major|minor|patch> \"change description\" [\"more bullets\"...]" >&2
  exit 1
fi

CURRENT="$(cat "$VERSION_FILE")"
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT"

case "$PART" in
  major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
  minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
  patch) PATCH=$((PATCH + 1)) ;;
  *) echo "First arg must be major, minor, or patch" >&2; exit 1 ;;
esac

NEW_VERSION="${MAJOR}.${MINOR}.${PATCH}"
TODAY="$(date +%Y-%m-%d)"

echo -n "$NEW_VERSION" > "$VERSION_FILE"

# Read the whole file into memory FIRST — writing straight into
# $CHANGELOG_FILE while also reading from it inside the same redirected
# block truncates it out from under you before the read happens.
PREAMBLE="$(awk '/^## \[/{exit} {print}' "$CHANGELOG_FILE")"
ENTRIES="$(awk 'BEGIN{found=0} /^## \[/{found=1} found{print}' "$CHANGELOG_FILE")"

{
  printf '%s\n' "$PREAMBLE"
  echo ""
  echo "## [$NEW_VERSION] - $TODAY"
  echo "### Changed"
  for msg in "$@"; do
    echo "- $msg"
  done
  echo ""
  printf '%s\n' "$ENTRIES"
} > /tmp/changelog.new.$$

mv /tmp/changelog.new.$$ "$CHANGELOG_FILE"

echo "Bumped $CURRENT -> $NEW_VERSION"
echo "Updated CHANGELOG.md. /version and the Settings screen pick this up on next run."
echo
echo "To ship this as a signed release:"
echo "  git add VERSION CHANGELOG.md && git commit -m \"release: v$NEW_VERSION\""
echo "  git tag v$NEW_VERSION && git push && git push --tags"
echo "  # .github/workflows/release.yml builds core for all platforms, builds +"
echo "  # signs + notarizes the desktop app, and publishes a GitHub release."

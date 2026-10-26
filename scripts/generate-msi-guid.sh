#!/usr/bin/env bash
# Generate a fresh GUID for apps/desktop/package.json's build.msi.upgradeCode.
#
# Run this ONCE, right after forking/cloning this repo for your own
# distribution — never again after that. The upgradeCode is how Windows
# recognizes "this MSI is a newer version of that same product" and does
# an in-place upgrade instead of installing a second, unrelated copy.
# Changing it on every release defeats the entire point; regenerating it
# once, up front, for your own org/signing identity is correct and expected
# (the GUID shipped in this scaffold is just this build's own default).
set -euo pipefail

if command -v uuidgen >/dev/null 2>&1; then
  GUID="$(uuidgen | tr '[:lower:]' '[:upper:]')"
elif command -v python3 >/dev/null 2>&1; then
  GUID="$(python3 -c 'import uuid; print(str(uuid.uuid4()).upper())')"
else
  echo "Need uuidgen or python3 to generate a GUID." >&2
  exit 1
fi

echo "New upgradeCode: $GUID"
echo
echo "Set this in apps/desktop/package.json under build.msi.upgradeCode,"
echo "commit it, and never change it again for this product line."

#!/usr/bin/env bash
#
# Build a distributable Datametric Login Shield plugin .zip.
# Usage: ./build.sh
#
set -euo pipefail

SLUG="datametric-login-shield"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="${ROOT}/dist"
STAGE="${DIST}/${SLUG}"

VERSION="$(grep -oE "define\( 'DLS_VERSION', '[^']+'" "${ROOT}/${SLUG}.php" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" || echo "dev")"

echo "Building ${SLUG} v${VERSION}…"

rm -rf "${DIST}"
mkdir -p "${STAGE}"

# Copy everything, then strip dev/build artefacts.
rsync -a \
  --exclude '.git' \
  --exclude '.github' \
  --exclude '.gitignore' \
  --exclude '.distignore' \
  --exclude 'node_modules' \
  --exclude 'vendor' \
  --exclude 'tests' \
  --exclude '_original' \
  --exclude 'dist' \
  --exclude 'composer.json' \
  --exclude 'composer.lock' \
  --exclude 'phpcs.xml.dist' \
  --exclude 'build.sh' \
  --exclude 'README.md' \
  --exclude '*.log' \
  --exclude '.DS_Store' \
  "${ROOT}/" "${STAGE}/"

# Optional production Composer autoload (only if composer is available and needed).
if [ -f "${ROOT}/composer.json" ] && command -v composer >/dev/null 2>&1; then
  if grep -q '"require"' "${ROOT}/composer.json"; then
    :
  fi
fi

( cd "${DIST}" && zip -rq "${SLUG}.${VERSION}.zip" "${SLUG}" )

echo "Done: ${DIST}/${SLUG}.${VERSION}.zip"

#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SRC_DEFAULT="${SCRIPT_DIR}/../rustdesk/flutter/build/web"
SRC_INPUT="${1:-$SRC_DEFAULT}"

if [[ ! -d "$SRC_INPUT" ]]; then
  echo "Source web build not found: $SRC_INPUT" >&2
  exit 1
fi

SRC="$(cd "$SRC_INPUT" && pwd -P)"
DST="${SCRIPT_DIR}/static/web_client"
STATIC_DIR="${SCRIPT_DIR}/static"

if [[ "$SRC" == "/" || "$SRC" == "$DST" ]]; then
  echo "Refusing unsafe web client source: $SRC" >&2
  exit 1
fi
if [[ -n "$(find "$SRC" -type l -print -quit)" ]]; then
  echo "Web client build must not contain symbolic links" >&2
  exit 1
fi

STAGING="$(mktemp -d "${STATIC_DIR}/.web-client-stage.XXXXXX")"
BACKUP=""

cleanup() {
  if [[ -n "$STAGING" && -d "$STAGING" ]]; then
    rm -rf -- "$STAGING"
  fi
  if [[ -n "$BACKUP" && -d "$BACKUP" ]]; then
    if [[ ! -e "$DST" ]]; then
      mv -- "$BACKUP" "$DST"
    else
      rm -rf -- "$BACKUP"
    fi
  fi
}
trap cleanup EXIT

cp -a -- "$SRC"/. "$STAGING"/

# Flutter copies everything under flutter/web into build/web. Only the compiled
# bridge belongs in a deployable artifact; source, package managers and build
# scripts needlessly expose internals and inflate the production image.
rm -rf -- \
  "$STAGING/README.md" \
  "$STAGING/tools" \
  "$STAGING/js/README.md" \
  "$STAGING/js/node_modules" \
  "$STAGING/js/src" \
  "$STAGING/js/tools" \
  "$STAGING/js/package.json" \
  "$STAGING/js/package-lock.json" \
  "$STAGING/js/tsconfig.json" \
  "$STAGING/js/vite.config.ts"

if [[ -f "$STAGING/assets/NOTICES" ]]; then
  sed -i 's/[[:blank:]]\+$//' "$STAGING/assets/NOTICES"
fi

# Flutter embeds flutter.js into the bootstrap but leaves a source-map comment
# even when release builds do not publish the map. WhiteNoise treats the
# dangling comment as a required static dependency, so remove it from both
# emitted copies.
for generated_js in flutter.js flutter_bootstrap.js; do
  if [[ -f "$STAGING/$generated_js" ]]; then
    sed -i '/^[[:blank:]]*\/\/[#@][[:blank:]]*sourceMappingURL=.*$/d' \
      "$STAGING/$generated_js"
  fi
done

required_files=(
  "flutter_bootstrap.js"
  "main.dart.js"
  "manifest.json"
  "canvaskit/canvaskit.wasm"
  "js/dist/web_bridge.js"
)
for required_file in "${required_files[@]}"; do
  if [[ ! -f "$STAGING/$required_file" ]]; then
    echo "Incomplete web client build; missing $required_file" >&2
    exit 1
  fi
done

if [[ -d "$DST" ]]; then
  BACKUP="$(mktemp -d "${STATIC_DIR}/.web-client-backup.XXXXXX")"
  rmdir -- "$BACKUP"
  mv -- "$DST" "$BACKUP"
fi
mv -- "$STAGING" "$DST"
STAGING=""
if [[ -n "$BACKUP" ]]; then
  rm -rf -- "$BACKUP"
  BACKUP=""
fi

echo "Synced runtime-only web client assets to: $DST"

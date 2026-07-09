#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DEFAULT="${SCRIPT_DIR}/../rustdesk/flutter/build/web"
SRC="${1:-$SRC_DEFAULT}"
DST="${SCRIPT_DIR}/static/web_client"

if [[ ! -d "$SRC" ]]; then
  echo "Source web build not found: $SRC" >&2
  exit 1
fi

mkdir -p "$DST"
find "$DST" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
cp -a "$SRC"/. "$DST"/

echo "Synced web client assets to: $DST"

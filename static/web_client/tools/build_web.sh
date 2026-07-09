#!/usr/bin/env bash

set -euo pipefail

MODE=${MODE:=release}
RUN=false
SKIP_JS=false
SKIP_DEPS=false
SKIP_ICONS=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="$2"
      shift 2
      ;;
    --run)
      RUN=true
      shift
      ;;
    --skip-js)
      SKIP_JS=true
      shift
      ;;
    --skip-deps)
      SKIP_DEPS=true
      shift
      ;;
    --skip-icons)
      SKIP_ICONS=true
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLUTTER_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "$FLUTTER_ROOT"

if ! command -v flutter >/dev/null 2>&1; then
  echo "Missing 'flutter'. Install Flutter and ensure it is in PATH." >&2
  exit 1
fi

WEB_DIR="${FLUTTER_ROOT}/web"
WEB_INDEX="${WEB_DIR}/index.html"
WEB_JS_DIR="${WEB_DIR}/js"
WEB_JS_PKG="${WEB_JS_DIR}/package.json"
WEB_JS_LOCK="${WEB_JS_DIR}/package-lock.json"
REPO_ROOT="$(cd "${FLUTTER_ROOT}/.." && pwd)"
PUBSPEC_FILE="${FLUTTER_ROOT}/pubspec.yaml"
APP_VERSION_VALUE="${APP_VERSION:-}"
APP_NAME_VALUE="${APP_NAME:-}"
if [[ -z "$APP_VERSION_VALUE" && -f "$PUBSPEC_FILE" ]]; then
  APP_VERSION_VALUE="$(grep -E '^version:' "$PUBSPEC_FILE" | head -n 1 | sed -E 's/^version:[[:space:]]*//')"
fi

if [[ ! -f "$WEB_INDEX" ]]; then
  echo "Missing web assets: $WEB_INDEX. Ensure flutter/web has index.html, manifest.json, and favicon assets before building." >&2
  exit 2
fi

have_web_deps() {
  [[ -f "${WEB_DIR}/libopus.js" ]] &&
  [[ -f "${WEB_DIR}/libopus.wasm" ]] &&
  [[ -f "${WEB_DIR}/yuv-canvas-1.2.6.js" ]] &&
  [[ -f "${WEB_DIR}/ogvjs-1.8.6/ogv.js" ]]
}

FAVICON_SOURCE="${REPO_ROOT}/res/icon.png"
if [[ -f "$FAVICON_SOURCE" ]]; then
  cp "$FAVICON_SOURCE" "${WEB_DIR}/favicon.png"
fi

flutter pub get
if [[ "$SKIP_ICONS" == "false" ]]; then
  flutter pub run flutter_launcher_icons
fi

if [[ "$SKIP_JS" == "false" ]]; then
  if [[ ! -f "$WEB_JS_PKG" ]]; then
    echo "Missing '$WEB_JS_PKG'. Add the web JS bridge toolchain, or use --skip-js." >&2
    exit 3
  fi
  if ! command -v npm >/dev/null 2>&1; then
    echo "Missing 'npm'. Install Node.js (npm) to build web JS dependencies." >&2
    exit 4
  fi
  pushd "$WEB_JS_DIR" >/dev/null
  if [[ -f "$WEB_JS_LOCK" ]]; then
    npm ci --no-fund --no-audit
  else
    npm install --no-fund --no-audit
  fi
  npm run build
  popd >/dev/null
fi

if [[ "$SKIP_DEPS" == "false" ]]; then
  if have_web_deps; then
    echo "Web deps already present, skipping download."
  else
    DEPS_URL="https://github.com/rustdesk/doc.rustdesk.com/releases/download/console/web_deps.tar.gz"
    DEPS_TAR="${WEB_DIR}/web_deps.tar.gz"
    echo "Downloading web deps: $DEPS_URL"
    if command -v wget >/dev/null 2>&1; then
      wget -O "$DEPS_TAR" "$DEPS_URL"
    else
      curl -L -o "$DEPS_TAR" "$DEPS_URL"
    fi
    tar -xzf "$DEPS_TAR" -C "$WEB_DIR"
    rm -f "$DEPS_TAR"
  fi
fi

FLUTTER_BUILD_ARGS=()
if [[ "$RUN" == "true" ]]; then
  FLUTTER_BUILD_ARGS=("run" "-d" "chrome" "-v")
  if [[ "$MODE" == "release" ]]; then
    FLUTTER_BUILD_ARGS+=("--release")
  elif [[ "$MODE" == "profile" ]]; then
    FLUTTER_BUILD_ARGS+=("--profile")
  fi
else
  FLUTTER_BUILD_ARGS=("build" "web" "--${MODE}")
fi
if [[ -n "${RS_PUB_KEY:-}" ]]; then
  FLUTTER_BUILD_ARGS+=("--dart-define=RS_PUB_KEY=${RS_PUB_KEY}")
fi
if [[ -n "${RENDEZVOUS_SERVERS:-}" ]]; then
  FLUTTER_BUILD_ARGS+=("--dart-define=RENDEZVOUS_SERVERS=${RENDEZVOUS_SERVERS}")
fi
if [[ -n "${API_SERVER:-}" ]]; then
  FLUTTER_BUILD_ARGS+=("--dart-define=API_SERVER=${API_SERVER}")
fi
if [[ -n "$APP_NAME_VALUE" ]]; then
  FLUTTER_BUILD_ARGS+=("--dart-define=APP_NAME=${APP_NAME_VALUE}")
fi
if [[ -n "$APP_VERSION_VALUE" ]]; then
  FLUTTER_BUILD_ARGS+=("--dart-define=APP_VERSION=${APP_VERSION_VALUE}")
fi
BUILD_DATE_VALUE="$(date '+%Y-%m-%d %H:%M')"
FLUTTER_BUILD_ARGS+=("--dart-define=BUILD_DATE=${BUILD_DATE_VALUE}")

flutter "${FLUTTER_BUILD_ARGS[@]}"

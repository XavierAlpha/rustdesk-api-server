#!/bin/sh
set -eu

APP_DIR="/camellia-server"
cd "$APP_DIR"

if [ "$#" -gt 0 ]; then
    exec "$@"
fi

PORT="${PORT:-21114}"
HOST="${HOST:-0.0.0.0}"
WORKERS="${GUNICORN_WORKERS:-2}"
THREADS="${GUNICORN_THREADS:-2}"
TIMEOUT="${GUNICORN_TIMEOUT_SECONDS:-60}"
GRACEFUL_TIMEOUT="${GUNICORN_GRACEFUL_TIMEOUT_SECONDS:-30}"
KEEP_ALIVE="${GUNICORN_KEEP_ALIVE_SECONDS:-5}"
MAX_REQUESTS="${GUNICORN_MAX_REQUESTS:-1000}"
MAX_REQUESTS_JITTER="${GUNICORN_MAX_REQUESTS_JITTER:-100}"
FORWARDED_ALLOW_IPS="${GUNICORN_FORWARDED_ALLOW_IPS:-127.0.0.1}"
RECORD_DIR="${RECORD_UPLOAD_ROOT:-$APP_DIR/records}"

if [ "${DATABASE_TYPE:-SQLITE}" = "SQLITE" ]; then
    DB_FILE="${SQLITE_DB_PATH:-$APP_DIR/db/db.sqlite3}"
    DB_DIR="$(dirname "$DB_FILE")"
    if [ ! -d "$DB_DIR" ] || [ ! -w "$DB_DIR" ]; then
        echo "SQLite database directory is not writable: $DB_DIR" >&2
        exit 1
    fi
fi

if [ ! -d "$RECORD_DIR" ] || [ ! -w "$RECORD_DIR" ]; then
    echo "Recording directory is not writable: $RECORD_DIR" >&2
    exit 1
fi

case "${RUN_MIGRATIONS:-false}" in
    1|true|TRUE|yes|YES)
        python manage.py migrate --noinput
        ;;
    0|false|FALSE|no|NO)
        ;;
    *)
        echo "RUN_MIGRATIONS must be true or false" >&2
        exit 1
        ;;
esac

python manage.py check

exec gunicorn rustdesk_server_api.wsgi:application \
    --bind "$HOST:$PORT" \
    --workers "$WORKERS" \
    --threads "$THREADS" \
    --timeout "$TIMEOUT" \
    --graceful-timeout "$GRACEFUL_TIMEOUT" \
    --keep-alive "$KEEP_ALIVE" \
    --max-requests "$MAX_REQUESTS" \
    --max-requests-jitter "$MAX_REQUESTS_JITTER" \
    --worker-tmp-dir /tmp \
    --forwarded-allow-ips "$FORWARDED_ALLOW_IPS" \
    --access-logfile "-" \
    --error-logfile "-" \
    --capture-output

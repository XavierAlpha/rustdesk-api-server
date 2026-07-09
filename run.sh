#!/bin/sh
set -eu

APP_DIR="/camellia-server"
cd "$APP_DIR"

DB_FILE="${SQLITE_DB_PATH:-$APP_DIR/db/db.sqlite3}"
DB_DIR="$(dirname "$DB_FILE")"
PORT="${PORT:-21114}"
HOST="${HOST:-0.0.0.0}"
WORKERS="${GUNICORN_WORKERS:-2}"

mkdir -p "$DB_DIR"
if [ ! -w "$DB_DIR" ]; then
    echo "数据库目录不可写: $DB_DIR" >&2
    ls -ld "$DB_DIR" >&2 || true
    exit 1
fi

if [ ! -f "$DB_FILE" ]; then
    touch "$DB_FILE"
    echo "首次运行，初始化数据库"
fi

python manage.py migrate --noinput
python manage.py collectstatic --noinput --clear
exec gunicorn rustdesk_server_api.wsgi:application \
    --bind "$HOST:$PORT" \
    --workers "$WORKERS" \
    --access-logfile "-" \
    --error-logfile "-"

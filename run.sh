#!/bin/sh
set -eu

cd /rustdesk-api-server

DB_FILE="${SQLITE_DB_PATH:-/rustdesk-api-server/db/db.sqlite3}"
DB_DIR="$(dirname "$DB_FILE")"

mkdir -p "$DB_DIR"
if [ ! -w "$DB_DIR" ]; then
    echo "数据库目录不可写: $DB_DIR" >&2
    ls -ld "$DB_DIR" >&2 || true
    exit 1
fi

if [ ! -f "$DB_FILE" ]; then
    if [ -f "/rustdesk-api-server/db_bak/db.sqlite3" ]; then
        cp "/rustdesk-api-server/db_bak/db.sqlite3" "$DB_FILE"
    else
        touch "$DB_FILE"
    fi
    echo "首次运行，初始化数据库"
fi

python manage.py makemigrations
python manage.py migrate
python manage.py runserver "$HOST:21114"

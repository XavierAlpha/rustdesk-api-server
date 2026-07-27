# Camellia API Server

Camellia API Server is the management and coordination service used by the Camellia client, RustDesk Server, and the bundled Web client. It provides account authentication, device management, address books, device groups, strategy delivery, audit logs, plugin signing, and the static Web client entry point.

## Features

- `/api/*`: client authentication, devices, address books, device groups, strategies, and audit APIs.
- `/lic/web/api/plugin-sign`: Ed25519 plugin signing for authenticated administrators.
- `/webui2/`: Web client entry page that loads `static/web_client`.
- `/admin/`: Django admin.

## Requirements

- Python 3.14
- Django 6
- SQLite or MySQL 8+
- Optional: Docker 25+ / Docker Compose v2

## Local Development

```bash
cd camellia-api-server
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

export DEBUG=true
export SECRET_KEY=dev-only-secret
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver 0.0.0.0:21114
```

Quality checks:

```bash
python -m compileall api webui2 rustdesk_server_api
python -m ruff check api webui2 rustdesk_server_api
python manage.py check
python manage.py makemigrations --check --dry-run
python -m pytest
```

## Production Environment

| Variable | Default | Description |
| --- | --- | --- |
| `DEBUG` | `false` | Keep disabled in production. |
| `SECRET_KEY` | unset | Required when `DEBUG=false`; use a strong random value. |
| `ALLOWED_HOSTS` | `127.0.0.1,localhost` | Allowed Django hosts. |
| `CSRF_TRUSTED_ORIGINS` | `http://127.0.0.1:21114` | Public or reverse-proxy origins. |
| `SECURE_TLS` | `false` | Production HTTPS mode: secure cookies, proxy scheme handling, HTTPS redirects, and HSTS. |
| `SECURE_HSTS_SECONDS` | `31536000` in TLS mode | HSTS lifetime; enable only after the hostname is permanently HTTPS-only. |
| `SECURE_HSTS_INCLUDE_SUBDOMAINS` | `true` in TLS mode | Applies HSTS to child hostnames; explicitly disable for mixed-HTTP domains. |
| `SECURE_HSTS_PRELOAD` | `true` in TLS mode | Emits the HSTS preload directive; review the domain policy before preload-list submission. |
| `TRUST_PROXY_HEADERS` | `false` | Enable only when the front proxy overwrites client forwarding headers. |
| `LANGUAGE_CODE` | `zh-hans` | `zh-hans` or `en`. |
| `TIME_ZONE` | `Asia/Shanghai` | Django time zone. |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL`. |
| `PORT` | `21114` | Gunicorn listen port. |
| `HOST` | `0.0.0.0` | Gunicorn bind host. |
| `GUNICORN_WORKERS` | `2` | Gunicorn worker count. |
| `ALLOW_REGISTRATION` | `false` | Enables public registration; registered accounts are always regular users. |
| `PLUGIN_SIGNING_KEY` | unset | 32-byte Ed25519 signing key in base64 or hex. The signing endpoint returns 503 when unset. |
| `RECORD_UPLOAD_MAX_CHUNK_BYTES` | `4194304` | Maximum bytes accepted by one recording upload request. |
| `RECORD_UPLOAD_MAX_FILE_BYTES` | `10737418240` | Maximum bytes stored for one recording. |
| `RECORD_UPLOAD_ROOT` | `records` | Root for per-user, per-device recording namespaces. |

Create the first administrator explicitly with `python manage.py createsuperuser` or a controlled provisioning workflow. Public registration never grants administrator privileges.

### Database

| Variable | Default | Description |
| --- | --- | --- |
| `DATABASE_TYPE` | `SQLITE` | `SQLITE` or `MYSQL`. |
| `SQLITE_DB_PATH` | `db/db.sqlite3` | SQLite file path. |
| `MYSQL_DBNAME` | `-` | MySQL database name. |
| `MYSQL_HOST` | `127.0.0.1` | MySQL host. |
| `MYSQL_USER` | `-` | MySQL user. |
| `MYSQL_PASSWORD` | `-` | MySQL password. |
| `MYSQL_PORT` | `3306` | MySQL port. |

The default dependency set targets SQLite. Install the optional MySQL driver only when MySQL is used:

```bash
pip install -r requirements-mysql.txt
```

### Server and Web Client Coordination

| Variable | Default | Description |
| --- | --- | --- |
| `ID_SERVER` | empty | Rendezvous server list, separated by comma, semicolon, whitespace, or newline. |
| `RELAY_SERVER` | empty | Relay server list. When empty, it is derived from `ID_SERVER` and the port rules. |
| `DEFAULT_ID_PORT` | `21116` | Base ID service port. |
| `API_SERVER` | empty | API URL exposed to the Web client. |
| `RS_PUB_KEY` | empty | RustDesk Server public key; must match the server `RS_PRIV_KEY`. |
| `OIDC_NAME` | empty | OIDC login provider name. |
| `OIDC_ISSUER` | empty | OIDC issuer. |
| `OIDC_CLIENT_ID` | empty | OIDC client id. |
| `OIDC_CLIENT_SECRET` | empty | OIDC client secret. |
| `OIDC_REDIRECT_URI` | empty | OIDC callback URL, usually `https://api.example.com/api/oidc/callback`. |
| `OIDC_SCOPE` | `openid email profile` | OIDC scope. |

## Docker

```bash
docker build -t camellia-api-server:latest .
docker run -d \
  --name camellia-api-server \
  -p 21114:21114 \
  -e SECRET_KEY='<strong-random-secret>' \
  -e ALLOWED_HOSTS='api.example.com' \
  -e CSRF_TRUSTED_ORIGINS='https://api.example.com' \
  -e ID_SERVER='wss://id.example.com' \
  -e API_SERVER='https://api.example.com' \
  -e RS_PUB_KEY='<server-public-key>' \
  -v /data/camellia-api/db:/camellia-server/db \
  -v /data/camellia-api/records:/camellia-server/records \
  --restart unless-stopped \
  camellia-api-server:latest
```

Build a MySQL-capable image:

```bash
docker build --build-arg INSTALL_MYSQL=true -t camellia-api-server:mysql .
```

See [docker-compose.yaml](docker-compose.yaml) for a Compose example.

## Web Client Assets

`static/web_client` is the release asset directory. It is built from `rustdesk/flutter/web/tools` in the client repository and copied into this project. Do not commit `static/web_client/js/node_modules`; keep only runtime assets and bridge output.

## CI

The repository contains two workflows:

- `API Server CI`: compile checks, Ruff, Django checks, migration checks, and tests.
- `API Server Docker`: manually triggered image build and optional GHCR / Docker Hub publishing with selectable target platforms.

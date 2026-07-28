# Camellia API Server

Camellia API Server is the management and coordination service used by the Camellia client, RustDesk Server, and the bundled Web client. It provides account authentication, device management, address books, device groups, strategy delivery, audit logs, plugin signing, and the static Web client entry point.

## Features

- `/api/*`: client authentication, devices, address books, device groups, strategies, and audit APIs.
- `/lic/web/api/plugin-sign`: Ed25519 plugin signing for authenticated administrators.
- `/webui2/`: Web client entry page that loads `static/web_client`.
- `/admin/`: Django admin.

## Requirements

- Python 3.13+ (CI and the container use Python 3.14)
- Django 6
- SQLite or MySQL 8+
- Optional: Docker 25+ / Docker Compose v2

## Local Development

```bash
cd camellia-api-server
uv sync --locked --all-groups

export DEBUG=true
uv run python manage.py migrate
uv run python manage.py createsuperuser
uv run python manage.py runserver 0.0.0.0:21114
```

Quality checks:

```bash
uv run python -m compileall api webui2 rustdesk_server_api
uv run ruff check api webui2 rustdesk_server_api
uv run python manage.py check
uv run python manage.py makemigrations --check --dry-run
uv run pytest --create-db
```

Because this project has not launched, the migration history is deliberately compressed into one `api/0001_initial.py`. Deploy only to an empty database; an old development database is not a supported production upgrade source.

## Production Environment

| Variable | Default | Description |
| --- | --- | --- |
| `DEBUG` | `false` | Keep disabled in production. |
| `SECRET_KEY` | unset | Required when `DEBUG=false`; use a strong random value. |
| `DATA_ENCRYPTION_KEY` | unset | Required; a canonical Base64-encoded 32-byte key used for sensitive fields. Encrypted data is unrecoverable if this key is lost. |
| `DEVICE_VERIFICATION_TOKEN` | unset | Required; a 32–512 character secret without whitespace. It must exactly match the RustDesk Server variable of the same name. |
| `ALLOWED_HOSTS` | `127.0.0.1,localhost` | Allowed Django hosts. |
| `CSRF_TRUSTED_ORIGINS` | `http://127.0.0.1:21114` | Public or reverse-proxy origins. |
| `SECURE_TLS` | `false` | Production HTTPS mode: secure cookies, proxy scheme handling, HTTPS redirects, and HSTS. |
| `SECURE_HSTS_SECONDS` | `31536000` in TLS mode | HSTS lifetime; enable only after the hostname is permanently HTTPS-only. |
| `SECURE_HSTS_INCLUDE_SUBDOMAINS` | `false` | Applies HSTS to child hostnames; enable only after the entire child namespace is permanently HTTPS-only. |
| `SECURE_HSTS_PRELOAD` | `false` | Emits the HSTS preload directive; enable only when the domain is ready for preload-list submission. |
| `TRUST_PROXY_HEADERS` | `false` | Enable only when the front proxy overwrites client forwarding headers. |
| `TRUSTED_PROXY_CIDRS` | empty | Required with trusted proxy headers; only these direct proxy networks may supply client-address headers. |
| `LANGUAGE_CODE` | `zh-hans` | `zh-hans` or `en`. |
| `TIME_ZONE` | `Asia/Shanghai` | Django time zone. |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL`. |
| `PORT` | `21114` | Gunicorn listen port. |
| `HOST` | `0.0.0.0` | Gunicorn bind host. |
| `GUNICORN_WORKERS` | `2` | Gunicorn worker count. |
| `GUNICORN_THREADS` | `2` | Thread count per worker. |
| `GUNICORN_FORWARDED_ALLOW_IPS` | `127.0.0.1` | Proxy source addresses from which Gunicorn accepts scheme headers. |
| `RUN_MIGRATIONS` | `false` | Runs migrations before startup. Prefer a dedicated one-off migration task. |
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
| `SQLITE_BUSY_TIMEOUT_SECONDS` | `20` | SQLite write-lock wait limit. |
| `MYSQL_DBNAME` | `-` | MySQL database name. |
| `MYSQL_HOST` | `127.0.0.1` | MySQL host. |
| `MYSQL_USER` | `-` | MySQL user. |
| `MYSQL_PASSWORD` | `-` | MySQL password. |
| `MYSQL_PORT` | `3306` | MySQL port. |
| `DATABASE_CONN_MAX_AGE` | `60` | MySQL persistent-connection lifetime. |
| `DATABASE_CONNECT_TIMEOUT` | `10` | MySQL connection timeout. |

SQLite uses WAL, `IMMEDIATE` transactions, and a busy timeout. It is intended for one API application instance. Use MySQL for multiple replicas or sustained write-heavy workloads. Install its optional driver with:

```bash
uv sync --locked --extra mysql
```

### Server and Web Client Coordination

| Variable | Default | Description |
| --- | --- | --- |
| `ID_SERVER` | empty | Rendezvous server list, separated by comma, semicolon, whitespace, or newline. |
| `RELAY_SERVER` | empty | Relay server list. When empty, it is safely derived from `ID_SERVER` and its port rules. |
| `DEFAULT_ID_PORT` | `21116` | Base ID service port. |
| `API_SERVER` | empty | API URL exposed to the Web client. |
| `RS_PUB_KEY` | empty | RustDesk Server public key; must match the server `RS_PRIV_KEY`. |
| `OIDC_NAME` | empty | OIDC login provider name. |
| `OIDC_ISSUER` | empty | OIDC issuer. |
| `OIDC_CLIENT_ID` | empty | OIDC client id. |
| `OIDC_CLIENT_SECRET` | empty | OIDC client secret. |
| `OIDC_REDIRECT_URI` | empty | OIDC callback URL, usually `https://api.example.com/api/oidc/callback`. |
| `OIDC_SCOPE` | `openid email profile` | OIDC scope. |

A native endpoint is `remote.example.com:21116`; a direct browser WS endpoint is `ws://remote.example.com:21118`. HTTPS pages must use WSS. Configure `wss://remote.example.com:443` explicitly and route `/ws/id` and `/ws/relay` on that origin to RustDesk Server ports `21118` and `21119`. Writing `:443` explicitly prevents the endpoint from being interpreted as a custom WebSocket port.

## Docker

Compose is the recommended deployment path. Copy the environment template, generate three independent secrets, and fill in the public endpoints and server key. Back up the secrets with the database and never rotate them accidentally.

```bash
cp .env.example .env
python -c 'import secrets; print(secrets.token_urlsafe(64))'
python -c 'import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())'

./sync_web_client.sh --build-from ../rustdesk
docker compose build
docker compose run --rm camellia-server python manage.py migrate --noinput
docker compose run --rm camellia-server python manage.py createsuperuser
docker compose up -d
docker compose ps
```

Compose binds the API only to host `127.0.0.1:21114` by default. The container runs as a non-root user with a read-only root filesystem, all Linux capabilities removed, and named `camellia-db` and `camellia-records` volumes for persistent data. `/health/live` reports process liveness; `/health/ready` also verifies required configuration, database connectivity, and the migrated core table.

The reverse proxy must overwrite, not append, `X-Forwarded-For` and `X-Forwarded-Proto`. Set `GUNICORN_FORWARDED_ALLOW_IPS` to the proxy source address observed by the container and retain `127.0.0.1` for the internal readiness probe, for example `127.0.0.1,172.17.0.1`. If real client addresses are needed, also enable `TRUST_PROXY_HEADERS` and put that trusted network in `TRUSTED_PROXY_CIDRS`. A proxy on the Docker host normally reaches the container from a bridge gateway address, not `127.0.0.1`.

Build a MySQL-capable image:

```bash
docker build --build-arg INSTALL_MYSQL=true -t camellia-api-server:mysql .
```

See [docker-compose.yaml](docker-compose.yaml) for a Compose example.

## Web Client Assets

The only Web source tree is `rustdesk/flutter/web` in the client repository. This repository retains only one immutable full commit in `web-client.lock`; generated `static/web_client` assets are ignored by Git and are no longer committed. Pure API development and ordinary unit tests do not need a local Web build. Generate one only before serving `/webui2/`, building a container, or validating the complete runtime locally:

```bash
git -C ../rustdesk checkout "$(./scripts/web_client_revision.sh)"
./sync_web_client.sh --build-from ../rustdesk
```

The script runs the canonical client release build, requires both the local repository and artifact provenance to match the locked commit, atomically replaces the runtime assets, and strips source, package-manager files, and build tools. To synchronize an existing build, use `--source ../rustdesk/flutter/build/web` explicitly. Unknown, dirty, or unlocked artifacts are rejected. To update Web, first commit and push RustDesk, then change `web-client.lock` to that full commit; never commit the generated directory.

CI only accesses a RustDesk repository owned by the same GitHub owner as the API repository. Its name defaults to `rustdesk`. If the repository is renamed, set the Actions repository variable `RUSTDESK_REPOSITORY_NAME` in the API repository. The value must be one unqualified repository name without an owner or `/`, so source cannot be fetched across accounts. The locked commit must also be reachable from that repository's default branch and have a successful push `CI / Required`; an unreviewed branch or client commit that failed CI cannot enter the API image.

## CI

The repository contains two workflows:

- `CI` is the shared entry point for pull requests, `master` pushes, and manual reruns. Documentation-only changes run classification, version consistency, and the stable `CI / Required` gate. Runtime changes build or restore the `web-client.lock` revision from the same owner's repository, then reuse one artifact for quality and container checks. Dependency pull requests additionally review the dependency-graph delta. Full validation covers locked installation and auditing, compilation, Ruff, development and production Django checks, migration drift, a fresh-database migration, tests, and a readiness probe against a read-only non-root container.
- `Release` accepts only a manually selected ref reachable from the default branch. It requires a successful push `CI` for that exact commit and reuses its unexpired Web artifact, so it neither reruns tests nor rebuilds Web. One multi-architecture build can push the same digest to GHCR and/or Docker Hub. `publish=false` is the safe dry-run default; a production run passes the `release` environment gate before creating the component-derived `vMAJOR.MINOR.PATCH` tag, GitHub Release, and traceability manifest.

The API version is independent of client and server versions. Before release, update `pyproject.toml`, the virtual project entry in `uv.lock`, and `version.py`, then run `python scripts/release_metadata.py`. CI rejects inconsistent values, non-stable SemVer, and duplicate release tags. Web artifacts are retained for 14 days; rerun the corresponding push CI run before release if its artifact has expired.

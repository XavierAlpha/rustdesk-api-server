# Camellia API Server

Camellia API Server 是 Camellia 客户端、RustDesk Server 与 Web 控制端之间的管理与协同服务。它提供账号认证、设备管理、地址簿、设备组、策略、审计日志、插件签名和 Web 客户端静态入口。

## 功能

- `/api/*`：客户端认证、设备、地址簿、设备组、策略与审计接口。
- `/lic/web/api/plugin-sign`：仅管理员 Bearer 会话可用的 Ed25519 插件签名接口。
- `/webui2/`：Web 客户端入口，加载 `static/web_client`。
- `/admin/`：Django 管理后台。

## 运行要求

- Python 3.13+（CI 与容器使用 Python 3.14）
- Django 6
- SQLite 或 MySQL 8+
- 可选：Docker 25+ / Docker Compose v2

## 本地开发

```bash
cd camellia-api-server
uv sync --locked --all-groups

export DEBUG=true
uv run python manage.py migrate
uv run python manage.py createsuperuser
uv run python manage.py runserver 0.0.0.0:21114
```

质量检查：

```bash
uv run python -m compileall api webui2 rustdesk_server_api
uv run ruff check api webui2 rustdesk_server_api
uv run python manage.py check
uv run python manage.py makemigrations --check --dry-run
uv run pytest --create-db
```

当前项目尚未上线，迁移历史已压缩为单一的 `api/0001_initial.py`。部署目标必须使用空数据库；不要把旧开发数据库当作可升级的生产数据库。

## 生产环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DEBUG` | `false` | 生产环境保持 `false`。 |
| `SECRET_KEY` | 无 | `DEBUG=false` 时必须提供高强度随机值。 |
| `DATA_ENCRYPTION_KEY` | 无 | 必需；规范 Base64 编码的 32 字节密钥，用于加密敏感字段。丢失后已加密数据无法恢复。 |
| `DEVICE_VERIFICATION_TOKEN` | 无 | 必需；32–512 位无空白共享密钥，必须与 RustDesk Server 的同名变量完全一致。 |
| `ALLOWED_HOSTS` | `127.0.0.1,localhost` | Django 允许访问的主机名。 |
| `CSRF_TRUSTED_ORIGINS` | `http://127.0.0.1:21114` | 反向代理或公开域名 Origin。 |
| `SECURE_TLS` | `false` | 生产 HTTPS 模式：启用安全 Cookie、代理协议识别、HTTPS 跳转和 HSTS。 |
| `SECURE_HSTS_SECONDS` | TLS 模式下 `31536000` | HSTS 时长；仅在确认域名始终使用 HTTPS 后启用。 |
| `SECURE_HSTS_INCLUDE_SUBDOMAINS` | `false` | 将 HSTS 应用于该主机的子域；仅在整个子域空间都永久使用 HTTPS 后启用。 |
| `SECURE_HSTS_PRELOAD` | `false` | 输出 HSTS preload 指令；仅在确认并准备提交 preload 列表后启用。 |
| `TRUST_PROXY_HEADERS` | `false` | 仅当前置代理覆盖客户端转发头时启用。 |
| `TRUSTED_PROXY_CIDRS` | 空 | 启用代理头时必需；仅这些直连代理可提供客户端地址头。 |
| `LANGUAGE_CODE` | `zh-hans` | `zh-hans` 或 `en`。 |
| `TIME_ZONE` | `Asia/Shanghai` | Django 时区。 |
| `LOG_LEVEL` | `INFO` | `DEBUG`、`INFO`、`WARNING`、`ERROR`、`CRITICAL`。 |
| `PORT` | `21114` | Gunicorn 监听端口。 |
| `HOST` | `0.0.0.0` | Gunicorn 监听地址。 |
| `GUNICORN_WORKERS` | `2` | Gunicorn worker 数量。 |
| `GUNICORN_THREADS` | `2` | 每个 worker 的线程数。 |
| `GUNICORN_FORWARDED_ALLOW_IPS` | `127.0.0.1` | Gunicorn 接受协议转发头的代理源地址。 |
| `RUN_MIGRATIONS` | `false` | 启动前自动迁移；推荐保持关闭并使用显式的一次性迁移任务。 |
| `ALLOW_REGISTRATION` | `false` | 是否允许前台注册；注册用户始终为普通用户。 |
| `PLUGIN_SIGNING_KEY` | 无 | 32 字节 Ed25519 私钥，支持 base64 或 hex。未配置时插件签名返回 503。 |
| `RECORD_UPLOAD_MAX_CHUNK_BYTES` | `4194304` | 单次录像上传请求的最大字节数。 |
| `RECORD_UPLOAD_MAX_FILE_BYTES` | `10737418240` | 单个录像文件的最大字节数。 |
| `RECORD_UPLOAD_ROOT` | `records` | 按用户和设备隔离保存的录像根目录。 |

生产环境必须通过 `python manage.py createsuperuser` 或受控的自动化流程显式创建首位管理员。公开注册绝不会自动授予管理员权限。

### 数据库

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DATABASE_TYPE` | `SQLITE` | `SQLITE` 或 `MYSQL`。 |
| `SQLITE_DB_PATH` | `db/db.sqlite3` | SQLite 数据库文件路径。 |
| `SQLITE_BUSY_TIMEOUT_SECONDS` | `20` | SQLite 写锁等待上限。 |
| `MYSQL_DBNAME` | `-` | MySQL 数据库名。 |
| `MYSQL_HOST` | `127.0.0.1` | MySQL 主机。 |
| `MYSQL_USER` | `-` | MySQL 用户。 |
| `MYSQL_PASSWORD` | `-` | MySQL 密码。 |
| `MYSQL_PORT` | `3306` | MySQL 端口。 |
| `DATABASE_CONN_MAX_AGE` | `60` | MySQL 持久连接秒数。 |
| `DATABASE_CONNECT_TIMEOUT` | `10` | MySQL 建连超时秒数。 |

SQLite 使用 WAL、`IMMEDIATE` 事务与忙等待，适合单个 API 应用实例。多副本部署或持续高写入负载必须改用 MySQL。使用 MySQL 时安装可选驱动：

```bash
uv sync --locked --extra mysql
```

### 服务端与 Web 客户端协同

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `ID_SERVER` | 空 | Rendezvous 服务地址，支持逗号、分号、空格或换行分隔。 |
| `RELAY_SERVER` | 空 | Relay 服务地址；为空时由 `ID_SERVER` 和端口规则安全推导。 |
| `DEFAULT_ID_PORT` | `21116` | ID 服务基准端口。 |
| `API_SERVER` | 空 | Web 客户端展示和调用的 API 服务地址。 |
| `RS_PUB_KEY` | 空 | RustDesk Server 公钥，必须与服务端 `RS_PRIV_KEY` 匹配。 |
| `OIDC_NAME` | 空 | OIDC 登录入口名称。 |
| `OIDC_ISSUER` | 空 | OIDC issuer。 |
| `OIDC_CLIENT_ID` | 空 | OIDC client id。 |
| `OIDC_CLIENT_SECRET` | 空 | OIDC client secret。 |
| `OIDC_REDIRECT_URI` | 空 | OIDC 回调地址，通常为 `https://api.example.com/api/oidc/callback`。 |
| `OIDC_SCOPE` | `openid email profile` | OIDC scope。 |

原生服务地址使用 `remote.example.com:21116`；浏览器直连 WS 使用 `ws://remote.example.com:21118`。HTTPS 页面必须使用 WSS，建议显式配置 `wss://remote.example.com:443`，并由反向代理把同一 Origin 的 `/ws/id` 与 `/ws/relay` 分别转发至 RustDesk Server 的 `21118` 与 `21119`。显式写出 `:443` 可避免被当作自定义 WebSocket 端口。

## Docker

推荐使用 Compose。先从模板创建 `.env`，生成三个独立密钥并填写公开地址、公钥；这些密钥必须和数据库一起备份并在重启时保持不变。

```bash
cp .env.example .env
python -c 'import secrets; print(secrets.token_urlsafe(64))'
python -c 'import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())'

docker compose build
docker compose run --rm camellia-server python manage.py migrate --noinput
docker compose run --rm camellia-server python manage.py createsuperuser
docker compose up -d
docker compose ps
```

Compose 默认只把 API 绑定到宿主机 `127.0.0.1:21114`，容器以非 root、只读根文件系统、移除 Linux capabilities 的方式运行；持久数据位于 `camellia-db` 与 `camellia-records` 命名卷。`/health/live` 只表示进程存活，`/health/ready` 同时检查必要配置、数据库连接和迁移后的核心表。

反向代理必须覆盖而不是追加 `X-Forwarded-For` 与 `X-Forwarded-Proto`。把 `GUNICORN_FORWARDED_ALLOW_IPS` 设为容器实际看到的代理源地址，并保留 `127.0.0.1` 供内部就绪探针使用，例如 `127.0.0.1,172.17.0.1`；需要记录真实客户端地址时，再启用 `TRUST_PROXY_HEADERS` 并把同一受信网络写入 `TRUSTED_PROXY_CIDRS`。Docker 宿主机代理通常以桥接网关地址进入容器，而不是 `127.0.0.1`。

构建带 MySQL 驱动的镜像：

```bash
docker build --build-arg INSTALL_MYSQL=true -t camellia-api-server:mysql .
```

Compose 示例见 [docker-compose.yaml](docker-compose.yaml)。

## Web 客户端静态资源

Web 源码唯一位于客户端仓库的 `rustdesk/flutter/web`；本仓库的 `static/web_client` 只保存发布所需的 Flutter 构建产物与编译后桥接脚本。推荐运行 `./sync_web_client.sh --build-from ../rustdesk`，脚本会先调用客户端的规范 release 构建，再校验 clean 源码提交标记并原子替换运行资产，同时剔除源码、包管理文件和构建工具。同步已有产物时必须显式使用 `--source ../rustdesk/flutter/build/web`；未携带来源提交或由 dirty 工作树生成的产物会被拒绝。

## CI

仓库包含两个 workflow：

- `API Server CI`：锁文件安装、编译、Ruff、开发/生产 Django check、迁移漂移检查、空数据库迁移、完整测试，以及只读非 root 容器的就绪探针。
- `API Server Docker`：手动多架构构建，可选择发布到 GHCR 或 Docker Hub、启用 MySQL 驱动；发布镜像附带最大化 provenance 与 SBOM attestations。

# Camellia API Server

Camellia API Server 是 Camellia 客户端、RustDesk Server 与 Web 控制端之间的管理与协同服务。它提供账号认证、设备管理、地址簿、设备组、策略、审计日志、插件签名和 Web 客户端静态入口。

## 功能

- `/api/*`：客户端认证、设备、地址簿、设备组、策略与审计接口。
- `/lic/web/api/plugin-sign`：插件签名接口，使用 Ed25519 签名密钥。
- `/webui2/`：Web 客户端入口，加载 `static/web_client`。
- `/admin/`：Django 管理后台。

## 运行要求

- Python 3.14
- Django 6
- SQLite 或 MySQL 8+
- 可选：Docker 25+ / Docker Compose v2

## 本地开发

```bash
cd camellia-api-server
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

export DEBUG=true
export SECRET_KEY=dev-only-secret
python manage.py migrate
python manage.py runserver 0.0.0.0:21114
```

质量检查：

```bash
python -m compileall api webui2 rustdesk_server_api
python -m ruff check api webui2 rustdesk_server_api
python manage.py check
python manage.py makemigrations --check --dry-run
python -m pytest
```

## 生产环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DEBUG` | `false` | 生产环境保持 `false`。 |
| `SECRET_KEY` | 无 | `DEBUG=false` 时必须提供高强度随机值。 |
| `ALLOWED_HOSTS` | `127.0.0.1,localhost` | Django 允许访问的主机名。 |
| `CSRF_TRUSTED_ORIGINS` | `http://127.0.0.1:21114` | 反向代理或公开域名 Origin。 |
| `LANGUAGE_CODE` | `zh-hans` | `zh-hans` 或 `en`。 |
| `TIME_ZONE` | `Asia/Shanghai` | Django 时区。 |
| `LOG_LEVEL` | `INFO` | `DEBUG`、`INFO`、`WARNING`、`ERROR`、`CRITICAL`。 |
| `PORT` | `21114` | Gunicorn 监听端口。 |
| `HOST` | `0.0.0.0` | Gunicorn 监听地址。 |
| `GUNICORN_WORKERS` | `2` | Gunicorn worker 数量。 |
| `ALLOW_REGISTRATION` | `true` | 是否允许前台注册。 |
| `PLUGIN_SIGNING_KEY` | 无 | 32 字节 Ed25519 私钥，支持 base64 或 hex。未配置时插件签名返回 503。 |

### 数据库

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DATABASE_TYPE` | `SQLITE` | `SQLITE` 或 `MYSQL`。 |
| `SQLITE_DB_PATH` | `db/db.sqlite3` | SQLite 数据库文件路径。 |
| `MYSQL_DBNAME` | `-` | MySQL 数据库名。 |
| `MYSQL_HOST` | `127.0.0.1` | MySQL 主机。 |
| `MYSQL_USER` | `-` | MySQL 用户。 |
| `MYSQL_PASSWORD` | `-` | MySQL 密码。 |
| `MYSQL_PORT` | `3306` | MySQL 端口。 |

默认依赖面向 SQLite。使用 MySQL 时安装可选驱动：

```bash
pip install -r requirements-mysql.txt
```

### 服务端与 Web 客户端协同

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `ID_SERVER` | 空 | Rendezvous 服务地址，支持逗号、分号、空格或换行分隔。 |
| `RELAY_SERVER` | 空 | Relay 服务地址；为空时由 `ID_SERVER` 和端口规则推导。 |
| `DEFAULT_ID_PORT` | `21116` | ID 服务基准端口。 |
| `API_SERVER` | 空 | Web 客户端展示和调用的 API 服务地址。 |
| `RS_PUB_KEY` | 空 | RustDesk Server 公钥，必须与服务端 `RS_PRIV_KEY` 匹配。 |
| `OIDC_NAME` | 空 | OIDC 登录入口名称。 |
| `OIDC_ISSUER` | 空 | OIDC issuer。 |
| `OIDC_CLIENT_ID` | 空 | OIDC client id。 |
| `OIDC_CLIENT_SECRET` | 空 | OIDC client secret。 |
| `OIDC_REDIRECT_URI` | 空 | OIDC 回调地址，通常为 `https://api.example.com/api/oidc/callback`。 |
| `OIDC_SCOPE` | `openid email profile` | OIDC scope。 |

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

构建带 MySQL 驱动的镜像：

```bash
docker build --build-arg INSTALL_MYSQL=true -t camellia-api-server:mysql .
```

Compose 示例见 [docker-compose.yaml](docker-compose.yaml)。

## Web 客户端静态资源

`static/web_client` 是发布资产目录，由客户端项目 `rustdesk/flutter/web/tools` 构建并复制到本项目。不要提交 `static/web_client/js/node_modules`；只保留构建后的运行资产和桥接脚本。

## CI

仓库包含两个 workflow：

- `API Server CI`：编译检查、Ruff、Django check、迁移检查和测试。
- `API Server Docker`：手动触发，可选择仅构建镜像、发布到 GHCR、发布到 Docker Hub，并可输入目标平台。

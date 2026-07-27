# syntax=docker/dockerfile:1.7

FROM ghcr.io/astral-sh/uv:0.11.30@sha256:93b61e21202b1dab861092748e46bbd6e0e41dd84f59b9174efd2353186e1b47 AS uv

FROM python:3.14.6-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6 AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /build

ARG DEBIAN_FRONTEND=noninteractive
ARG INSTALL_MYSQL=false
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config \
    && if [ "$INSTALL_MYSQL" = "true" ]; then \
        apt-get install -y --no-install-recommends default-libmysqlclient-dev; \
    fi \
    && rm -rf /var/lib/apt/lists/*

COPY --from=uv /uv /uvx /usr/local/bin/
COPY pyproject.toml uv.lock ./
RUN if [ "$INSTALL_MYSQL" = "true" ]; then \
        uv sync --locked --no-dev --no-install-project --extra mysql; \
    else \
        uv sync --locked --no-dev --no-install-project; \
    fi

FROM python:3.14.6-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    HOST="0.0.0.0" \
    PORT="21114" \
    TZ="Asia/Shanghai"

ARG DEBIAN_FRONTEND=noninteractive
ARG INSTALL_MYSQL=false
RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata \
    && if [ "$INSTALL_MYSQL" = "true" ]; then \
        apt-get install -y --no-install-recommends libmariadb3; \
    fi \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid appuser --no-create-home --shell /usr/sbin/nologin appuser

WORKDIR /camellia-server

COPY --from=builder /opt/venv /opt/venv
COPY --chown=appuser:appuser manage.py version.py run.sh ./
COPY --chown=appuser:appuser api ./api
COPY --chown=appuser:appuser locale ./locale
COPY --chown=appuser:appuser rustdesk_server_api ./rustdesk_server_api
COPY --chown=appuser:appuser static ./static
COPY --chown=appuser:appuser templates ./templates
COPY --chown=appuser:appuser webui2 ./webui2
RUN mkdir -p db records static_root \
    && chown appuser:appuser db records static_root

USER appuser
RUN DEBUG=true \
    SECRET_KEY="build-only-secret-key-with-at-least-fifty-characters-000000000" \
    DEVICE_VERIFICATION_TOKEN="build-only-device-verification-token-000000000000" \
    python manage.py collectstatic --noinput --clear

EXPOSE 21114/tcp

ENTRYPOINT ["sh", "run.sh"]

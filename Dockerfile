FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /camellia-server

ARG DEBIAN_FRONTEND=noninteractive
ARG INSTALL_MYSQL=false
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        tzdata \
    && if [ "$INSTALL_MYSQL" = "true" ]; then apt-get install -y --no-install-recommends default-libmysqlclient-dev; fi \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt
COPY requirements-mysql.txt ./requirements-mysql.txt
RUN if [ "$INSTALL_MYSQL" = "true" ]; then pip install -r requirements-mysql.txt; else pip install -r requirements.txt; fi

COPY . .
RUN mkdir -p /camellia-server/db /camellia-server/static_root /camellia-server/records \
    && chmod -R u+rwX /camellia-server/db /camellia-server/static_root /camellia-server/records

RUN useradd -m -u 10001 appuser \
    && chown -R appuser:appuser /camellia-server
USER appuser

ENV HOST="0.0.0.0"
ENV PORT="21114"
ENV TZ="Asia/Shanghai"

EXPOSE 21114/tcp
EXPOSE 21114/udp

ENTRYPOINT ["sh", "run.sh"]

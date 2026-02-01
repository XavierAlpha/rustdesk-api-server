FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /rustdesk-api-server

# 安装系统依赖
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        default-libmysqlclient-dev \
        tzdata \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt
RUN pip install -r requirements.txt

COPY . .
RUN cp -r ./db ./db_bak
RUN chmod -R u+rwX /rustdesk-api-server/db /rustdesk-api-server/db_bak

RUN useradd -m -u 10001 appuser \
    && chown -R appuser:appuser /rustdesk-api-server
USER appuser

ENV HOST="0.0.0.0"
ENV TZ="Asia/Shanghai"

EXPOSE 21114/tcp
EXPOSE 21114/udp

ENTRYPOINT ["sh", "run.sh"]

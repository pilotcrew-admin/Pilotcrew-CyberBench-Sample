FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl jq less vim-tiny tmux ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 --shell /bin/bash analyst \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin service

COPY assets/public/ /evidence/
COPY assets/control-plane/server.py /opt/meridian/server.py
RUN find /evidence -type d -exec chmod 0555 {} + \
    && find /evidence -type f -exec chmod 0444 {} + \
    && chown service:service /opt/meridian/server.py \
    && chmod 0500 /opt/meridian/server.py \
    && mkdir -p /app/submission /logs/agent /logs/verifier /data \
    && chown -R analyst:analyst /app /logs /home/analyst \
    && chown service:service /data \
    && chmod 0775 /app/submission /logs/agent /logs/verifier

WORKDIR /app
USER analyst
CMD ["sleep", "infinity"]

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends jq less vim-tiny tree ripgrep procps tmux \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 analyst \
    && mkdir -p /app/submission /logs/agent /logs/verifier \
    && chown -R analyst:analyst /app /logs

COPY --chown=analyst:analyst assets/public/ /opt/crypto-case/
RUN chmod -R a-w /opt/crypto-case \
    && chmod 0755 /opt/crypto-case/tools/agilityctl.py \
    && ln -s /opt/crypto-case/tools/agilityctl.py /usr/local/bin/agilityctl

USER analyst
WORKDIR /app
CMD ["sleep", "infinity"]

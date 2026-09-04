FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl jq less vim-tiny tree ca-certificates tmux \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --uid 1000 analyst \
    && mkdir -p /app /logs/agent /logs/verifier \
    && chown -R analyst:analyst /app /logs
COPY --chown=analyst:analyst assets/public/ /app/
RUN chmod +x /app/waflab
USER analyst
WORKDIR /app
EXPOSE 8080
CMD ["python3", "/app/lab_server.py"]

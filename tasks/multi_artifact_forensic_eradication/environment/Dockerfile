FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends     jq sqlite3 file less vim-tiny ripgrep procps tmux asciinema     && tmux -V && asciinema --version     && rm -rf /var/lib/apt/lists/*

COPY assets/public/evidence/ /evidence/
COPY assets/public/irctl.py /usr/local/bin/irctl
COPY assets/public/state-template.json /opt/case/state-template.json
COPY assets/public/README.md /app/README.md

RUN chmod 0755 /usr/local/bin/irctl     && chmod -R a-w /evidence /opt/case/state-template.json     && mkdir -p /case/live /app /logs/agent /logs/verifier     && cp /opt/case/state-template.json /case/live/state.json     && chmod 0777 /case/live /app /logs/agent /logs/verifier     && chmod 0666 /case/live/state.json

RUN useradd --create-home --uid 1000 solver
USER 1000:1000

WORKDIR /app
CMD ["sleep", "infinity"]

#!/usr/bin/env bash
set -u
mkdir -p "${LOG_DIR:-/logs/verifier}"
python3 /tests/grader.py

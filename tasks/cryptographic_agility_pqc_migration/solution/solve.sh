#!/usr/bin/env bash
set -euo pipefail
python3 /solution/solution.py
agilityctl lint /app/submission/migration-plan.json
agilityctl rehearse /app/submission/migration-plan.json

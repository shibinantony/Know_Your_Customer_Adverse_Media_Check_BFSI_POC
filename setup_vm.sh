#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt

mkdir -p logs reports data
python -m app.audit.hash_logger init --db logs/audit_chain.sqlite3 --jsonl logs/audit_chain.jsonl
python scripts/create_sample_intake.py --output data/sample_intake.xlsx

if [[ -f logs/gateway.pid ]] && kill -0 "$(cat logs/gateway.pid)" 2>/dev/null; then
  echo "gateway already running with PID $(cat logs/gateway.pid)"
else
  nohup python -m app.gateway.middleware --config config/gateway_policy.yml > logs/gateway.out 2>&1 &
  echo "$!" > logs/gateway.pid
  echo "started CITADEL gateway with PID $(cat logs/gateway.pid)"
fi

python - <<'PY'
import json
import time
import urllib.request

for _ in range(30):
    try:
        with urllib.request.urlopen("http://127.0.0.1:8000/health", timeout=2) as response:
            body = json.loads(response.read().decode("utf-8"))
        if body.get("status") == "ok":
            print(json.dumps({"gateway": "healthy", "health": body}, indent=2))
            raise SystemExit(0)
    except Exception:
        time.sleep(0.5)

raise SystemExit("gateway did not become healthy at http://127.0.0.1:8000/health")
PY

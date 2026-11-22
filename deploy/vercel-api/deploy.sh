#!/usr/bin/env bash
# Deploy the locked public API to Vercel as one Python function.
# Used while Render's free hours are exhausted; render.yaml + Dockerfile.api is the container route.
# Usage: deploy/vercel-api/deploy.sh   (needs `vercel login` and the trained models in models/)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

[ -f "$ROOT/models/injection_classifier.joblib" ] || (cd "$ROOT" && make train)
cp -r "$ROOT/alertlens" "$ROOT/models" "$ROOT/results" "$STAGE/"
mkdir -p "$STAGE/data" && cp -r "$ROOT/data/__init__.py" "$ROOT/data/generator" "$ROOT/data/samples" "$STAGE/data/"
find "$STAGE" -name __pycache__ -prune -exec rm -rf {} +
cp "$ROOT/deploy/vercel-api/index.py" "$STAGE/"
# Only what the API imports; versions follow requirements.txt.
grep -iE "^(fastapi|uvicorn|pydantic|pydantic-core|starlette|scikit-learn|scipy|numpy|pandas|networkx|matplotlib|jinja2|fpdf2|pyyaml|python-dotenv|joblib|httpx|sentry-sdk|threadpoolctl)==" \
  "$ROOT/requirements.txt" > "$STAGE/requirements.txt"
echo "3.12" > "$STAGE/.python-version"
cd "$STAGE"
vercel link --yes --project alertlens-api >/dev/null
for kv in "PUBLIC_DEMO=true" "LLM_PROVIDER=mock" "DB_PATH=/tmp/alertlens.db" \
          "ALLOWED_ORIGINS=${ALLOWED_ORIGINS:-https://alertlens.adoranto737.workers.dev}"; do
  vercel env rm "${kv%%=*}" production --yes >/dev/null 2>&1 || true
  printf '%s' "${kv#*=}" | vercel env add "${kv%%=*}" production >/dev/null
done
vercel deploy --prod --yes

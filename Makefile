VENV := .venv
BIN := $(VENV)/bin
PY := $(BIN)/python
export PYTHONPATH := .

.PHONY: setup data train seed api ui demo test lint eval report retrain check-secrets clean

$(PY):
	@if command -v uv >/dev/null 2>&1; then uv venv -q --python 3.12 $(VENV); \
	elif command -v python3.12 >/dev/null 2>&1; then python3.12 -m venv $(VENV); \
	elif command -v python3.11 >/dev/null 2>&1; then python3.11 -m venv $(VENV); \
	else echo "Python 3.11 or 3.12 is required (or install uv)"; exit 1; fi

setup: $(PY)
	@if command -v uv >/dev/null 2>&1; then uv pip install -q --python $(PY) -r requirements.txt; \
	else $(PY) -m pip install -q -r requirements.txt; fi
	@test -f .env || cp .env.example .env
	$(MAKE) data train seed

data:
	$(PY) -m data.generator.generate --seed 42 --n 2000 --out data/benchmark

train:
	$(PY) -m alertlens.scoring.model

seed:
	$(PY) -m scripts.seed_db

api:
	$(BIN)/uvicorn alertlens.api.main:app --host 127.0.0.1 --port 8000

ui:
	$(BIN)/streamlit run ui/Home.py

demo:
	@echo "API  http://localhost:8000/docs"
	@echo "UI   http://localhost:8501"
	@trap 'kill 0' EXIT INT TERM; \
	$(BIN)/uvicorn alertlens.api.main:app --host 127.0.0.1 --port 8000 --log-level warning & \
	$(BIN)/streamlit run ui/Home.py

test:
	$(PY) -m pytest -q --cov=alertlens --cov-report=term:skip-covered

lint:
	$(BIN)/ruff check .

eval:
	$(PY) -m eval.run_benchmark $(EVAL_ARGS)

report:
	$(PY) -m eval.report

retrain:
	$(PY) -m alertlens.feedback.loop

check-secrets:
	$(PY) -m scripts.check_secrets

clean:
	rm -rf $(VENV) alertlens.db* models/*.joblib models/*.json data/benchmark .pytest_cache .ruff_cache .coverage

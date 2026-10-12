# TrustGate Phase 1 development commands.
# On Windows, GNU Make resolves OS=Windows_NT and uses the Scripts interpreter.

# PY is relative to backend/ because the recipes `cd` there first.
ifeq ($(OS),Windows_NT)
PY := .venv/Scripts/python.exe
else
PY := .venv/bin/python
endif

.PHONY: dev-backend lint format typecheck test migrate

dev-backend:
	cd backend && $(PY) -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

lint:
	cd backend && $(PY) -m ruff check app tests alembic
	cd backend && $(PY) -m ruff format --check app tests alembic

format:
	cd backend && $(PY) -m ruff check --fix app tests alembic
	cd backend && $(PY) -m ruff format app tests alembic

typecheck:
	cd backend && $(PY) -m mypy

test:
	cd backend && $(PY) -m pytest

# Applies committed revisions. Phase 2C has none, so this does not create application tables.
migrate:
	cd backend && $(PY) -m alembic upgrade head

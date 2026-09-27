# TrustGate Phase 1 development commands.
# On Windows, GNU Make resolves OS=Windows_NT and uses the Scripts interpreter.

# PY is relative to backend/ because the recipes `cd` there first.
ifeq ($(OS),Windows_NT)
PY := .venv/Scripts/python.exe
else
PY := .venv/bin/python
endif

.PHONY: dev-backend dev-frontend lint format typecheck test migrate

dev-backend:
	cd backend && $(PY) -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

dev-frontend:
	npm --prefix frontend run dev

lint:
	cd backend && $(PY) -m ruff check app tests
	cd backend && $(PY) -m ruff format --check app tests
	npm --prefix frontend run lint

format:
	cd backend && $(PY) -m ruff check --fix app tests
	cd backend && $(PY) -m ruff format app tests
	npm --prefix frontend run format

typecheck:
	cd backend && $(PY) -m mypy

test:
	cd backend && $(PY) -m pytest
	npm --prefix frontend run test

# Phase 1 placeholder. Schema migrations begin in Phase 2.
migrate:
	@echo Phase 1 placeholder: database migrations start in Phase 2. No migration was applied.

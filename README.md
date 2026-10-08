# TrustGate

Educational / portfolio prototype — not a production security product.

TrustGate is a small adaptive access-control prototype. Phase 1 is the application shell. Phase 2B adds an async PostgreSQL connection. Authentication, tables, migrations, trust scoring, OTP, and the admin dashboard are not implemented yet.

## Prerequisites

- Git
- Node.js 22 or newer
- Python 3.12
- GNU Make is optional. PowerShell commands are listed below for Windows without Make.

## First-time setup

From the repository root:

```powershell
Copy-Item .env.example .env
py -3.12 -m venv backend\.venv
backend\.venv\Scripts\python -m pip install --upgrade pip
backend\.venv\Scripts\python -m pip install -e "backend[dev]"
npm ci --prefix frontend
```

On macOS or Linux, create the virtual environment with `python3.12 -m venv backend/.venv` and call `backend/.venv/bin/python` instead of `backend\.venv\Scripts\python`.

`.env` stays on your machine. `.env.example` is the committed template. The API needs `APP_ENV` and `CORS_ALLOWED_ORIGIN` to start. The frontend needs `VITE_API_BASE_URL`. Set a strong random `DEVICE_HASH_SECRET` in the repository-root `.env` for access evaluation and device recognition; it is backend-only and must never use a `VITE_` name. The access/device-context path fails closed if it is missing. `DATABASE_URL` is optional for `GET /health` and required only for database connectivity.

## Run locally

Two terminals, from the repository root.

Backend (http://127.0.0.1:8000):

```powershell
make dev-backend
```

```powershell
backend\.venv\Scripts\python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000 --app-dir backend
```

Frontend (http://localhost:5173):

```powershell
make dev-frontend
```

```powershell
npm --prefix frontend run dev
```

The shell shows a persistent prototype notice and whether `GET /health` succeeded. The frontend origin must match `CORS_ALLOWED_ORIGIN`. The default is `http://localhost:5173`.

Health check:

```powershell
curl http://127.0.0.1:8000/health
```

Expected body: `{"status":"ok"}`. This route does not connect to a database.

## Database connection

Set `DATABASE_URL` in the repository-root `.env` to the Supabase direct Postgres connection string (host `db.<project-ref>.supabase.co`, port 5432). That value is backend-only. Do not commit `.env`, and do not copy the string into a `VITE_` variable.

The connectivity test runs `SELECT 1` when `DATABASE_URL` is set, and skips when it is empty:

```powershell
cd backend
.\.venv\Scripts\python -m pytest tests/test_database.py -q
```

## Migrations

Alembic is configured, and there is no schema revision yet. It uses `MIGRATION_DATABASE_URL` when that value is set, and otherwise the direct `DATABASE_URL`. It does not read Supabase Auth settings. Run these from `backend/`:

```powershell
.\.venv\Scripts\python -m alembic current
.\.venv\Scripts\python -m alembic heads
.\.venv\Scripts\python -m alembic upgrade head
```

`upgrade head` applies only committed revisions. With an empty `alembic/versions/` directory it does not create TrustGate tables.

Interactive API docs are at http://127.0.0.1:8000/docs when `APP_ENV` is not `production`.

## Checks

```powershell
make lint
make typecheck
make test
make format
```

Without Make:

```powershell
cd backend
.\.venv\Scripts\python -m ruff check app tests alembic
.\.venv\Scripts\python -m ruff format --check app tests alembic
.\.venv\Scripts\python -m mypy
.\.venv\Scripts\python -m pytest
cd ..
npm --prefix frontend run lint
npm --prefix frontend run typecheck
npm --prefix frontend run test
```

`make migrate` runs `alembic upgrade head`. It does not create TrustGate tables until a revision exists.

## Layout

- `frontend/` — React, TypeScript, and Vite
- `backend/app/` — FastAPI application
- `docs/decisions.md` — architecture and naming notes
- `.github/workflows/ci.yml` — lint, typecheck, and test

# TrustGate

Educational / portfolio prototype — not a production security product.

TrustGate is a small adaptive access-control prototype. This repository is at **Phase 1: project and repository setup**. The frontend shell and the API liveness check run locally. Authentication, the database, trust scoring, OTP, and the admin dashboard are not implemented yet.

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

`.env` stays on your machine. `.env.example` is the committed template. Phase 1 starts with `APP_ENV`, `CORS_ALLOWED_ORIGIN`, and `VITE_API_BASE_URL` only.

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
.\.venv\Scripts\python -m ruff check app tests
.\.venv\Scripts\python -m ruff format --check app tests
.\.venv\Scripts\python -m mypy
.\.venv\Scripts\python -m pytest
cd ..
npm --prefix frontend run lint
npm --prefix frontend run typecheck
npm --prefix frontend run test
```

`make migrate` is a Phase 1 placeholder. It does not create or apply a migration. Database migrations start in Phase 2.

## Layout

- `frontend/` — React, TypeScript, and Vite
- `backend/app/` — FastAPI application
- `docs/decisions.md` — architecture and naming notes
- `.github/workflows/ci.yml` — lint, typecheck, and test

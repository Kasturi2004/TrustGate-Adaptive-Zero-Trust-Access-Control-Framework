# Architecture decisions

Educational / portfolio prototype — not a production security product.

These notes record choices made while standing up the repository. Later phases should extend this file when a decision changes.

## Phase 1 scope

Phase 1 is a runnable development foundation:

- a React + TypeScript + Vite frontend shell
- a Python 3.12 FastAPI backend
- `GET /health`, which reports liveness and does not open a database connection
- explicit CORS, lint, typecheck, and test tooling

Authentication, Supabase tables, SQLAlchemy models, Alembic migrations, JWT validation, RBAC, OTP, trust scoring, policy decisions, and the admin dashboard are intentionally absent. They must not be stubbed with fake results.

## Stack

The implementation plan fixes the product stack: React, TypeScript (strict), Vite, and FastAPI with Pydantic v2. PostgreSQL via Supabase is the planned database, and it arrives with the schema phase.

Phase 1 installs the frontend libraries the plan names for this phase: `react-router-dom`, `@supabase/supabase-js`, ESLint, Prettier, and Vitest. The Supabase client package is installed and not initialized. Creating a client now would pretend that authentication exists.

Backend runtime dependencies started as FastAPI, Uvicorn, Pydantic v2, and pydantic-settings. Phase 2B adds SQLAlchemy 2 and asyncpg for the connection only. Alembic, PyJWT, and the other later-phase libraries stay uninstalled. `make migrate` still applies nothing.

Recharts stays deferred until post-MVP charts.

## Repository layout

```text
frontend/src/{api,components,content,lib,pages,routes,types}
backend/app/{api/routes,core}
backend/tests
docs/decisions.md
```

The technical requirements document also lists `features/`, `hooks/`, `services/`, `auth/`, and backend packages such as `gateway/` and `scoring/`. Those folders are created when that behavior is implemented, not as empty security modules.

## Naming

From the technical requirements document:

| Item | Convention |
| --- | --- |
| React components | PascalCase (`HealthStatus.tsx`) |
| TypeScript types | PascalCase (`HealthResponse`) |
| Python modules | snake_case (`health.py`) |
| Functions | snake_case verbs (`read_health`) |
| API paths | slash REST style (`/health`) |
| Pydantic models | PascalCase with a `Response` suffix (`HealthResponse`) |

Route placeholders follow the navigation map (`/login`, `/dashboard`, `/access`, `/history`, `/account`, `/admin/overview`, `/admin/events`) and render only a “not implemented in Phase 1” message.

The role-based sidebar from the app-flow document arrives with roles. Phase 1 has no signed-in user, so the shell uses a header.

## Configuration

The implementation plan names `CORS_ALLOWED_ORIGIN` (one origin). The technical requirements document says `CORS_ALLOWED_ORIGINS`. Phase 1 follows the implementation plan: one explicit `http(s)` origin. `*` and comma-separated lists are rejected at startup.

`APP_ENV` is `local`, `test`, `staging`, or `production`. OpenAPI (`/docs`, `/redoc`, `/openapi.json`) is mounted only when `APP_ENV` is not `production`.

Required Phase 1 variables are `APP_ENV` and `CORS_ALLOWED_ORIGIN` for the API, and `VITE_API_BASE_URL` for the frontend. The other variables in `.env.example` are commented out until a later phase reads them. Requiring unused secrets now would force placeholder credentials.

The API reads the repository-root `.env`. Vite is configured with `envDir` set to that same directory. Secrets never go in the frontend bundle beyond the `VITE_` variables a later phase actually needs. `SUPABASE_SERVICE_ROLE_KEY`, `DATABASE_URL`, and `SUPABASE_JWT_SECRET` are backend-only and are not given `VITE_` names.

## HTTP errors

Every error response uses:

```json
{"error": {"code": "...", "message": "...", "request_id": "..."}}
```

Messages for 5xx responses are generic. Stack traces, SQL, and filesystem paths are not returned to the client. A request id is taken from a well-formed `X-Request-ID` header or generated.

## CORS

`CORSMiddleware` receives a single configured origin. `allow_origins` is never `["*"]`. Phase 1 allows `GET` and `OPTIONS` only, because `/health` is the only route.

## Database connection (Phase 2B)

`backend/app/db/session.py` builds an async SQLAlchemy engine and an `async_sessionmaker` from `DATABASE_URL`. The engine does not connect until a session is opened. `GET /health` does not call it, so the API still starts when the database is down or the variable is empty.

`DATABASE_URL` is separate from the Supabase Auth variables (`SUPABASE_URL`, `SUPABASE_ANON_KEY`, and the service-role and JWT secrets). Those remain unused. The URL is not logged. `statement_cache_size=0` is set so a later move to the Supabase transaction pooler does not break asyncpg prepared statements. Development should use the direct database host.

Phase 2C adds an async Alembic environment under `backend/alembic/`. `target_metadata` is `None` until SQLAlchemy models exist, and `alembic/versions/` has no revision. Alembic prefers `MIGRATION_DATABASE_URL` (the future owner role, direct or session connection) and falls back to `DATABASE_URL`. That URL is separate from Supabase Auth settings and is not stored in `alembic.ini`.

No models, roles, or row-level security policies exist yet.

## Tests and CI

GitHub Actions runs Ruff, mypy, and pytest for the backend, and ESLint, Prettier, `tsc`, and Vitest for the frontend. The health tests assert the JSON body and that the route module does not reference a database driver.

## Security-event append-only protection (Phase 10E)

Security events are protected at three layers: the API exposes no PATCH, PUT, or DELETE operation for security events; the `trustgate_app` runtime role has SELECT and INSERT privileges without UPDATE or DELETE; and PostgreSQL BEFORE UPDATE and BEFORE DELETE triggers reject mutations that reach the table. This is append-only protection for the application and runtime paths, not absolute database immutability: a sufficiently privileged database owner or administrator can alter database objects or otherwise bypass these controls. Cryptographic hash chaining and WORM/immutable storage are outside the MVP scope.

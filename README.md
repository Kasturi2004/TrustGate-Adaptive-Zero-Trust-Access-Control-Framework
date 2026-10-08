# TrustGate — Zero Trust Access Control Framework

## 1. Overview

TrustGate is an educational/portfolio prototype that demonstrates adaptive, zero-trust access decisions for a small and medium-sized business (SMB) scenario. It evaluates each request to a protected resource using server-collected context, a weighted trust score, and a versioned policy. Authentication alone does not grant access to the protected Operations Dashboard.

TrustGate is a focused access-control framework for demonstration and learning. It is not a full endpoint detection and response (EDR) product, security information and event management (SIEM) system, security operations center (SOC), or production ZTNA platform.

## 2. Core Access-Control Flow

```text
Authentication
  → server-side context collection
  → trust evaluation
  → policy decision
  → MFA when required
  → protected-resource authorization
  → security-event and access-history recording
```

For an access request, the backend gathers device familiarity, browser and connection health signals, approximate location context when a GeoIP resolver is configured, and time context based on the user's request history and timezone. It calculates a trust score and evaluates that score against the active policy.

The policy returns one of three outcomes:

- **ALLOW** — the request meets the policy's allow threshold.
- **STEP-UP** — the score falls between the step-up and allow thresholds; the user must complete TOTP verification before the protected request can be redeemed.
- **BLOCK** — the score is below the step-up threshold, or the evaluation fails safely.

The backend owns context collection, scores, roles, policy decisions, and resource authorization. The browser submits a request and its device identifier; it cannot choose its trust score or outcome.

## 3. Main Features

- Employee signup and sign-in through Supabase Auth, with backend verification of Supabase access tokens.
- Role-based access control for `USER` and `ADMIN` profiles.
- Adaptive evaluation using device familiarity, browser/connection health, location, and time signals.
- Weighted trust scoring, policy-based ALLOW / STEP-UP / BLOCK decisions, and informational LOW / MEDIUM / HIGH risk classification.
- Authenticator-app TOTP enrollment and step-up verification.
- A protected Operations Dashboard requiring a successful, current-session access request that can be consumed once.
- Employee access history and current-device recognition, including the ability to forget a recognized device.
- Persisted security events with append-only protections for the application runtime role.
- Admin dashboard metrics, filtered security-event browsing, event investigation, behavioral risk indicators, and available device/access/security context.

The device-health signal describes the request's HTTPS status and parsed browser/OS family and version. It does not inspect antivirus, patch level, disk encryption, endpoint compromise, or EDR/MDM status.

## 4. Employee Experience

1. Sign up or sign in, then open the employee Dashboard.
2. Choose **Request Access** to submit a request for Operations Dashboard.
3. TrustGate evaluates the request using the current server-side context and policy. The result can be ALLOW, STEP-UP, or BLOCK; it is not guaranteed to be the same for every request.
4. If STEP-UP is required, enter a current six-digit code from an authenticator app. A successful verification allows the associated request to proceed.
5. Open Operations Dashboard. The backend checks the user's identity, session, request outcome, and one-time request state before returning the protected resource.
6. Where applicable, choose to recognize the current device after access has been granted. Recognition affects future familiarity evaluations and can be removed in Account settings.
7. Review prior requests in **Access History**, manage authenticator and device-recognition settings in **Account**, and use **Log out** to end the Supabase session.

## 5. Admin Experience

Administrators have an Admin Dashboard with access/security metrics and recent suspicious activity. The Security Events view supports filtering and pagination; an event can be opened for investigation with its available access and security context. The interface also presents behavioral indicators derived from recent blocks and failed TOTP attempts.

These are focused review tools. TrustGate does not provide a full SOC workflow, alert triage system, or case-management platform.

## 6. Security Model

- **Server-authoritative access:** The backend validates the Supabase JWT, loads the profile role, collects context, evaluates the active policy, and authorizes the protected resource.
- **Role checks:** Employee and admin routes and API operations enforce roles on the server. Hiding a frontend route is not the authorization boundary.
- **Ownership and session binding:** Access requests are tied to a user and authentication session. Protected-resource redemption and device recognition check the authenticated owner and session.
- **One-time redemption:** A successful access request is atomically consumed so it cannot be replayed to reopen the protected resource. STEP-UP requests require successful MFA before redemption.
- **MFA safeguards:** TOTP secrets are encrypted at rest with AES-256-GCM. Verification uses challenge and replay protections; plaintext OTP codes are not persisted. The encryption key must be kept stable and protected because existing credentials depend on it.
- **Device identifiers:** The browser's device token is HMAC-hashed server-side using `DEVICE_HASH_SECRET`; the raw token is not used as the stored device fingerprint.
- **Security events:** The runtime database role is granted read/insert access to security events, and database protections reject update/delete operations. These controls protect normal application paths; a sufficiently privileged database owner can still alter database state or controls.
- **Database access:** Migrations configure PostgreSQL privileges and row-level security. The TrustGate backend uses a dedicated database role with explicit table grants and RLS bypass, so database credentials must remain server-side and must never be shipped to the browser.
- **Safe errors and fail-safe outcomes:** API errors use safe response messages and request IDs; internal SQL, paths, and stack traces are not returned. Access evaluation is designed to fail closed where required context or processing is unavailable.

These controls reduce specific risks in the prototype; they do not constitute a production security certification.

## 7. Trust and Risk Evaluation

The seeded `POL-1.0` policy uses four normalized signals. Their weights sum to 1.00:

| Factor | Weight | Implemented signal mapping |
| --- | ---: | --- |
| Device familiarity | 0.35 | Recognized device: 100; unknown device: 20 |
| Device health | 0.30 | Healthy: 100; partially healthy: 60; unhealthy: 10 |
| Location normality | 0.20 | Expected region: 100; new region: 40; unavailable: 70 |
| Time normality | 0.15 | Within the user's normal window: 100; outside it: 30 |

The trust score is the weighted sum of these factor scores, on a 0–100 scale. The seeded policy thresholds are **ALLOW at 70 or above**, **STEP-UP from 40 to below 70**, and **BLOCK below 40**. The active policy version supplies the weights and thresholds used by the policy engine.

Risk classification is a separate informational label calculated from the trust score: **LOW** at 70 or above, **MEDIUM** from 40 to below 70, and **HIGH** below 40. Risk classification does not independently override the policy decision.

Location is a coarse IP-derived country/subdivision comparison, not precise geolocation. The default resolver reports location as unavailable until a server-side GeoIP resolver is configured. Device health is limited to transport and parsed browser/OS data, and does not represent endpoint security posture.

## 8. Technology Stack

- **Frontend:** React 19, TypeScript, Vite, React Router, Supabase JavaScript client.
- **Backend:** Python 3.12, FastAPI, Pydantic v2, Uvicorn.
- **Database:** PostgreSQL, with Supabase used for hosted Postgres and Supabase Auth.
- **Persistence and migrations:** SQLAlchemy 2 async ORM, asyncpg driver, Alembic.
- **Authentication and MFA:** Supabase Auth JWTs and TOTP compatible with authenticator apps (`pyotp`).
- **Quality tooling:** pytest, Vitest, Ruff, mypy, ESLint, Prettier, and TypeScript compiler checks.

## 9. Project Structure

```text
backend/
  app/                 FastAPI routes, authentication, persistence, and services
  alembic/             Database migration environment and ordered revisions
  tests/               Unit, API, security, and PostgreSQL integration tests
frontend/
  src/                 React app, routes, pages, API clients, and tests
scripts/               Administrative utility scripts
docs/                  Project documents and architecture decisions
.github/workflows/     CI workflows
```

## 10. Setup and Prerequisites

Prerequisites: Python 3.12, Node.js 22 or newer, npm, and access to a Supabase project (Auth and PostgreSQL) or compatible configured services. GNU Make is optional.

From the repository root, create a local environment file and install dependencies:

```powershell
Copy-Item .env.example .env
py -3.12 -m venv backend\.venv
backend\.venv\Scripts\python -m pip install --upgrade pip
backend\.venv\Scripts\python -m pip install -e "backend[dev]"
npm ci --prefix frontend
```

On macOS/Linux, create the environment with `python3.12 -m venv backend/.venv` and use `backend/.venv/bin/python` in place of `backend\.venv\Scripts\python`.

The backend reads `.env` from the repository root. Vite also reads frontend variables from that root via its configured `envDir`. Copy `.env.example` as a names-only template and enter local values there; never commit `.env` or put backend secrets in `VITE_` variables.

Configuration names, with no values shown:

- **Required for API startup:** `APP_ENV`, `CORS_ALLOWED_ORIGIN`.
- **Required by the frontend:** `VITE_API_BASE_URL`, `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY`.
- **Supabase Auth backend:** `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_JWT_SECRET`.
- **Database features and migrations:** `DATABASE_URL`; optionally `MIGRATION_DATABASE_URL` for a separate migration-owner connection.
- **Access/device and protected security features:** `DEVICE_HASH_SECRET`, `RATE_LIMIT_KEY_SECRET`, `SECURITY_EVENT_KEY_SECRET`, `TOTP_SECRET_ENCRYPTION_KEY` as required by the feature being used.
- **PostgreSQL integration tests:** `TEST_DATABASE_URL`, pointing to a dedicated scratch/test database. Tests do not fall back to `DATABASE_URL`.

Optional settings for trusted proxies, GeoIP, SMTP, and local development are documented by name in `.env.example` and should only be configured when the corresponding deployment setup is in place.

## 11. Running the Project

Start the backend and frontend in separate terminals from the repository root. The backend command below uses the Windows virtualenv path; on macOS/Linux substitute `backend/.venv/bin/python`.

Backend:

```powershell
backend\.venv\Scripts\python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000 --app-dir backend
```

Frontend:

```powershell
npm --prefix frontend run dev
```

The frontend runs at `http://localhost:5173` and the API at `http://127.0.0.1:8000`. Set `CORS_ALLOWED_ORIGIN` to the exact frontend origin. The liveness endpoint is `GET /health`; it returns `{"status":"ok"}` without connecting to the database. Interactive API documentation is available at `/docs` outside production; OpenAPI routes are disabled when `APP_ENV=production`.

With GNU Make installed, `make dev-backend` and `make dev-frontend` provide the repository's development commands.

## 12. Database and Migrations

The backend uses an asynchronous SQLAlchemy engine and PostgreSQL. Set `DATABASE_URL` to the application database connection. Set `MIGRATION_DATABASE_URL` when Alembic needs a separate migration-owner connection; otherwise migrations use `DATABASE_URL`. Keep both URLs server-side and use the direct PostgreSQL connection for development where appropriate.

Alembic revisions in `backend/alembic/versions/` are ordered by their `down_revision` chain. They cover the initial schema, runtime privileges and RLS, profile triggers, append-only security-event protection, the initial policy seed, MFA credentials, and later access-request consumption/session-binding changes. To inspect and apply migrations, run from `backend/`:

```powershell
.\.venv\Scripts\python -m alembic current
.\.venv\Scripts\python -m alembic history
.\.venv\Scripts\python -m alembic upgrade head
```

Review the target database and migration plan before applying revisions to a shared or production database. Migrations configure PostgreSQL table privileges and security constraints in addition to creating tables; they are not a substitute for protecting database credentials and deployment access.

## 13. Testing and Quality Checks

Run backend checks from `backend/`:

```powershell
.\.venv\Scripts\python -m pytest
.\.venv\Scripts\python -m ruff check app tests alembic
.\.venv\Scripts\python -m ruff format --check app tests alembic
.\.venv\Scripts\python -m mypy
```

Run frontend checks from the repository root:

```powershell
npm --prefix frontend run test
npm --prefix frontend run lint
npm --prefix frontend run typecheck
npm --prefix frontend run build
```

Backend PostgreSQL integration tests require `TEST_DATABASE_URL` to reference a dedicated disposable test database. The CI workflow provisions PostgreSQL 16 for these tests. Frontend tests run with Vitest; lint runs ESLint and Prettier checks; typecheck and build use the TypeScript compiler.

## 14. Demo Flow

**Employee:** Sign in → Dashboard → Request Access → review the evaluation → complete Authenticator STEP-UP when required → open Operations Dashboard → recognize the device where offered → review Access History.

**Admin:** Sign in with an administrator account → Admin Dashboard → Security Events → inspect suspicious activity → open an event investigation → review behavioral indicators and available access context.

A **BLOCK** result is a valid policy outcome and can be shown as part of the demo. STEP-UP is conditional; it is not produced on every request.

## 15. Project Scope and Limitations

TrustGate is an educational/portfolio prototype that demonstrates adaptive access control in an SMB-oriented scenario. It is not:

- an EDR or production endpoint-security product;
- a SIEM or SOC;
- a complete Zero Trust or ZTNA platform;
- an enterprise IAM replacement; or
- a full investigation case-management system.

Its device-health signal cannot assess endpoint compromise or installed security controls. Location evaluation requires a configured server-side resolver, and the default resolver yields an unavailable signal. The prototype requires additional security review, operational controls, and hardening before any production use.

## 16. Security and Deployment Notes

- Never commit `.env` or publish credentials. Use strong, independently generated secrets for each backend key and store them in a deployment secret manager.
- Protect Supabase Auth keys and PostgreSQL connection strings; never include server-only credentials in the frontend bundle.
- Keep `TOTP_SECRET_ENCRYPTION_KEY` available and backed up securely. Changing or losing it makes existing encrypted TOTP credentials unreadable; key rotation requires an application-supported procedure.
- Use HTTPS in deployed environments and configure trusted proxy settings only for known proxy hops.
- Configure `CORS_ALLOWED_ORIGIN` to the exact deployed frontend origin; wildcard origins are rejected.
- Review and apply database migrations deliberately, using appropriately protected migration credentials.
- TrustGate is a prototype and needs additional threat modeling, security review, monitoring, and deployment hardening before production use.

## 17. License / Academic Project

The repository includes an MIT License; see [LICENSE](LICENSE). Existing project documentation describes TrustGate as an educational/portfolio prototype.

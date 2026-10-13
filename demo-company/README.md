# bVoir Technology Employee Portal

Independent React and TypeScript application for bVoir Technology. It runs separately from the TrustGate administrator console at `http://127.0.0.1:5174`.

## Run

From this directory, install the portal's dependencies and start Vite:

```powershell
npm install
npm run dev
```

During development, Vite proxies `/api` to `VITE_API_BASE_URL` from the repository-root `.env`, defaulting to `http://127.0.0.1:8000`. This keeps browser requests same-origin and lets the portal and admin UI use the backend concurrently. For deployment, route `/api` through the portal's reverse proxy or set `VITE_API_BASE_URL` to a backend origin allowed by its CORS configuration.

Employees can sign in through `POST /auth/login` or register through `POST /auth/signup`. Registration uses the existing Supabase Auth service; the backend profile trigger assigns the `USER` role and marks newly created accounts as requiring authenticator setup. After sign-in, `/auth/me` tells the portal whether setup is required. The portal then uses the existing TOTP enrollment and verification endpoints before showing the employee workspace. Existing profiles keep their sign-in path. If Supabase is configured to require email confirmation and signup does not return a session, the employee must sign in once the account is ready before setup can continue.

## TrustGate boundary

The portal uses TrustGate password sign-in, profile verification, mandatory TOTP onboarding for newly registered users, access evaluation, TOTP step-up, and one-time redemption. Backend guards reject protected API calls by accounts that have not completed required onboarding. The operations workspace remains protected as `ops-dashboard`. Document pages evaluate and redeem the registered `employee-handbook`, `company-policies`, `quarterly-strategy-plan`, and `confidential-financial-report` resources before displaying backend-returned sample content.

Handbook and company policies are available to authenticated employees. The quarterly strategy plan and confidential financial report require group grants; because TrustGate does not yet have a group-grant model, those requests are denied server-side. The document bodies returned for the two employee-wide resources are clearly labeled fictional samples stored by the backend, not frontend assets. The portal's project, resource, activity, team, task, and announcement entries remain fictional demo content. Its support form explicitly states that a request is only drafted locally and is not submitted. No simulated events are sent to TrustGate.

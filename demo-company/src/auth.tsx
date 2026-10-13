import { useEffect, useState, type FormEvent } from "react";
import { QRCodeSVG } from "qrcode.react";
import { requestTotpEnrollment } from "./enrollment";
import type { PortalSession } from "./session";
import brandLogo from "../icon/bVoir Technology Logo-Photoroom.svg";
import darkBrandLogo from "../icon/bVoir Technology Dark Logo.svg";

const API = (import.meta.env.DEV ? "/api" : import.meta.env.VITE_API_BASE_URL || "/api").replace(
  /\/$/,
  "",
);

export type AuthSession = PortalSession;

type AuthProfile = {
  id: string;
  email: string | null;
  role: "USER" | "ADMIN";
  authenticator_required: boolean;
  mfa_enrolled: boolean;
};

type AuthResponse = {
  access_token?: string;
  refresh_token?: string;
  session_created?: boolean;
  user?: { email?: string | null };
};

const showAuthShowcase = true;

function AuthShowcase() {
  return (
    <aside className="auth-showcase">
      <a className="auth-brand auth-showcase-brand" href="/" aria-label="bVoir Technology">
        <img className="company-logo" src={darkBrandLogo} alt="bVoir Technology" />
      </a>

      <div className="auth-showcase-copy">
        <h2 className="auth-showcase-headline">Your work,<br />all connected</h2>
        <p className="auth-showcase-subtext">Find the people and resources you need to move forward.</p>
        <div className="auth-showcase-dots" aria-hidden="true"><span className="active" /><span /><span /></div>
      </div>
    </aside>
  );
}

function AuthLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className={`auth-page auth-layout${showAuthShowcase ? " with-showcase" : ""}`}>
      {showAuthShowcase && <AuthShowcase />}
      <main className="auth-main-panel">
        <header className="auth-topbar">
          <a className="auth-brand auth-brand-dark" href="/" aria-label="bVoir Technology home">
            <img className="company-logo" src={brandLogo} alt="bVoir Technology" />
          </a>
        </header>
        <div className="auth-panel-content">{children}</div>
      </main>
    </div>
  );
}

async function request<T>(path: string, init: RequestInit = {}, token?: string): Promise<T> {
  let response: Response;
  try {
    response = await fetch(API + path, {
      ...init,
      headers: {
        Accept: "application/json",
        ...(init.body ? { "Content-Type": "application/json" } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...init.headers,
      },
    });
  } catch {
    throw new Error("Unable to reach TrustGate. Check your connection and try again.");
  }
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = response.status === 401 && token
      ? "Your session expired. Sign in again to continue."
      : body.detail || body.error?.message;
    throw new Error(typeof message === "string" ? message : `Request failed (${response.status}).`);
  }
  return body as T;
}

export function AuthPage({
  onSession,
  sessionError = "",
}: {
  onSession: (session: AuthSession) => void;
  sessionError?: string;
}) {
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [touched, setTouched] = useState({ fullName: false, email: false, password: false });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  async function submit(event: FormEvent) {
    event.preventDefault();
    setTouched((previous) => ({
      ...previous,
      email: true,
      ...(mode === "signup" ? { fullName: true, password: true } : {}),
    }));
    if (!validEmail) {
      setError("Enter a valid work email address.");
      return;
    }
    if (mode === "signup" && !validFullName) {
      setError("Enter your full name.");
      return;
    }
    if (mode === "signup" && (passwordLength > 128 || passwordChecks.some((check) => !check.passed))) {
      setError("Meet all four password requirements to continue.");
      return;
    }
    if (mode === "signin" && !password) {
      setError("Enter your password.");
      return;
    }
    setBusy(true);
    setError("");
    setNotice("");
    try {
      if (mode === "signin") {
        const result = await request<AuthResponse>("/auth/login", {
          method: "POST",
          body: JSON.stringify({ email: email.trim().toLowerCase(), password }),
        });
        if (!result.access_token) throw new Error("Sign-in did not return a session.");
        onSession({
          token: result.access_token,
          refresh_token: result.refresh_token,
          user: { email: result.user?.email || email },
        });
      } else {
        const result = await request<AuthResponse>("/auth/signup", {
          method: "POST",
          body: JSON.stringify({ full_name: fullName.trim(), email: email.trim().toLowerCase(), password }),
        });
        if (result.session_created && result.access_token) {
          onSession({
            token: result.access_token,
            refresh_token: result.refresh_token,
            user: { email: result.user?.email || email },
          });
        } else {
          setNotice("Your account was created. If email confirmation is enabled, confirm your address, then sign in to set up your authenticator.");
          setMode("signin");
          setPassword("");
        }
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to continue. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  const signingUp = mode === "signup";
  const validEmail = /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim());
  const validFullName = fullName.trim().length >= 2;
  const passwordLength = Array.from(password).length;
  const passwordChecks = [
    { label: "At least 12 characters", passed: passwordLength >= 12 },
    { label: "Upper and lowercase letters", passed: /[a-z]/.test(password) && /[A-Z]/.test(password) },
    { label: "At least one number", passed: /[0-9]/.test(password) },
    { label: "At least one symbol", passed: /[^A-Za-z0-9]/.test(password) },
  ];
  const strength = passwordChecks.filter((check) => check.passed).length;
  const strengthLabel = ["", "Weak", "Fair", "Good", "Strong"][strength];
  function switchMode() {
    setMode(signingUp ? "signin" : "signup");
    setShowPassword(false);
    setTouched({ fullName: false, email: false, password: false });
    setError("");
    setNotice("");
  }
  return (
    <AuthLayout>
      <section key={signingUp ? "signup" : "signin"} className={`auth-card auth-card-transition ${signingUp ? "is-signup" : "is-signin"}`} aria-labelledby="auth-title">
        <h1 id="auth-title">{signingUp ? "Create your account" : "Sign in to bVoir Technology"}</h1>
        <p className="auth-subtitle">
          {signingUp
            ? "Set up your employee account to get started."
            : "Use your work email and password to continue."}
        </p>
        {notice && <div className="notice" role="status">{notice}</div>}
        <form className="auth-form" onSubmit={submit} noValidate>
          {signingUp && (
            <label>
              Full name
              <input
                className="auth-input"
                autoComplete="name"
                required
                minLength={2}
                maxLength={100}
                value={fullName}
                onChange={(event) => setFullName(event.target.value)}
                onBlur={() => setTouched((previous) => ({ ...previous, fullName: true }))}
                aria-invalid={touched.fullName && !validFullName}
                placeholder="Your full name"
              />
              {touched.fullName && !validFullName && <span className="field-error">Enter your full name.</span>}
            </label>
          )}
          <label>
            Work email
            <input
              className="auth-input"
              autoComplete="email"
              type="email"
              required
              maxLength={254}
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              onBlur={() => setTouched((previous) => ({ ...previous, email: true }))}
              aria-invalid={touched.email && !validEmail}
              placeholder="you@company.com"
            />
            {touched.email && !validEmail && <span className="field-error">Enter a valid work email address.</span>}
          </label>
          <div className="auth-password-group">
            <div className="auth-password-label-row">
              <label htmlFor="auth-password">{signingUp ? "New password" : "Password"}</label>
            </div>
            <span className="password-field">
              <input
                id="auth-password"
                className="auth-input"
                autoComplete={signingUp ? "new-password" : "current-password"}
                type={showPassword ? "text" : "password"}
                required
                minLength={signingUp ? 12 : 1}
                maxLength={256}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                onBlur={() => signingUp && setTouched((previous) => ({ ...previous, password: true }))}
                aria-invalid={signingUp && touched.password && passwordLength > 128}
                placeholder={signingUp ? "Create a password" : "Enter your password"}
                aria-describedby={signingUp ? "password-hint" : undefined}
              />
              <button
                className="password-toggle"
                type="button"
                aria-label={showPassword ? "Hide password" : "Show password"}
                aria-pressed={showPassword}
                onClick={() => setShowPassword((shown) => !shown)}
              >
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  {showPassword ? (
                    <><path d="M2.5 12s3.5-7 9.5-7 9.5 7 9.5 7-3.5 7-9.5 7-9.5-7-9.5-7Z" /><circle cx="12" cy="12" r="3" /></>
                  ) : (
                    <><path d="M3 3l18 18" /><path d="M10.6 10.6a2 2 0 0 0 2.8 2.8" /><path d="M9.9 5.2A10.8 10.8 0 0 1 12 5c5 0 8.5 4.2 9.5 7-.4 1.1-1.2 2.3-2.3 3.4M6.2 6.2C3.9 7.7 2.8 9.8 2.5 12c1 2.8 4.5 7 9.5 7 1 0 1.9-.2 2.8-.5" /></>
                  )}
                </svg>
              </button>
            </span>
            {!signingUp && <a className="forgot-password" href="/forgot-password">Forgot password?</a>}
          </div>
          {signingUp && (
            <div className="password-guidance" id="password-hint" aria-live="polite">
              <div
                className={`password-strength strength-${strengthLabel.toLowerCase() || "empty"}`}
                role="meter"
                aria-label="Password strength"
                aria-valuemin={0}
                aria-valuemax={4}
                aria-valuenow={strength}
                aria-valuetext={strengthLabel || "Not set"}
                aria-live="polite"
              >
                <div className="strength-bars" aria-hidden="true">
                  {passwordChecks.map((check, index) => (
                    <span key={check.label} className={index < strength ? `filled level-${strength}` : ""} />
                  ))}
                </div>
                {strengthLabel && <span>{strengthLabel}</span>}
              </div>
              <ul className="password-rules">
                {passwordChecks.map((check) => (
                  <li key={check.label} className={check.passed ? "passed" : ""}>
                    <span className="rule-icon" aria-hidden="true">
                      {check.passed && (
                        <svg viewBox="0 0 16 16" focusable="false">
                          <path d="m3 8 3.2 3.2L13 4.5" />
                        </svg>
                      )}
                    </span>
                    <span>{check.label}</span>
                    <span className="visually-hidden">{check.passed ? "met" : "not met"}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {(error || sessionError) && (
            <div className="error" role="alert" aria-live="polite">{error || sessionError}</div>
          )}
          <button className="auth-submit" type="submit" disabled={busy}>
            {busy ? "Please wait…" : signingUp ? "Create account" : "Sign in"}
          </button>
          {/* TODO: Add approved social sign-in options here if an auth integration is introduced. */}
        </form>
        <p className="auth-switch">
          {signingUp ? "Already have an account?" : "New to bVoir Technology?"}{" "}
          <button
            type="button"
            onClick={switchMode}
          >
            {signingUp ? "Sign in" : "Create an account"}
          </button>
        </p>
        <p className="auth-caption">Secure sign-in provided by TrustGate.</p>
      </section>
    </AuthLayout>
  );
}

export function AuthenticatorSetup({
  session,
  onComplete,
  onSignOut,
}: {
  session: AuthSession;
  onComplete: (profile: AuthProfile) => void;
  onSignOut: () => void;
}) {
  const [uri, setUri] = useState("");
  const [manualKey, setManualKey] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let current = true;
    setLoading(true);
    setError("");
    requestTotpEnrollment(API, session)
      .then((result) => {
        if (current) {
          setUri(result.otpauth_uri);
          setManualKey(result.manual_entry_key);
        }
      })
      .catch((caught: unknown) => {
        if (current) setError(caught instanceof Error ? caught.message : "Authenticator setup failed.");
      })
      .finally(() => {
        if (current) setLoading(false);
      });
    return () => {
      current = false;
    };
  }, [session.token, attempt]);

  function retryEnrollment() {
    setUri("");
    setManualKey("");
    setError("");
    setLoading(true);
    setAttempt((value) => value + 1);
  }

  async function verify(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await request(
        "/auth/mfa/totp/enrollment/verify",
        { method: "POST", body: JSON.stringify({ code }) },
        session.token,
      );
      const profile = await request<AuthProfile>("/auth/me", {}, session.token);
      setManualKey("");
      setUri("");
      onComplete(profile);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Code verification failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth-page">
      <section className="auth-card enrollment-card" aria-labelledby="enrollment-title">
        <a className="auth-brand" href="/" aria-label="bVoir Technology home">
          <img className="company-logo" src={brandLogo} alt="bVoir Technology" />
        </a>
        <div className="eyebrow">ACCOUNT SECURITY</div>
        <h1 id="enrollment-title">Set up your authenticator</h1>
        <p className="auth-subtitle">
          Scan this code with an authenticator app, then enter its six-digit code to finish setup.
        </p>
        {loading && <div className="notice" role="status">Preparing your secure setup…</div>}
        {!loading && !uri && error && <div className="error" role="alert">{error}</div>}
        {!loading && !uri && error && (
          <button className="auth-secondary" type="button" onClick={retryEnrollment}>
            Retry authenticator setup
          </button>
        )}
        {!loading && uri && (
          <>
            <div className="qr-frame" aria-label="Authenticator enrollment QR code">
              <QRCodeSVG value={uri} size={216} level="M" includeMargin />
            </div>
            <details className="manual-setup">
              <summary>Can’t scan the code? Enter it manually</summary>
              <p>In your authenticator app, add a time-based code with this key:</p>
              <code>{manualKey}</code>
            </details>
            <form className="auth-form" onSubmit={verify}>
              <label>
                6-digit authenticator code
                <input
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  pattern="[0-9]{6}"
                  minLength={6}
                  maxLength={6}
                  required
                  value={code}
                  onChange={(event) => setCode(event.target.value.replace(/\D/g, "").slice(0, 6))}
                  aria-describedby={error ? "enrollment-error" : undefined}
                />
              </label>
              {error && <div className="error" id="enrollment-error" role="alert">{error}</div>}
              <button className="auth-submit" type="submit" disabled={busy || code.length !== 6}>
                {busy ? "Verifying…" : "Verify and continue"}
              </button>
            </form>
          </>
        )}
        <button className="auth-secondary" type="button" onClick={onSignOut}>Sign out</button>
      </section>
    </main>
  );
}

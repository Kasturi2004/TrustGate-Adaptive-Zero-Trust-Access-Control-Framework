import { useState } from "react";
import type { FormEvent } from "react";
import { ArrowRight, Eye, EyeOff, ShieldCheck } from "../components/Icons";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../auth/useAuth";
import { loginFailureMessage, loginVerificationMessage } from "./loginCopy";

export function LoginPage() {
  const { signIn, configurationReady } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setBusy(true);
    try {
      await signIn(email, password);
      navigate("/", { replace: true });
    } catch {
      setError(loginFailureMessage);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-page">
      <div className="login-backdrop" />
      <section className="login-card">
        <div className="login-brand">
          <span className="brand-symbol">
            <ShieldCheck size={20} />
          </span>
          <span>
            Trust<span className="brand-accent">Gate</span>
          </span>
        </div>
        <div className="login-kicker">ADMINISTRATOR CONSOLE</div>
        <h1>Welcome back</h1>
        <p className="login-description">
          Sign in to review access decisions and security activity.
        </p>
        {!configurationReady && (
          <div className="config-notice" role="status">
            Set the public Supabase URL and anon key in the root environment
            before signing in.
          </div>
        )}
        <form onSubmit={(event) => void submit(event)}>
          <label htmlFor="email">Work email</label>
          <input
            id="email"
            type="email"
            autoComplete="username"
            required
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            placeholder="you@company.com"
            aria-invalid={Boolean(error)}
          />
          <label htmlFor="password">Password</label>
          <div className="password-field">
            <input
              id="password"
              type={showPassword ? "text" : "password"}
              autoComplete="current-password"
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="Your password"
              aria-invalid={Boolean(error)}
              aria-describedby={error ? "login-error" : undefined}
            />
            <button
              type="button"
              className="password-toggle"
              onClick={() => setShowPassword((visible) => !visible)}
              aria-label={showPassword ? "Hide password" : "Show password"}
              aria-pressed={showPassword}
            >
              {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          </div>
          {error && (
            <div className="login-error" role="alert" id="login-error">
              {error}
            </div>
          )}
          <button
            className="primary-button login-submit"
            type="submit"
            disabled={busy || !configurationReady}
          >
            {busy ? (
              "Verifying…"
            ) : (
              <>
                Continue securely <ArrowRight size={16} />
              </>
            )}
          </button>
        </form>
        <div className="login-foot">
          <ShieldCheck size={14} /> {loginVerificationMessage}
        </div>
      </section>
      <p className="login-legal">
        Access decisions remain enforced by the TrustGate backend.
      </p>
    </main>
  );
}

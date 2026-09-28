import { useRef, useState } from "react";
import type { FormEvent } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { apiRequest } from "../api/client.ts";
import { supabase } from "../lib/supabase.ts";

interface TokenResponse {
  access_token: string;
  refresh_token: string;
}

function parseTokenResponse(value: unknown): TokenResponse | null {
  if (typeof value !== "object" || value === null) {
    return null;
  }

  const { access_token, refresh_token } = value as Record<string, unknown>;
  if (
    typeof access_token !== "string" ||
    access_token.trim() === "" ||
    typeof refresh_token !== "string" ||
    refresh_token.trim() === ""
  ) {
    return null;
  }

  return { access_token, refresh_token };
}

function returnPath(locationState: unknown): string | null {
  if (typeof locationState !== "object" || locationState === null || !("from" in locationState)) {
    return null;
  }
  const destination = locationState.from;
  if (typeof destination !== "object" || destination === null || !("pathname" in destination)) {
    return null;
  }

  const { pathname, search, hash } = destination as Record<string, unknown>;
  if (
    typeof pathname !== "string" ||
    !pathname.startsWith("/") ||
    pathname.startsWith("//") ||
    pathname.includes("\\")
  ) {
    return null;
  }

  const safeSearch = typeof search === "string" && search.startsWith("?") ? search : "";
  const safeHash = typeof hash === "string" && hash.startsWith("#") ? hash : "";
  return `${pathname}${safeSearch}${safeHash}`;
}

function loginError(status: number): string {
  if (status === 401) {
    return "Invalid email or password.";
  }
  if (status === 429) {
    return "Too many login attempts. Please try again later.";
  }
  if (status === 422) {
    return "Enter a valid email address and password.";
  }
  return "Unable to sign in right now. Please try again.";
}

export function LoginPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const submittingRef = useRef(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (submittingRef.current) {
      return;
    }

    submittingRef.current = true;
    setSubmitting(true);
    setError(null);

    try {
      const response = await apiRequest("/auth/login", {
        method: "POST",
        body: { email: email.trim(), password },
      });

      if (!response.ok) {
        setError(loginError(response.status));
        return;
      }

      const tokens = parseTokenResponse(await response.json());
      if (!tokens) {
        setError("Unable to sign in right now. Please try again.");
        return;
      }

      const { error: sessionError } = await supabase.auth.setSession(tokens);
      if (sessionError) {
        setError("Unable to sign in right now. Please try again.");
        return;
      }

      navigate(returnPath(location.state) ?? "/access", { replace: true });
    } catch {
      setError("Unable to sign in right now. Please try again.");
    } finally {
      submittingRef.current = false;
      setSubmitting(false);
    }
  }

  return (
    <section className="panel login-panel">
      <h1>Sign in to TrustGate</h1>
      <p className="lede">Use your account to continue.</p>
      <form className="login-form" onSubmit={handleSubmit}>
        <label htmlFor="login-email">
          Email
          <input
            id="login-email"
            name="email"
            type="email"
            autoComplete="username"
            required
            value={email}
            onChange={(event) => setEmail(event.currentTarget.value)}
          />
        </label>
        <label htmlFor="login-password">
          Password
          <input
            id="login-password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(event) => setPassword(event.currentTarget.value)}
          />
        </label>
        {error ? (
          <p className="login-error" role="alert">
            {error}
          </p>
        ) : null}
        <button className="login-submit" type="submit" disabled={submitting}>
          {submitting ? "Signing in…" : "Sign in"}
        </button>
      </form>
      <p className="login-signup">
        Don’t have an account? <Link to="/signup">Sign up</Link>
      </p>
    </section>
  );
}

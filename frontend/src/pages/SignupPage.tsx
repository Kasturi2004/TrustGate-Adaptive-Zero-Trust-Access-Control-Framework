import { useRef, useState } from "react";
import type { FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { supabase } from "../lib/supabase.ts";
import { AuthPageLayout } from "../components/AuthPageLayout.tsx";

const SIGNUP_ERROR = "Unable to create your account right now. Please try again.";
const CONFIRMATION_MESSAGE =
  "Signup submitted. Check your email for a verification link before signing in.";

export function SignupPage() {
  const navigate = useNavigate();
  const submittingRef = useRef(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (submittingRef.current) {
      return;
    }

    setError(null);
    setSuccess(null);
    if (!email.trim()) {
      setError("Enter your email address.");
      return;
    }
    if (!password) {
      setError("Enter a password.");
      return;
    }
    if (!confirmPassword) {
      setError("Confirm your password.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    submittingRef.current = true;
    setSubmitting(true);
    try {
      const { data, error: signupError } = await supabase.auth.signUp({
        email: email.trim(),
        password,
      });

      if (signupError) {
        setError(SIGNUP_ERROR);
        return;
      }

      if (data.session) {
        navigate("/access", { replace: true });
      } else {
        setSuccess(CONFIRMATION_MESSAGE);
      }
    } catch {
      setError(SIGNUP_ERROR);
    } finally {
      submittingRef.current = false;
      setSubmitting(false);
    }
  }

  return (
    <AuthPageLayout
      eyebrow="Get started"
      title="Create your account"
      description="Set up your TrustGate account to continue."
      footer={
        <p className="login-signup">
          Already have an account? <Link to="/login">Sign in</Link>
        </p>
      }
    >
      <form className="login-form" onSubmit={handleSubmit}>
        <label htmlFor="signup-email">
          Email
          <input
            id="signup-email"
            name="email"
            type="email"
            autoComplete="email"
            required
            value={email}
            onChange={(event) => setEmail(event.currentTarget.value)}
          />
        </label>
        <label htmlFor="signup-password">
          Password
          <input
            id="signup-password"
            name="password"
            type="password"
            autoComplete="new-password"
            required
            value={password}
            onChange={(event) => setPassword(event.currentTarget.value)}
          />
        </label>
        <label htmlFor="signup-confirm-password">
          Confirm password
          <input
            id="signup-confirm-password"
            name="confirmPassword"
            type="password"
            autoComplete="new-password"
            required
            value={confirmPassword}
            onChange={(event) => setConfirmPassword(event.currentTarget.value)}
          />
        </label>
        {error ? (
          <p className="login-error" role="alert">
            {error}
          </p>
        ) : null}
        {success ? (
          <p className="signup-success" role="status">
            {success}
          </p>
        ) : null}
        <button className="login-submit auth-submit" type="submit" disabled={submitting}>
          {submitting ? "Creating account…" : "Create account"}
        </button>
      </form>
    </AuthPageLayout>
  );
}

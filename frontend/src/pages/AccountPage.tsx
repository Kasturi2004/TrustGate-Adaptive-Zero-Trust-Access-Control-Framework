import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import {
  MfaEnrollmentApiError,
  startTotpEnrollment,
  verifyTotpEnrollment,
} from "../api/mfaEnrollment.ts";
import { fetchCurrentDeviceRecognition, forgetCurrentDevice } from "../api/deviceRecognition.ts";
import type { TotpEnrollmentStartResponse } from "../types/mfaEnrollment.ts";

type EnrollmentState = "idle" | "starting" | "configuring" | "verifying" | "complete";
type DeviceState = "loading" | "recognized" | "unrecognized" | "unavailable" | "forgetting";

function startErrorMessage(error: unknown): string {
  if (error instanceof MfaEnrollmentApiError) {
    if (error.status === 401 || error.status === 403) {
      return "Your session has expired. Sign in again to set up an authenticator.";
    }
    if (error.status === 409) {
      return "An authenticator is already enrolled or this setup cannot be restarted.";
    }
  }
  return "We couldn't start authenticator setup. Please try again.";
}

function verificationErrorMessage(error: unknown): string {
  if (error instanceof MfaEnrollmentApiError) {
    if (error.status === 401 || error.status === 403) {
      return "Your session has expired. Sign in again to finish authenticator setup.";
    }
    if (error.status === 429) {
      return "Too many verification attempts. Please wait before trying again.";
    }
    if (error.status === 400 || error.status === 404 || error.status === 409) {
      return "That code was not accepted or this setup has expired. Start setup again and use a current code.";
    }
  }
  if (error instanceof MfaEnrollmentApiError && error.status === 503) {
    return "Authenticator verification is temporarily unavailable. Please try again later.";
  }
  return "We couldn't verify the authenticator code. Please try again.";
}

export function AccountPage() {
  const [state, setState] = useState<EnrollmentState>("idle");
  const [enrollment, setEnrollment] = useState<TotpEnrollmentStartResponse | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const startInFlight = useRef(false);
  const verifyInFlight = useRef(false);
  const forgetInFlight = useRef(false);
  const [deviceState, setDeviceState] = useState<DeviceState>("loading");
  const [deviceError, setDeviceError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    void fetchCurrentDeviceRecognition()
      .then(({ recognized }) => {
        if (active) setDeviceState(recognized ? "recognized" : "unrecognized");
      })
      .catch(() => {
        if (active) setDeviceState("unavailable");
      });
    return () => {
      active = false;
    };
  }, []);

  async function forgetDevice(): Promise<void> {
    if (forgetInFlight.current || deviceState !== "recognized") return;
    forgetInFlight.current = true;
    setDeviceState("forgetting");
    setDeviceError(null);
    try {
      await forgetCurrentDevice();
      setDeviceState("unrecognized");
    } catch {
      setDeviceState("recognized");
      setDeviceError("We couldn't update this device preference. Please try again.");
    } finally {
      forgetInFlight.current = false;
    }
  }

  async function beginEnrollment(): Promise<void> {
    if (startInFlight.current || verifyInFlight.current) return;
    startInFlight.current = true;
    setState("starting");
    setError(null);
    setCode("");
    setEnrollment(null);
    try {
      const result = await startTotpEnrollment();
      setEnrollment(result);
      setState("configuring");
    } catch (caught) {
      setState("idle");
      setError(startErrorMessage(caught));
    } finally {
      startInFlight.current = false;
    }
  }

  async function submitCode(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (verifyInFlight.current) return;
    if (!/^[0-9]{6}$/.test(code)) {
      setError("Enter the six-digit code from your authenticator app.");
      return;
    }

    verifyInFlight.current = true;
    setState("verifying");
    setError(null);
    try {
      await verifyTotpEnrollment(code);
      setEnrollment(null);
      setCode("");
      setState("complete");
    } catch (caught) {
      setState("configuring");
      setError(verificationErrorMessage(caught));
    } finally {
      setCode("");
      verifyInFlight.current = false;
    }
  }

  const busy = state === "starting" || state === "verifying";

  return (
    <div className="account-page">
      <header className="page-heading">
        <div>
          <span className="page-eyebrow">Account security</span>
          <h1>Authenticator</h1>
          <p>
            Set up and manage the authenticator used when TrustGate requires additional
            verification.
          </p>
        </div>
      </header>

      <section
        className="panel account-enrollment-panel"
        aria-labelledby="device-recognition-title"
      >
        <span className="page-eyebrow">Device familiarity</span>
        <h2 id="device-recognition-title">Current device</h2>
        <p>
          Recognition is a familiarity signal for future access decisions. It does not replace
          signing in or any required verification.
        </p>
        {deviceState === "loading" && <p role="status">Checking this device…</p>}
        {deviceState === "recognized" && (
          <>
            <p role="status">This device is recognized for your account.</p>
            <button
              className="history-secondary-action account-restart-action"
              type="button"
              onClick={() => void forgetDevice()}
            >
              Forget this device
            </button>
          </>
        )}
        {deviceState === "forgetting" && <p role="status">Updating device preference…</p>}
        {deviceState === "unrecognized" && <p role="status">This device is not recognized.</p>}
        {deviceState === "unavailable" && (
          <p role="status">Device recognition status is temporarily unavailable.</p>
        )}
        {deviceError && (
          <p className="login-error" role="alert">
            {deviceError}
          </p>
        )}
      </section>

      {state === "complete" ? (
        <section
          className="panel account-enrollment-panel"
          aria-labelledby="enrollment-success-title"
        >
          <span className="page-eyebrow">Setup complete</span>
          <h2 id="enrollment-success-title">Authenticator set up successfully.</h2>
          <p>
            Your authenticator can now be used when an access request requires additional
            verification.
          </p>
          <Link className="login-submit auth-submit account-primary-action" to="/access">
            Go to access requests
          </Link>
        </section>
      ) : state === "idle" || state === "starting" ? (
        <section
          className="panel account-enrollment-panel"
          aria-labelledby="enrollment-start-title"
        >
          <span className="page-eyebrow">Two-step setup</span>
          <h2 id="enrollment-start-title">Add an authenticator</h2>
          <p>
            Use an authenticator app to add this account. Setup takes a moment and is confirmed with
            a six-digit code.
          </p>
          {error && (
            <p className="login-error" role="alert">
              {error}
            </p>
          )}
          {error?.includes("session has expired") && (
            <Link className="history-back-link" to="/login">
              Sign in again
            </Link>
          )}
          <button
            className="login-submit auth-submit account-primary-action"
            type="button"
            onClick={() => void beginEnrollment()}
            disabled={busy}
          >
            {state === "starting" ? "Preparing setup…" : "Set up Authenticator"}
          </button>
        </section>
      ) : (
        <section
          className="panel account-enrollment-panel"
          aria-labelledby="enrollment-config-title"
        >
          <span className="page-eyebrow">Step 1 · Configure</span>
          <h2 id="enrollment-config-title">Connect your authenticator app</h2>
          <ol className="account-enrollment-instructions">
            <li>Open your authenticator application and choose to add a new account.</li>
            <li>
              Enter this setup key. Treat it as sensitive: anyone with the key can generate codes
              for this account.
            </li>
          </ol>
          <label className="account-key-label" htmlFor="totp-manual-key">
            Manual setup key
          </label>
          <code
            className="account-manual-key"
            id="totp-manual-key"
            aria-label="Authenticator manual setup key"
          >
            {enrollment?.manual_entry_key}
          </code>
          <p className="account-setup-note">
            No QR image is shown. Use the manual setup key above to connect your authenticator app.
          </p>

          <form className="account-verify-form" onSubmit={(event) => void submitCode(event)}>
            <label htmlFor="enrollment-code">Step 2 · Enter the six-digit code</label>
            <input
              id="enrollment-code"
              name="enrollment-code"
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6}"
              minLength={6}
              maxLength={6}
              required
              disabled={busy}
              value={code}
              onChange={(event) => {
                setCode(event.currentTarget.value.replace(/[^0-9]/g, "").slice(0, 6));
                setError(null);
              }}
            />
            {error && (
              <p className="login-error" role="alert">
                {error}
              </p>
            )}
            <button
              className="login-submit auth-submit account-primary-action"
              type="submit"
              disabled={busy}
            >
              {state === "verifying" ? "Verifying code…" : "Verify and enable authenticator"}
            </button>
          </form>
          {error?.includes("session has expired") && (
            <Link className="history-back-link" to="/login">
              Sign in again
            </Link>
          )}
          <button
            className="history-secondary-action account-restart-action"
            type="button"
            onClick={() => void beginEnrollment()}
            disabled={busy}
          >
            Start setup again
          </button>
        </section>
      )}
    </div>
  );
}

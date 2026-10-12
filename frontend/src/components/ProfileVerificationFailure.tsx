import { useState } from "react";

export function ProfileVerificationFailure({
  title = "Administrator access could not be verified",
  detail = "TrustGate could not resolve your current session profile.",
  onRetry,
  onSignOut,
}: {
  title?: string;
  detail?: string;
  onRetry: () => void;
  onSignOut: () => Promise<void>;
}) {
  const [signOutError, setSignOutError] = useState("");
  const [signingOut, setSigningOut] = useState(false);

  async function signOut() {
    setSigningOut(true);
    setSignOutError("");
    try {
      await onSignOut();
    } catch {
      setSignOutError("Unable to end the current session. Please try again.");
    } finally {
      setSigningOut(false);
    }
  }

  return (
    <section className="gate-message" aria-labelledby="profile-verification-title">
      <h1 id="profile-verification-title">{title}</h1>
      <p>{detail}</p>
      {signOutError && <p role="alert">{signOutError}</p>}
      <div className="gate-actions">
        <button className="primary-button" onClick={onRetry}>
          Retry verification
        </button>
        <button className="secondary-button" onClick={() => void signOut()} disabled={signingOut}>
          {signingOut ? "Signing out..." : "Sign out and return to login"}
        </button>
      </div>
    </section>
  );
}

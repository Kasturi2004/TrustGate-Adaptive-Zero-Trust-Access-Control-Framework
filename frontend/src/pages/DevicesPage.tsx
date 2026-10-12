import { AlertCircle, Computer } from "../components/Icons";
import { ErrorState, LoadingState } from "../components/States";
import { useAuth } from "../auth/useAuth";
import type { AuthStatus } from "../auth/AuthSessionController";
import type { Profile } from "../types/api";

export function DevicesPage() {
  const { profile, status, refreshProfile } = useAuth();
  return (
    <DevicesContent
      profile={profile}
      status={status}
      onRetry={() => void refreshProfile()}
    />
  );
}

export function DevicesContent({
  profile,
  status,
  onRetry,
}: {
  profile: Profile | null;
  status: AuthStatus;
  onRetry: () => void;
}) {
  if (status === "loading" || status === "resolving_profile") {
    return <LoadingState label="Verifying your account before loading device information" />;
  }
  if (status === "profile_error" || status === "session_error") {
    return (
      <ErrorState
        message="TrustGate could not verify the current account. Device information remains unavailable until verification succeeds."
        onRetry={onRetry}
      />
    );
  }
  if (status !== "authenticated" || !profile) {
    return (
      <section className="panel device-unavailable" aria-labelledby="devices-account-title">
        <div className="device-scope-icon"><AlertCircle size={20} /></div>
        <div className="device-row-copy">
          <h2 id="devices-account-title">Device information unavailable</h2>
          <p>A verified signed-in account is required to view device information.</p>
        </div>
      </section>
    );
  }

  return (
    <div className="devices-page">
      <section className="panel device-scope-panel" aria-labelledby="browser-recognition-title">
        <div className="device-scope-icon"><Computer size={20} /></div>
        <div className="device-row-copy">
          <span className="device-scope-label">Current account · {profile.id}</span>
          <h2 id="browser-recognition-title">Current browser recognition is not available here</h2>
          <p>
            The backend can check whether the signed-in user’s current browser identifier is recognized. That endpoint requires an <code>X-Device-Token</code>, and this frontend has no supported source for that token, so no recognition status is shown.
          </p>
          <p className="device-data-note">
            Browser recognition only identifies a browser for access decisions. It does not report endpoint protection, compliance, operating system, or device health.
          </p>
        </div>
        <span className="device-availability">Unavailable</span>
      </section>

      <section className="panel device-unavailable" aria-labelledby="inventory-unavailable-title">
        <div className="device-scope-icon"><AlertCircle size={20} /></div>
        <div className="device-row-copy">
          <h2 id="inventory-unavailable-title">Organization device inventory is not exposed</h2>
          <p>
            Current APIs do not provide an administrator-authorized device inventory. An organization-wide view requires a separately approved backend API with explicit admin authorization; event history cannot safely substitute for an inventory.
          </p>
        </div>
        <span className="device-availability">Unavailable</span>
      </section>
    </div>
  );
}

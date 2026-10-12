import { AlertCircle, Sliders } from "../components/Icons";
import { ErrorState, LoadingState } from "../components/States";
import { useAuth } from "../auth/useAuth";
import type { AuthStatus } from "../auth/AuthSessionController";
import type { Profile } from "../types/api";

export function PolicySettingsPage() {
  const { profile, status, refreshProfile } = useAuth();
  return (
    <PolicySettingsContent
      profile={profile}
      status={status}
      onRetry={() => void refreshProfile()}
    />
  );
}

export function PolicySettingsContent({
  profile,
  status,
  onRetry,
}: {
  profile: Profile | null;
  status: AuthStatus;
  onRetry: () => void;
}) {
  if (status === "loading" || status === "resolving_profile") {
    return <LoadingState label="Verifying administrator access" />;
  }
  if (status === "profile_error" || status === "session_error") {
    return (
      <ErrorState
        message="TrustGate could not verify the current account. Policy information remains unavailable until verification succeeds."
        onRetry={onRetry}
      />
    );
  }
  if (status !== "authenticated" || profile?.role !== "ADMIN") {
    return (
      <section className="panel policy-unavailable" aria-labelledby="policy-access-title">
        <AlertCircle size={20} />
        <div>
          <h2 id="policy-access-title">Policy settings unavailable</h2>
          <p>A verified administrator account is required to view this page.</p>
        </div>
      </section>
    );
  }

  return (
    <div className="policy-settings-page">
      <section className="panel policy-status-panel" aria-labelledby="policy-config-title">
        <span className="policy-icon"><Sliders size={21} /></span>
        <div>
          <span className="policy-readonly-badge">READ ONLY · CONFIGURATION UNAVAILABLE</span>
          <h2 id="policy-config-title">Active policy configuration cannot be retrieved</h2>
          <p>
            The available API does not expose an administrator-authorized endpoint for reading the active policy configuration. This page has no policy values or controls because the backend cannot supply or save them.
          </p>
          <p>
            Real policy settings require a separately approved backend API with server-side authorization and validation. Policy evaluation must remain server-authoritative.
          </p>
        </div>
      </section>

      <section className="panel policy-context-panel" aria-labelledby="policy-version-context-title">
        <AlertCircle size={19} />
        <div>
          <h2 id="policy-version-context-title">Policy version labels are investigation-specific</h2>
          <p>
            An investigation may include the version ID, label, and creation time referenced by that event’s recorded decision. Those fields identify historical context for one decision; they do not expose the active policy or its thresholds and rules.
          </p>
        </div>
      </section>
    </div>
  );
}

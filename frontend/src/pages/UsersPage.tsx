import { AlertCircle } from "../components/Icons";
import { ErrorState, LoadingState } from "../components/States";
import { useAuth } from "../auth/useAuth";
import type { AuthStatus } from "../auth/AuthSessionController";
import type { Profile } from "../types/api";

export function UsersPage() {
  const { profile, status, refreshProfile } = useAuth();
  return (
    <UsersContent
      profile={profile}
      status={status}
      onRetry={() => void refreshProfile()}
    />
  );
}

export function UsersContent({
  profile,
  status,
  onRetry,
}: {
  profile: Profile | null;
  status: AuthStatus;
  onRetry: () => void;
}) {
  if (status === "loading" || status === "resolving_profile") {
    return <LoadingState label="Loading your verified profile" />;
  }
  if (status === "profile_error" || status === "session_error") {
    return (
      <ErrorState
        message="TrustGate could not verify the current profile. User details are hidden until verification succeeds."
        onRetry={onRetry}
      />
    );
  }
  if (status !== "authenticated" || !profile) {
    return (
      <section className="panel user-directory-unavailable" aria-labelledby="users-unavailable-title">
        <AlertCircle size={20} />
        <div>
          <h2 id="users-unavailable-title">User directory unavailable</h2>
          <p>No authenticated profile is available to display.</p>
        </div>
      </section>
    );
  }

  return (
    <div className="users-page">
      <section className="panel user-profile-panel" aria-labelledby="signed-in-profile-title">
        <div className="user-panel-heading">
          <div>
            <h2 id="signed-in-profile-title">Signed-in profile</h2>
            <p>Identity and role returned for your authenticated account.</p>
          </div>
          <span className="user-source-badge">Verified by backend</span>
        </div>
        <div className="table-scroll">
          <table className="user-profile-table">
            <caption className="sr-only">Signed-in administrator profile</caption>
            <thead>
              <tr>
                <th>User ID</th>
                <th>Email</th>
                <th>Role</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><code className="user-identifier">{profile.id}</code></td>
                <td>{profile.email ?? <span className="muted-copy">Not provided</span>}</td>
                <td><span className="badge badge-neutral">{profile.role}</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel user-directory-unavailable" aria-labelledby="directory-unavailable-title">
        <AlertCircle size={20} />
        <div>
          <h2 id="directory-unavailable-title">Organization user directory is not available</h2>
          <p>
            The current backend exposes the authenticated account profile only. It does not provide an administrator-visible user list, so this page cannot show other accounts or derive a roster from activity records.
          </p>
        </div>
      </section>
    </div>
  );
}

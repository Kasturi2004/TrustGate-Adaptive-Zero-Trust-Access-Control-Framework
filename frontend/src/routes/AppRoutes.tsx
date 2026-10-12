import { lazy, Suspense } from "react";
import { Navigate, Outlet, Route, Routes } from "react-router-dom";
import { useAuth } from "../auth/useAuth";
import { adminAccess } from "../auth/adminAccess";
import { AdminLayout } from "../components/AdminLayout";
import { LoadingState } from "../components/States";
import { ProfileVerificationFailure } from "../components/ProfileVerificationFailure";

const DashboardPage = lazy(() =>
  import("../pages/DashboardPage").then((module) => ({
    default: module.DashboardPage,
  })),
);
const EventsPage = lazy(() =>
  import("../pages/EventsPage").then((module) => ({
    default: module.EventsPage,
  })),
);
const AnalyticsPage = lazy(() =>
  import("../pages/AnalyticsPage").then((module) => ({
    default: module.AnalyticsPage,
  })),
);
const InvestigationPage = lazy(() =>
  import("../pages/InvestigationPage").then((module) => ({
    default: module.InvestigationPage,
  })),
);
const InvestigationsPage = lazy(() =>
  import("../pages/InvestigationsPage").then((module) => ({
    default: module.InvestigationsPage,
  })),
);
const LoginPage = lazy(() =>
  import("../pages/LoginPage").then((module) => ({
    default: module.LoginPage,
  })),
);
const RiskIndicatorsPage = lazy(() =>
  import("../pages/RiskIndicatorsPage").then((module) => ({
    default: module.RiskIndicatorsPage,
  })),
);
const UsersPage = lazy(() =>
  import("../pages/UsersPage").then((module) => ({
    default: module.UsersPage,
  })),
);
const DevicesPage = lazy(() =>
  import("../pages/DevicesPage").then((module) => ({
    default: module.DevicesPage,
  })),
);
const PolicySettingsPage = lazy(() =>
  import("../pages/PolicySettingsPage").then((module) => ({
    default: module.PolicySettingsPage,
  })),
);

function AdminGate() {
  const auth = useAuth();
  const access = adminAccess(auth);
  if (access === "loading")
    return <LoadingState fullPage label="Verifying administrator access" />;
  if (access === "unauthenticated" || access === "session_error") return <Navigate to="/login" replace />;
  if (access === "profile_error")
    return (
      <ProfileVerificationFailure
        onRetry={() => void auth.refreshProfile()}
        onSignOut={auth.signOut}
      />
    );
  if (access === "denied")
    return (
      <div className="gate-message">
        <h1>Administrator access required</h1>
        <p>Your verified account does not have the ADMIN role.</p>
        <p className="muted-copy">Access remains enforced by the TrustGate backend.</p>
      </div>
    );
  return <Outlet />;
}

export function AppRoutes() {
  const auth = useAuth();
  const access = adminAccess(auth);
  return (
    <Suspense fallback={<LoadingState fullPage />}>
      <Routes>
        <Route
          path="/login"
          element={
            access === "loading" ? (
              <LoadingState fullPage label="Verifying administrator access" />
            ) : access === "allow" ? (
              <Navigate to="/" replace />
            ) : access === "profile_error" && auth.session ? (
              <ProfileVerificationFailure
                title="Account verification unavailable"
                detail="TrustGate could not verify your current profile."
                onRetry={() => void auth.refreshProfile()}
                onSignOut={auth.signOut}
              />
            ) : (
              <LoginPage />
            )
          }
        />
        <Route element={<AdminGate />}>
          <Route element={<AdminLayout />}>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/events" element={<EventsPage />} />
            <Route path="/analytics" element={<AnalyticsPage />} />
            <Route path="/users" element={<UsersPage />} />
            <Route path="/devices" element={<DevicesPage />} />
            <Route path="/policy-settings" element={<PolicySettingsPage />} />
            <Route path="/investigations" element={<InvestigationsPage />} />
            <Route
              path="/investigations/:eventId"
              element={<InvestigationPage />}
            />
            <Route path="/risk-indicators" element={<RiskIndicatorsPage />} />
          </Route>
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Suspense>
  );
}

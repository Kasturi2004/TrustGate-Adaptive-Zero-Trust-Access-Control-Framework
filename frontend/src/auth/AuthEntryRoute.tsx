import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "./AuthProvider.tsx";
import { safeReturnPath } from "./returnPath.ts";

interface AuthEntryRouteProps {
  children: ReactNode;
}

export function AuthEntryRoute({ children }: AuthEntryRouteProps) {
  const { session, user, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <p role="status" aria-live="polite">
        Restoring session…
      </p>
    );
  }

  if (session && user) {
    return <Navigate to={safeReturnPath(location.state) ?? "/dashboard"} replace />;
  }

  return children;
}

import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { ProtectedRoute } from "../auth/ProtectedRoute.tsx";
import { useAuth } from "../auth/AuthProvider.tsx";
import { useProfileRole } from "../auth/useProfileRole.ts";

interface AdminRouteProps {
  children: ReactNode;
}

/**
 * Frontend navigation guard based on the trusted FastAPI profile response.
 * This is not a security boundary: FastAPI ADMIN authorization must protect
 * every admin API route.
 */
export function AdminRoute({ children }: AdminRouteProps) {
  const { session, user, loading: authLoading } = useAuth();
  const { role, loading: profileLoading } = useProfileRole();

  if (authLoading) {
    return (
      <p role="status" aria-live="polite">
        Restoring session…
      </p>
    );
  }

  if (!session || !user) {
    return <ProtectedRoute>{children}</ProtectedRoute>;
  }

  if (profileLoading) {
    return (
      <p role="status" aria-live="polite">
        Checking admin access…
      </p>
    );
  }

  if (role !== "ADMIN") {
    return <Navigate to="/access" replace />;
  }

  return <ProtectedRoute>{children}</ProtectedRoute>;
}

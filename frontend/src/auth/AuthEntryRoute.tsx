import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "./AuthProvider.tsx";

interface AuthEntryRouteProps {
  children: ReactNode;
}

export function AuthEntryRoute({ children }: AuthEntryRouteProps) {
  const { session, user, loading } = useAuth();

  if (loading) {
    return (
      <p role="status" aria-live="polite">
        Restoring session…
      </p>
    );
  }

  if (session && user) {
    return <Navigate to="/access" replace />;
  }

  return children;
}

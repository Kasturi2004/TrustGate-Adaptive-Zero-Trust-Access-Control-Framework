import { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthProvider.tsx";
import { supabase } from "../lib/supabase.ts";

const LOGOUT_ERROR = "Unable to sign out right now. Please try again.";

export function LogoutButton() {
  const { session, user, loading } = useAuth();
  const navigate = useNavigate();
  const signingOutRef = useRef(false);
  const [signingOut, setSigningOut] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (loading || !session || !user) {
    return null;
  }

  async function handleLogout(): Promise<void> {
    if (signingOutRef.current) {
      return;
    }

    signingOutRef.current = true;
    setSigningOut(true);
    setError(null);
    try {
      const { error: signOutError } = await supabase.auth.signOut();
      if (signOutError) {
        setError(LOGOUT_ERROR);
        return;
      }

      navigate("/login", { replace: true });
    } catch {
      setError(LOGOUT_ERROR);
    } finally {
      signingOutRef.current = false;
      setSigningOut(false);
    }
  }

  return (
    <li className="nav-auth-action">
      <button className="logout-button" type="button" onClick={handleLogout} disabled={signingOut}>
        {signingOut ? "Signing out…" : "Sign out"}
      </button>
      {error ? (
        <span className="logout-error" role="alert">
          {error}
        </span>
      ) : null}
    </li>
  );
}

import { useEffect, useState } from "react";
import { apiRequest } from "../api/client.ts";
import { useAuth } from "./AuthProvider.tsx";

export type ProfileRole = "USER" | "ADMIN";

interface ProfileRoleState {
  userId: string | null;
  accessToken: string | null;
  role: ProfileRole | null;
}

function isProfileRoleResponse(
  value: unknown,
  expectedUserId: string,
): value is { id: string; role: ProfileRole } {
  if (typeof value !== "object" || value === null) return false;

  const profile = value as Record<string, unknown>;
  return profile.id === expectedUserId && (profile.role === "USER" || profile.role === "ADMIN");
}

export async function fetchProfileRole(expectedUserId: string): Promise<ProfileRole | null> {
  const response = await apiRequest("/auth/me");
  if (!response.ok) return null;

  const profile: unknown = await response.json();
  return isProfileRoleResponse(profile, expectedUserId) ? profile.role : null;
}

/** Resolve the authorization role from the database-backed FastAPI profile. */
export function useProfileRole(): { role: ProfileRole | null; loading: boolean } {
  const { session, user, loading: authLoading } = useAuth();
  const userId = session && user ? user.id : null;
  const accessToken = session?.access_token;
  const [state, setState] = useState<ProfileRoleState>({
    userId: null,
    accessToken: null,
    role: null,
  });

  useEffect(() => {
    let active = true;

    if (authLoading) {
      return () => {
        active = false;
      };
    }

    if (!userId || !accessToken) {
      return () => {
        active = false;
      };
    }

    void fetchProfileRole(userId)
      .then((role) => {
        if (active) {
          setState({ userId, accessToken, role });
        }
      })
      .catch(() => {
        if (active) setState({ userId, accessToken, role: null });
      });

    return () => {
      active = false;
    };
  }, [accessToken, authLoading, userId]);

  const stateIsCurrent = state.userId === userId && state.accessToken === accessToken;
  return {
    role: userId !== null && stateIsCurrent ? state.role : null,
    loading: authLoading || (userId !== null && !stateIsCurrent),
  };
}

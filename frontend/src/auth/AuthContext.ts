import { createContext } from "react";
import type { Session } from "@supabase/supabase-js";
import type { Profile } from "../types/api";
import type { AuthStatus } from "./AuthSessionController";

export interface AuthValue {
  session: Session | null;
  profile: Profile | null;
  status: AuthStatus;
  loading: boolean;
  configurationReady: boolean;
  signIn: (email: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
  refreshProfile: () => Promise<void>;
}

export const AuthContext = createContext<AuthValue | null>(null);

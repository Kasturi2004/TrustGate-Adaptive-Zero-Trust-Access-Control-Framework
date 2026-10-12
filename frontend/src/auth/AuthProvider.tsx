import { useEffect, useMemo, useSyncExternalStore } from "react";
import type { ReactNode } from "react";
import type { Session } from "@supabase/supabase-js";
import { api } from "../api/client";
import { AuthContext } from "./AuthContext";
import type { AuthValue } from "./AuthContext";
import { AuthSessionController } from "./AuthSessionController";
import { supabase } from "./supabase";

const controller = new AuthSessionController((token, signal) =>
  api.profile(token, signal),
);

export function AuthProvider({ children }: { children: ReactNode }) {
  const snapshot = useSyncExternalStore(
    controller.subscribe,
    controller.getSnapshot,
    controller.getSnapshot,
  );

  useEffect(() => {
    if (!supabase) {
      controller.setSession(null);
      return;
    }
    let active = true;
    let authEventCount = 0;
    const { data: listener } = supabase.auth.onAuthStateChange((_event, next) => {
      authEventCount += 1;
      if (active) controller.setSession(next as Session | null);
    });
    const initialEventCount = authEventCount;
    void supabase.auth.getSession().then(
      ({ data }) => {
        if (active && authEventCount === initialEventCount) {
          controller.setSession(data.session as Session | null);
        }
      },
      () => {
        if (active && authEventCount === initialEventCount) {
          controller.failSessionResolution();
        }
      },
    );
    return () => {
      active = false;
      listener.subscription.unsubscribe();
    };
  }, []);

  const value = useMemo<AuthValue>(
    () => ({
      session: snapshot.session as Session | null,
      profile: snapshot.profile,
      status: snapshot.status,
      loading: snapshot.status === "loading" || snapshot.status === "resolving_profile",
      configurationReady: supabase !== null,
      async signIn(email, password) {
        if (!supabase) {
          throw new Error("Authentication is not configured for this frontend.");
        }
        const body = await api.login(email, password).catch(() => {
          throw new Error("Sign-in request was rejected.");
        });
        if (
          typeof body !== "object" ||
          body === null ||
          !("access_token" in body) ||
          !("refresh_token" in body) ||
          typeof body.access_token !== "string" ||
          typeof body.refresh_token !== "string"
        ) {
          throw new Error("The authentication service returned an incomplete session.");
        }
        const result = await supabase.auth.setSession({
          access_token: body.access_token,
          refresh_token: body.refresh_token,
        });
        if (result.error) throw new Error(result.error.message);
        if (!result.data.session) {
          throw new Error("The authentication service did not establish a session.");
        }
        controller.setSession(result.data.session);
      },
      async signOut() {
        if (supabase) {
          const result = await supabase.auth.signOut();
          if (result.error) throw new Error(result.error.message);
        }
        controller.setSession(null);
      },
      async refreshProfile() {
        controller.retryProfile();
      },
    }),
    [snapshot],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

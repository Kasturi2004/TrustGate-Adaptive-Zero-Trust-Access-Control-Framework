import type { Profile } from "../types/api";

export interface AuthSessionLike {
  access_token: string;
  user: { id: string };
}

export type AuthStatus =
  | "loading"
  | "unauthenticated"
  | "resolving_profile"
  | "authenticated"
  | "profile_error"
  | "session_error";

export interface AuthSnapshot {
  session: AuthSessionLike | null;
  profile: Profile | null;
  status: AuthStatus;
}

type ProfileResolver = (token: string, signal: AbortSignal) => Promise<Profile>;
const PROFILE_TIMEOUT_MS = 15_000;

export class AuthSessionController {
  private snapshot: AuthSnapshot = {
    session: null,
    profile: null,
    status: "loading",
  };
  private listeners = new Set<() => void>();
  private generation = 0;
  private activeKey: string | null = null;
  private abortController: AbortController | null = null;
  private profileTimeout: ReturnType<typeof setTimeout> | null = null;

  constructor(private readonly resolveProfile: ProfileResolver) {}

  getSnapshot = (): AuthSnapshot => this.snapshot;

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  private publish(snapshot: AuthSnapshot) {
    this.snapshot = snapshot;
    this.listeners.forEach((listener) => listener());
  }

  setSession(session: AuthSessionLike | null) {
    const key = session ? `${session.user.id}:${session.access_token}` : null;
    if (
      key === this.activeKey &&
      this.snapshot.status !== "session_error" &&
      (session !== null || this.snapshot.status === "unauthenticated")
    ) return;

    this.generation += 1;
    const generation = this.generation;
    if (this.profileTimeout !== null) clearTimeout(this.profileTimeout);
    this.profileTimeout = null;
    this.abortController?.abort();
    this.abortController = null;
    this.activeKey = key;

    if (!session) {
      this.publish({ session: null, profile: null, status: "unauthenticated" });
      return;
    }

    // Clear the prior profile synchronously before starting the next request.
    this.publish({ session, profile: null, status: "resolving_profile" });
    const abortController = new AbortController();
    this.abortController = abortController;
    let timedOut = false;
    const timeout = setTimeout(() => {
      this.profileTimeout = null;
      timedOut = true;
      abortController.abort();
      if (generation === this.generation) {
        this.publish({ session, profile: null, status: "profile_error" });
      }
    }, PROFILE_TIMEOUT_MS);
    this.profileTimeout = timeout;
    void this.resolveProfile(session.access_token, abortController.signal)
      .then((profile) => {
        clearTimeout(timeout);
        if (this.profileTimeout === timeout) this.profileTimeout = null;
        if (generation !== this.generation || (abortController.signal.aborted && !timedOut)) return;
        if (timedOut) {
          this.publish({ session, profile: null, status: "profile_error" });
          return;
        }
        if (profile.id !== session.user.id) {
          this.publish({ session, profile: null, status: "profile_error" });
          return;
        }
        this.publish({ session, profile, status: "authenticated" });
      })
      .catch(() => {
        clearTimeout(timeout);
        if (this.profileTimeout === timeout) this.profileTimeout = null;
        if (generation !== this.generation || (abortController.signal.aborted && !timedOut)) return;
        this.publish({ session, profile: null, status: "profile_error" });
      });
  }

  retryProfile() {
    if (this.snapshot.session) {
      this.activeKey = null;
      this.setSession(this.snapshot.session);
    }
  }

  failSessionResolution() {
    this.generation += 1;
    if (this.profileTimeout !== null) clearTimeout(this.profileTimeout);
    this.profileTimeout = null;
    this.abortController?.abort();
    this.abortController = null;
    this.activeKey = null;
    this.publish({ session: null, profile: null, status: "session_error" });
  }
}

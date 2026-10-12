import type { AuthSnapshot } from "./AuthSessionController";

export type AdminAccess =
  | "loading"
  | "unauthenticated"
  | "session_error"
  | "profile_error"
  | "denied"
  | "allow";

export function adminAccess(snapshot: AuthSnapshot): AdminAccess {
  if (snapshot.status === "loading" || snapshot.status === "resolving_profile") return "loading";
  if (snapshot.status === "session_error") return "session_error";
  if (snapshot.status === "profile_error") return "profile_error";
  if (snapshot.status === "unauthenticated" || !snapshot.session) return "unauthenticated";
  if (!snapshot.profile || snapshot.profile.id !== snapshot.session.user.id) return "profile_error";
  return snapshot.profile.role === "ADMIN" ? "allow" : "denied";
}

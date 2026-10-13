import { ApiError, authenticatedRequest, type PortalSession } from "./session";

export type TotpEnrollment = {
  otpauth_uri: string;
  manual_entry_key: string;
};

const ENROLLMENT_TIMEOUT_MS = 15_000;
const enrollmentRequests = new Map<string, Promise<TotpEnrollment>>();

function enrollmentError(status: number): Error {
  if (status === 401) return new Error("Your session expired. Sign in again to continue.");
  if (status === 403) return new Error("You are not authorized to set up this authenticator.");
  if (status === 429) return new Error("Too many setup attempts. Wait a moment and retry.");
  if (status >= 500) {
    return new Error("Authenticator setup is temporarily unavailable. Please retry.");
  }
  return new Error("TrustGate could not start authenticator setup. Please retry.");
}

function safeEnrollmentError(error: unknown): Error {
  if (error instanceof ApiError) {
    if (error.status === 0) {
      return new Error("Unable to reach TrustGate. Check your connection and retry.");
    }
    return enrollmentError(error.status);
  }
  return new Error("TrustGate returned an invalid authenticator setup response.");
}

async function performEnrollment(
  api: string,
  session: PortalSession,
  signal: AbortSignal,
  storage: Storage,
) {
  let result: unknown;
  try {
    result = await authenticatedRequest<unknown>(
      api,
      "/auth/mfa/totp/enrollment",
      session,
      { method: "POST", signal },
      storage,
    );
  } catch (error) {
    throw safeEnrollmentError(error);
  }
  if (
    typeof result !== "object" || result === null ||
    !("otpauth_uri" in result) || typeof result.otpauth_uri !== "string" || !result.otpauth_uri ||
    !("manual_entry_key" in result) || typeof result.manual_entry_key !== "string" || !result.manual_entry_key
  ) {
    throw new Error("TrustGate returned an invalid authenticator setup response.");
  }
  return {
    otpauth_uri: result.otpauth_uri,
    manual_entry_key: result.manual_entry_key,
  };
}

export function requestTotpEnrollment(
  api: string,
  session: PortalSession,
  storage: Storage = window.sessionStorage,
): Promise<TotpEnrollment> {
  const key = `${api}\u0000${session.token}\u0000${session.refresh_token ?? ""}`;
  const existing = enrollmentRequests.get(key);
  if (existing) return existing;

  const controller = new AbortController();
  let timeout: ReturnType<typeof setTimeout>;
  const timedOut = new Promise<never>((_resolve, reject) => {
    timeout = setTimeout(() => {
      controller.abort();
      reject(new Error("Secure setup is taking too long. Check your connection and retry."));
    }, ENROLLMENT_TIMEOUT_MS);
  });
  const request = Promise.race([
    performEnrollment(api, session, controller.signal, storage),
    timedOut,
  ]).finally(() => clearTimeout(timeout));

  enrollmentRequests.set(key, request);
  void request.then(
    () => {
      if (enrollmentRequests.get(key) === request) enrollmentRequests.delete(key);
    },
    () => {
      if (enrollmentRequests.get(key) === request) enrollmentRequests.delete(key);
    },
  );
  return request;
}

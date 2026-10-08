import { apiRequest } from "./client.ts";
import type {
  TotpEnrollmentStartResponse,
  TotpEnrollmentVerificationResponse,
} from "../types/mfaEnrollment.ts";

export class MfaEnrollmentApiError extends Error {
  readonly status: number;

  constructor(status: number) {
    super("Authenticator enrollment request failed");
    this.name = "MfaEnrollmentApiError";
    this.status = status;
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export async function startTotpEnrollment(): Promise<TotpEnrollmentStartResponse> {
  const response = await apiRequest("/auth/mfa/totp/enrollment", { method: "POST" });
  if (!response.ok) throw new MfaEnrollmentApiError(response.status);

  const body: unknown = await response.json();
  if (
    !isObject(body) ||
    typeof body.otpauth_uri !== "string" ||
    !body.otpauth_uri.startsWith("otpauth://totp/") ||
    typeof body.manual_entry_key !== "string" ||
    body.manual_entry_key.trim() === ""
  ) {
    throw new Error("Authenticator setup response was not recognized");
  }

  return {
    otpauth_uri: body.otpauth_uri,
    manual_entry_key: body.manual_entry_key,
  };
}

export async function verifyTotpEnrollment(
  code: string,
): Promise<TotpEnrollmentVerificationResponse> {
  const response = await apiRequest("/auth/mfa/totp/enrollment/verify", {
    method: "POST",
    body: { code },
  });
  if (!response.ok) throw new MfaEnrollmentApiError(response.status);

  const body: unknown = await response.json();
  if (
    !isObject(body) ||
    body.enrollment_status !== "verified" ||
    typeof body.verified_at !== "string" ||
    !Number.isFinite(Date.parse(body.verified_at))
  ) {
    throw new Error("Authenticator verification response was not recognized");
  }

  return {
    enrollment_status: "verified",
    verified_at: body.verified_at,
  };
}

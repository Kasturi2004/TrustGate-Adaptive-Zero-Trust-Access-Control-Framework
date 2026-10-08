export interface TotpEnrollmentStartResponse {
  otpauth_uri: string;
  manual_entry_key: string;
}

export interface TotpEnrollmentVerificationResponse {
  enrollment_status: "verified";
  verified_at: string;
}

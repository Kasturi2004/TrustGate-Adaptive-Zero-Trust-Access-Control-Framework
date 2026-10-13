export function formatDeviceHealth(
  value: string,
  assessmentVersion?: string | null,
): string {
  if (assessmentVersion !== "posture-v1") {
    return `Legacy browser/transport signal: ${value.replaceAll("_", " ")}`;
  }
  if (value === "unknown") return "Unknown · posture unverified";
  if (value === "healthy") return "Verified posture healthy";
  if (value === "unhealthy") return "Verified posture failure";
  if (value === "partially_healthy") return "Verified posture below healthy threshold";
  return `Posture status: ${value.replaceAll("_", " ")}`;
}

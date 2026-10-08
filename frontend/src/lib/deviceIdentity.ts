const DEVICE_IDENTIFIER_STORAGE_KEY = "trustgate.device-identifier.v1";

/** Return the browser's persistent, non-authenticating device familiarity identifier. */
export function getDeviceIdentifier(): string {
  const existingIdentifier = localStorage.getItem(DEVICE_IDENTIFIER_STORAGE_KEY);
  if (existingIdentifier) return existingIdentifier;

  const identifier = crypto.randomUUID();
  localStorage.setItem(DEVICE_IDENTIFIER_STORAGE_KEY, identifier);
  return identifier;
}

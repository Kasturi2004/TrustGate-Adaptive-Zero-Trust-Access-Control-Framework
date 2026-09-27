export function apiBaseUrl(): string {
  const value = import.meta.env.VITE_API_BASE_URL;
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error("VITE_API_BASE_URL is required");
  }
  return value.replace(/\/$/, "");
}

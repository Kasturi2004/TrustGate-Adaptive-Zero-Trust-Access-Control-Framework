const UUID_PATH = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";

const PROTECTED_PATHS = new Set([
  "/operations",
  "/access",
  "/history",
  "/account",
  "/admin/overview",
  "/admin/events",
]);

export function safeReturnPath(locationState: unknown): string | null {
  if (typeof locationState !== "object" || locationState === null || !("from" in locationState)) {
    return null;
  }
  const destination = locationState.from;
  if (typeof destination !== "object" || destination === null || !("pathname" in destination)) {
    return null;
  }

  const { pathname, search, hash } = destination as Record<string, unknown>;
  if (typeof pathname !== "string") return null;

  const isProtectedPath =
    PROTECTED_PATHS.has(pathname) ||
    new RegExp(`^/history/${UUID_PATH}$`, "i").test(pathname) ||
    new RegExp(`^/admin/events/${UUID_PATH}$`, "i").test(pathname);
  if (!isProtectedPath) return null;

  const safeSearch = typeof search === "string" && search.startsWith("?") ? search : "";
  const safeHash = typeof hash === "string" && hash.startsWith("#") ? hash : "";
  return `${pathname}${safeSearch}${safeHash}`;
}

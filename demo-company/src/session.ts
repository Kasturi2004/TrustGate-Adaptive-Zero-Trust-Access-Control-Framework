export type PortalSession = {
  token: string;
  refresh_token?: string;
  user?: { email?: string };
};

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
    this.name = "ApiError";
  }
}

type RefreshResponse = {
  access_token?: string;
  refresh_token?: string;
};

let refreshInFlight: { token: string; request: Promise<Response> } | null = null;

function refresh(api: string, token: string): Promise<Response> {
  if (refreshInFlight?.token === token) return refreshInFlight.request;
  const request = fetch(api + "/auth/refresh", {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: token }),
  });
  refreshInFlight = { token, request };
  const clear = () => {
    if (refreshInFlight?.request === request) refreshInFlight = null;
  };
  void request.then(clear, clear);
  return request.then((response) => response.clone());
}

function errorMessage(body: { detail?: unknown; error?: { message?: unknown } }, status: number) {
  const message = body.detail || body.error?.message;
  return typeof message === "string" ? message : `Request failed (${status}).`;
}

export function readPortalSession(storage: Storage): PortalSession | null {
  const key = "acme.session";
  try {
    const saved: unknown = JSON.parse(storage.getItem(key) || "null");
    if (saved === null) return null;
    if (typeof saved !== "object" || !saved || !("token" in saved)
      || typeof saved.token !== "string" || !saved.token
      || ("refresh_token" in saved && typeof saved.refresh_token !== "string")) {
      storage.removeItem(key);
      return null;
    }
    return saved as PortalSession;
  } catch {
    storage.removeItem(key);
    return null;
  }
}

async function readBody(response: Response): Promise<{ detail?: unknown; error?: { message?: unknown } }> {
  return response.json().catch(() => ({}));
}

export async function authenticatedRequest<T>(
  api: string,
  path: string,
  session: PortalSession,
  init: RequestInit = {},
  storage: Storage = window.sessionStorage,
): Promise<T> {
  const storedSession = readPortalSession(storage);
  const activeSession = storedSession && storedSession.refresh_token === session.refresh_token
    ? storedSession
    : session;
  const send = (token: string) => fetch(api + path, {
    ...init,
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${token}`,
      ...(init.body ? { "Content-Type": "application/json" } : {}),
      ...init.headers,
    },
  });

  let response: Response;
  try {
    response = await send(activeSession.token);
  } catch {
    throw new ApiError("Unable to reach TrustGate. Check your connection and try again.", 0);
  }
  let refreshedSession = false;
  if (response.status === 401 && activeSession.refresh_token) {
    let refreshResponse: Response;
    try {
      refreshResponse = await refresh(api, activeSession.refresh_token);
    } catch {
      throw new ApiError("Unable to reach TrustGate. Check your connection and try again.", 0);
    }
    const refreshed = await readBody(refreshResponse) as RefreshResponse & { detail?: unknown };
    if (!refreshResponse.ok) {
      if (refreshResponse.status === 401) {
        throw new ApiError("Your session expired. Sign in again to continue.", 401);
      }
      throw new ApiError(errorMessage(refreshed, refreshResponse.status), refreshResponse.status);
    }
    if (!refreshed.access_token || !refreshed.refresh_token) {
      throw new ApiError("TrustGate returned an invalid session response.", 502);
    }
    activeSession.token = refreshed.access_token;
    activeSession.refresh_token = refreshed.refresh_token;
    session.token = refreshed.access_token;
    session.refresh_token = refreshed.refresh_token;
    storage.setItem("acme.session", JSON.stringify(activeSession));
    refreshedSession = true;
    try {
      response = await send(activeSession.token);
    } catch {
      throw new ApiError("Unable to reach TrustGate. Check your connection and try again.", 0);
    }
  }

  const body = await readBody(response);
  if (!response.ok) {
    const message = response.status === 401
      ? refreshedSession
        ? "TrustGate rejected the refreshed session. Sign in again or contact your administrator."
        : "Your session expired. Sign in again to continue."
      : errorMessage(body, response.status);
    throw new ApiError(message, response.status);
  }
  return body as T;
}

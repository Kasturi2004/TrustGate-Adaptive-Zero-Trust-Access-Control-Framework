import type {
  DashboardMetrics,
  Investigation,
  Profile,
  SecurityEventPage,
} from "../types/api";

const API_BASE = (
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000"
).replace(/\/$/, "");

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export interface SecurityEventFilters {
  from?: string;
  to?: string;
  user_id?: string;
  decision?: "ALLOW" | "STEP_UP" | "BLOCK";
  risk_category?: "LOW" | "MEDIUM" | "HIGH";
  device_id?: string;
  score_min?: string;
  score_max?: string;
}

export function buildEventsQuery(
  page: number,
  pageSize: number,
  filters: SecurityEventFilters = {},
): string {
  const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
  for (const key of ["from", "to"] as const) {
    const value = filters[key];
    if (value) params.set(key, new Date(value).toISOString());
  }
  for (const key of ["user_id", "decision", "risk_category", "device_id", "score_min", "score_max"] as const) {
    const value = filters[key];
    if (value) params.set(key, value);
  }
  return params.toString();
}

async function request<T>(
  path: string,
  token: string,
  init?: RequestInit,
): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${token}`,
      ...init?.headers,
    },
  });
  if (!response.ok) {
    // Keep backend exception details out of the UI; retain only the status for
    // safe handling and diagnostics at the frontend boundary.
    throw new ApiError(`Request failed (${response.status})`, response.status);
  }
  return (await response.json()) as T;
}

function parseProfile(value: unknown): Profile {
  if (
    typeof value !== "object" ||
    value === null ||
    !("id" in value) ||
    typeof value.id !== "string" ||
    !("email" in value) ||
    !(typeof value.email === "string" || value.email === null) ||
    !("role" in value) ||
    (value.role !== "ADMIN" && value.role !== "USER")
  ) {
    throw new ApiError("The authentication service returned an invalid profile.", 200);
  }
  return { id: value.id, email: value.email, role: value.role };
}

export const api = {
  async login(email: string, password: string) {
    const response = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email, password }),
    });
    if (!response.ok) {
      throw new ApiError(`Sign-in request failed (${response.status})`, response.status);
    }
    return (await response.json()) as unknown;
  },
  async profile(token: string, signal?: AbortSignal) {
    return parseProfile(await request<unknown>("/auth/me", token, { signal }));
  },
  dashboard: (token: string, from: Date, to: Date, signal?: AbortSignal) => {
    const params = new URLSearchParams({
      from: from.toISOString(),
      to: to.toISOString(),
    });
    return request<DashboardMetrics>(`/admin/dashboard?${params}`, token, { signal });
  },
  events: (
    token: string,
    page = 1,
    pageSize = 20,
    filters: SecurityEventFilters = {},
    signal?: AbortSignal,
  ) => request<SecurityEventPage>(
    `/admin/events?${buildEventsQuery(page, pageSize, filters)}`,
    token,
    { signal },
  ),
  investigation: (token: string, eventId: string, signal?: AbortSignal) =>
    request<Investigation>(
      `/admin/events/${encodeURIComponent(eventId)}`,
      token,
      { signal },
    ),
};

export function dashboardInterval(
  now = new Date(),
  days = 30,
): { from: Date; to: Date } {
  const to = new Date(now);
  const from = new Date(now);
  from.setUTCDate(from.getUTCDate() - days);
  return { from, to };
}

import { apiRequest } from "./client.ts";
import {
  parseAdminDashboard,
  parseAdminEventPage,
  parseAdminInvestigation,
  type AdminDashboard,
  type AdminEventFilters,
  type AdminEventInvestigation,
  type AdminEventPage,
} from "../types/admin.ts";

async function getJson(path: string, signal?: AbortSignal): Promise<unknown> {
  const response = await apiRequest(path, { signal });
  if (!response.ok) throw new Error("Administrator request failed");
  return response.json() as Promise<unknown>;
}

export async function fetchAdminDashboard(
  from: string,
  to: string,
  signal?: AbortSignal,
): Promise<AdminDashboard> {
  const query = new URLSearchParams({ from, to });
  return parseAdminDashboard(await getJson(`/admin/dashboard?${query.toString()}`, signal));
}

export async function fetchAdminEvents(
  filters: AdminEventFilters,
  signal?: AbortSignal,
): Promise<AdminEventPage> {
  const query = new URLSearchParams();
  for (const key of [
    "from",
    "to",
    "user_id",
    "decision",
    "risk_category",
    "device_id",
    "score_min",
    "score_max",
    "page",
    "page_size",
  ] as const) {
    const value = filters[key];
    if (value !== undefined && value !== "") query.set(key, String(value));
  }
  return parseAdminEventPage(await getJson(`/admin/events?${query.toString()}`, signal));
}

export async function fetchAdminEventInvestigation(
  eventId: string,
  signal?: AbortSignal,
): Promise<AdminEventInvestigation> {
  const encodedId = encodeURIComponent(eventId);
  return parseAdminInvestigation(await getJson(`/admin/events/${encodedId}`, signal));
}

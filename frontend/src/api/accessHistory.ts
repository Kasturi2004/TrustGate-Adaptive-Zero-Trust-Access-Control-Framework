import { apiRequest } from "./client.ts";
import {
  parseAccessHistoryEntry,
  parseAccessHistoryResponse,
  type AccessHistoryEntry,
} from "../types/accessHistory.ts";
import { parseAdminInvestigation, type AdminEventInvestigation } from "../types/admin.ts";

export type AccessRequestDetail =
  | { kind: "user"; record: AccessHistoryEntry }
  | { kind: "admin"; investigation: AdminEventInvestigation };

export async function fetchAccessHistory(
  page: number,
  pageSize: number,
  signal?: AbortSignal,
): Promise<AccessHistoryEntry[]> {
  const query = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
  const response = await apiRequest(`/access/history?${query.toString()}`, { signal });
  if (!response.ok) {
    throw new Error("Access history request failed");
  }
  return parseAccessHistoryResponse(await response.json());
}

export async function fetchAccessRequest(
  accessRequestId: string,
  signal?: AbortSignal,
): Promise<AccessRequestDetail> {
  const response = await apiRequest(`/access/request/${encodeURIComponent(accessRequestId)}`, {
    signal,
  });
  if (!response.ok) {
    throw new Error("Access request detail failed");
  }
  const body: unknown = await response.json();
  try {
    return { kind: "user", record: parseAccessHistoryEntry(body) };
  } catch {
    return { kind: "admin", investigation: parseAdminInvestigation(body) };
  }
}

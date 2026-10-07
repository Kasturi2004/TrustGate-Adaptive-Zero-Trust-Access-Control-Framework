import { apiRequest } from "./client.ts";
import {
  parseAccessHistoryEntry,
  parseAccessHistoryResponse,
  type AccessHistoryEntry,
} from "../types/accessHistory.ts";

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
): Promise<AccessHistoryEntry> {
  const response = await apiRequest(`/access/request/${encodeURIComponent(accessRequestId)}`, {
    signal,
  });
  if (!response.ok) {
    throw new Error("Access request detail failed");
  }
  return parseAccessHistoryEntry(await response.json());
}

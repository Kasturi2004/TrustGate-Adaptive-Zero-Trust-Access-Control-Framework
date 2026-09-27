import type { HealthResponse } from "../types/health.ts";

export function parseHealthResponse(body: unknown): HealthResponse {
  if (typeof body !== "object" || body === null || !("status" in body)) {
    throw new Error("Health response was not recognized");
  }
  if (body.status !== "ok") {
    throw new Error("Health response was not recognized");
  }
  return { status: "ok" };
}

export async function fetchHealth(baseUrl: string, signal?: AbortSignal): Promise<HealthResponse> {
  const response = await fetch(`${baseUrl}/health`, {
    method: "GET",
    headers: { Accept: "application/json" },
    signal,
  });
  if (!response.ok) {
    throw new Error(`Health check failed (${response.status})`);
  }
  return parseHealthResponse(await response.json());
}

import { apiBaseUrl } from "../lib/env.ts";
import { supabase } from "../lib/supabase.ts";

export type ApiMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface ApiRequestOptions {
  method?: ApiMethod;
  body?: unknown;
  headers?: HeadersInit;
  signal?: AbortSignal;
}

function hasJsonContentType(headers: Headers): boolean {
  const contentType = headers.get("Content-Type");
  return contentType !== null && /^application\/(?:[\w.-]+\+)?json(?:\s*;|$)/i.test(contentType);
}

export async function apiRequest(path: string, options: ApiRequestOptions = {}): Promise<Response> {
  const { data } = await supabase.auth.getSession();
  const headers = new Headers(options.headers);

  if (options.body !== undefined && !hasJsonContentType(headers)) {
    headers.set("Content-Type", "application/json");
  }

  const accessToken = data.session?.access_token;
  if (accessToken) {
    headers.set("Authorization", `Bearer ${accessToken}`);
  }

  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  const url = `${apiBaseUrl()}${normalizedPath}`;
  const request: RequestInit = {
    method: options.method ?? "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    signal: options.signal,
  };

  const response = await fetch(url, request);
  if (response.status !== 401) {
    return response;
  }

  let refreshedAccessToken: string | undefined;
  try {
    const { data: refreshedData, error } = await supabase.auth.refreshSession();
    if (!error) {
      refreshedAccessToken = refreshedData.session?.access_token;
    }
  } catch {
    // Treat refresh exceptions the same as a refresh response without a usable session.
  }

  if (!refreshedAccessToken) {
    try {
      await supabase.auth.signOut();
    } catch {
      // Preserve the original authentication response if sign-out fails.
    }
    return response;
  }

  const retryHeaders = new Headers(headers);
  retryHeaders.set("Authorization", `Bearer ${refreshedAccessToken}`);
  const retryResponse = await fetch(url, { ...request, headers: retryHeaders });
  if (retryResponse.status === 401) {
    try {
      await supabase.auth.signOut();
    } catch {
      // Preserve the retry authentication response if sign-out fails.
    }
  }
  return retryResponse;
}

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
  return fetch(`${apiBaseUrl()}${normalizedPath}`, {
    method: options.method ?? "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    signal: options.signal,
  });
}

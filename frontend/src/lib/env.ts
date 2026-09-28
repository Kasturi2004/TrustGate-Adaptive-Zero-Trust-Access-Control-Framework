function requiredEnv(value: unknown, name: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${name} is required`);
  }
  return value;
}

export function apiBaseUrl(): string {
  return requiredEnv(import.meta.env.VITE_API_BASE_URL, "VITE_API_BASE_URL").replace(/\/$/, "");
}

export interface SupabasePublicConfig {
  url: string;
  anonKey: string;
}

export function supabasePublicConfig(): SupabasePublicConfig {
  return {
    url: requiredEnv(import.meta.env.VITE_SUPABASE_URL, "VITE_SUPABASE_URL").trim(),
    anonKey: requiredEnv(import.meta.env.VITE_SUPABASE_ANON_KEY, "VITE_SUPABASE_ANON_KEY").trim(),
  };
}

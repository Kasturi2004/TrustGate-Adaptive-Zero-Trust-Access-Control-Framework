import { createClient } from "@supabase/supabase-js";
import { supabasePublicConfig } from "./env.ts";

const { url, anonKey } = supabasePublicConfig();

export const supabase = createClient(url, anonKey);

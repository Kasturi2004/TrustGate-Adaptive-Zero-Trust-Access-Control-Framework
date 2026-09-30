import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  envDir: "..",
  server: {
    port: 5173,
    strictPort: true,
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    env: {
      VITE_SUPABASE_URL: "https://supabase.test.invalid",
      VITE_SUPABASE_ANON_KEY: "vitest-public-anon-key",
    },
  },
});

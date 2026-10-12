import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { AuthContext } from "../auth/AuthContext";
import type { AuthValue } from "../auth/AuthContext";
import { AdminLayout } from "./AdminLayout";

const authValue: AuthValue = {
  session: null,
  profile: { id: "admin-id", email: "admin@example.test", role: "ADMIN" },
  status: "authenticated",
  loading: false,
  configurationReady: true,
  signIn: async () => undefined,
  signOut: async () => undefined,
  refreshProfile: async () => undefined,
};

describe("admin navigation", () => {
  it("links to each admin section and exposes mobile menu relationships", () => {
    const markup = renderToStaticMarkup(
      createElement(
        MemoryRouter,
        null,
        createElement(
          AuthContext.Provider,
          { value: authValue },
          createElement(AdminLayout),
        ),
      ),
    );

    for (const path of [
      "/",
      "/analytics",
      "/users",
      "/devices",
      "/policy-settings",
      "/events",
      "/investigations",
      "/risk-indicators",
    ]) {
      expect(markup).toContain(`href="${path}"`);
    }
    expect(markup).toContain('aria-label="Admin navigation"');
    expect(markup).toContain(">Monitor</p>");
    expect(markup).toContain(">Manage</p>");
    expect(markup).toContain(">Investigate</p>");
    expect(markup).toContain('id="admin-navigation-panel"');
    expect(markup).toContain('aria-controls="admin-navigation-panel"');
    expect(markup).toContain('aria-expanded="false"');
  });
});

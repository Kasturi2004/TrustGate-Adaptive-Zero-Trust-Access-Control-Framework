import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { PolicySettingsContent } from "./PolicySettingsPage";

describe("Policy settings page", () => {
  it("explains the missing configuration API and distinguishes event version labels", () => {
    const markup = renderToStaticMarkup(createElement(PolicySettingsContent, {
      profile: { id: "admin-id", email: "admin@example.test", role: "ADMIN" },
      status: "authenticated",
      onRetry: () => undefined,
    }));

    expect(markup).toContain("Active policy configuration cannot be retrieved");
    expect(markup).toContain("administrator-authorized endpoint");
    expect(markup).toContain("server-side authorization and validation");
    expect(markup).toContain("Policy version labels are investigation-specific");
    expect(markup).toContain("historical context for one decision");
    expect(markup).not.toContain("<input");
    expect(markup).not.toContain("<select");
    expect(markup).not.toContain("Save");
    expect(markup).not.toContain("threshold value");
  });

  it("shows loading until administrator identity is resolved", () => {
    const markup = renderToStaticMarkup(createElement(PolicySettingsContent, {
      profile: null,
      status: "resolving_profile",
      onRetry: () => undefined,
    }));
    expect(markup).toContain('role="status"');
    expect(markup).toContain("Verifying administrator access");
    expect(markup).not.toContain("Active policy configuration");
  });

  it("offers retry after profile verification fails", () => {
    const retry = vi.fn();
    const markup = renderToStaticMarkup(createElement(PolicySettingsContent, {
      profile: null,
      status: "profile_error",
      onRetry: retry,
    }));
    expect(markup).toContain('role="alert"');
    expect(markup).toContain("could not verify the current account");
    expect(markup).toContain("Try again");
    expect(markup).not.toContain("<input");
    expect(retry).not.toHaveBeenCalled();
  });

  it("does not show policy context to a verified non-admin", () => {
    const markup = renderToStaticMarkup(createElement(PolicySettingsContent, {
      profile: { id: "user-id", email: "user@example.test", role: "USER" },
      status: "authenticated",
      onRetry: () => undefined,
    }));
    expect(markup).toContain("Policy settings unavailable");
    expect(markup).not.toContain("investigation-specific");
    expect(markup).not.toContain("Active policy configuration");
  });
});

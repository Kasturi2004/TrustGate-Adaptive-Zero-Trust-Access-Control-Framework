import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { UsersContent } from "./UsersPage";

describe("Users page", () => {
  it("renders only the signed-in profile fields returned by /auth/me", () => {
    const markup = renderToStaticMarkup(createElement(UsersContent, {
      profile: { id: "7e3c0b6a-9a11-4f61-bc25-8183d982aa34", email: "admin@trustgate.test", role: "ADMIN" },
      status: "authenticated",
      onRetry: () => undefined,
    }));

    expect(markup).toContain("Signed-in profile");
    expect(markup).toContain("7e3c0b6a-9a11-4f61-bc25-8183d982aa34");
    expect(markup).toContain("admin@trustgate.test");
    expect(markup).toContain("ADMIN");
    expect(markup).toContain("Organization user directory is not available");
    expect(markup).not.toContain("Active");
    expect(markup).not.toContain("Devices");
  });

  it("shows an explicit unavailable state when the current profile is absent", () => {
    const markup = renderToStaticMarkup(createElement(UsersContent, {
      profile: null,
      status: "unauthenticated",
      onRetry: () => undefined,
    }));
    expect(markup).toContain("User directory unavailable");
    expect(markup).toContain("No authenticated profile is available");
    expect(markup).not.toContain("<table");
  });

  it("hides profile data and offers retry after profile-resolution failure", () => {
    const retry = vi.fn();
    const markup = renderToStaticMarkup(createElement(UsersContent, {
      profile: null,
      status: "profile_error",
      onRetry: retry,
    }));
    expect(markup).toContain('role="alert"');
    expect(markup).toContain("could not verify the current profile");
    expect(markup).toContain("Try again");
    expect(markup).not.toContain("<table");
    expect(retry).not.toHaveBeenCalled();
  });

  it("labels a missing email as not provided instead of inventing one", () => {
    const markup = renderToStaticMarkup(createElement(UsersContent, {
      profile: { id: "profile-id", email: null, role: "USER" },
      status: "authenticated",
      onRetry: () => undefined,
    }));
    expect(markup).toContain("Not provided");
    expect(markup).toContain("USER");
    expect(markup).not.toContain("unknown@example.com");
  });
});

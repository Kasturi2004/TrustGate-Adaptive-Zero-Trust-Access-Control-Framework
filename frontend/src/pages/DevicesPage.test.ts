import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { DevicesContent } from "./DevicesPage";

describe("Devices page", () => {
  it("states the current-browser API scope and organization inventory limitation", () => {
    const markup = renderToStaticMarkup(createElement(DevicesContent, {
      profile: { id: "admin-profile-id", email: "admin@trustgate.test", role: "ADMIN" },
      status: "authenticated",
      onRetry: () => undefined,
    }));

    expect(markup).toContain("Current account · admin-profile-id");
    expect(markup).toContain("X-Device-Token");
    expect(markup).toContain("no supported source for that token");
    expect(markup).toContain("Organization device inventory is not exposed");
    expect(markup).toContain("separately approved backend API with explicit admin authorization");
    expect(markup).not.toContain("Healthy");
    expect(markup).not.toContain("Compliant");
    expect(markup).not.toContain("Operating system");
  });

  it("shows a loading state while account authentication is unresolved", () => {
    const markup = renderToStaticMarkup(createElement(DevicesContent, {
      profile: null,
      status: "resolving_profile",
      onRetry: () => undefined,
    }));
    expect(markup).toContain('role="status"');
    expect(markup).toContain("Verifying your account");
    expect(markup).not.toContain("Organization device inventory");
  });

  it("offers retry when profile verification fails", () => {
    const retry = vi.fn();
    const markup = renderToStaticMarkup(createElement(DevicesContent, {
      profile: null,
      status: "profile_error",
      onRetry: retry,
    }));
    expect(markup).toContain('role="alert"');
    expect(markup).toContain("could not verify the current account");
    expect(markup).toContain("Try again");
    expect(markup).not.toContain("<table");
    expect(retry).not.toHaveBeenCalled();
  });

  it("does not show device data when no verified account is available", () => {
    const markup = renderToStaticMarkup(createElement(DevicesContent, {
      profile: null,
      status: "unauthenticated",
      onRetry: () => undefined,
    }));
    expect(markup).toContain("Device information unavailable");
    expect(markup).not.toContain("<table");
    expect(markup).not.toContain("recognized");
  });
});

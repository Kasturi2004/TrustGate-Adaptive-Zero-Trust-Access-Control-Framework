import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { ProfileVerificationFailure } from "./ProfileVerificationFailure";

describe("profile verification failure state", () => {
  it("offers retry and explicit sign-out when profile resolution fails", () => {
    const markup = renderToStaticMarkup(
      createElement(ProfileVerificationFailure, {
        onRetry: () => undefined,
        onSignOut: async () => undefined,
      }),
    );
    expect(markup).toContain("Administrator access could not be verified");
    expect(markup).toContain("Retry verification");
    expect(markup).toContain("Sign out and return to login");
  });
});

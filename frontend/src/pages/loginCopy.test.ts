import { describe, expect, it } from "vitest";
import { loginFailureMessage, loginVerificationMessage } from "./loginCopy";

describe("login verification message", () => {
  it("explains that identity and role verification happens after sign-in", () => {
    expect(loginVerificationMessage).toContain("After sign-in");
    expect(loginVerificationMessage).toContain("verifies your identity and administrator role");
    expect(loginVerificationMessage).not.toMatch(/^Identity and administrator role verified/);
  });
});

describe("login failure message", () => {
  it("does not expose backend authentication response details", () => {
    expect(loginFailureMessage).toBe(
      "Sign-in failed. Check your credentials and try again.",
    );
    expect(loginFailureMessage).not.toContain("detail");
  });
});

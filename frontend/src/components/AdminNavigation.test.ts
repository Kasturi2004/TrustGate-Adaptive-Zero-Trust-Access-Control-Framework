import type { ReactElement } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

const { useAuthMock, useProfileRoleMock } = vi.hoisted(() => ({
  useAuthMock: vi.fn(),
  useProfileRoleMock: vi.fn(),
}));

vi.mock("../auth/AuthProvider.tsx", () => ({ useAuth: useAuthMock }));
vi.mock("../auth/useProfileRole.ts", () => ({ useProfileRole: useProfileRoleMock }));

import { Header } from "./Header.tsx";
import { HomePage } from "../pages/HomePage.tsx";

function textContent(node: unknown): string[] {
  if (typeof node === "string") return [node];
  if (Array.isArray(node)) return node.flatMap(textContent);
  if (typeof node !== "object" || node === null || !("props" in node)) return [];

  const element = node as ReactElement<{ children?: unknown }>;
  return textContent(element.props.children);
}

afterEach(() => {
  vi.clearAllMocks();
});

describe("admin navigation visibility", () => {
  it("shows admin links for an ADMIN profile", () => {
    useAuthMock.mockReturnValue({ session: {}, user: { id: "user-1" }, loading: false });
    useProfileRoleMock.mockReturnValue({ role: "ADMIN", loading: false });

    expect(textContent(Header())).toContain("Admin");
    expect(textContent(HomePage())).toContain("Security overview");
    expect(textContent(HomePage())).toContain("Security events");
  });

  it("hides admin links for a USER profile", () => {
    useAuthMock.mockReturnValue({ session: {}, user: { id: "user-1" }, loading: false });
    useProfileRoleMock.mockReturnValue({ role: "USER", loading: false });

    expect(textContent(Header())).not.toContain("Admin");
    expect(textContent(HomePage())).not.toContain("Security overview");
    expect(textContent(HomePage())).not.toContain("Security events");
  });
});

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

function links(node: unknown): Array<{ to: string; className: string; text: string }> {
  if (Array.isArray(node)) return node.flatMap(links);
  if (typeof node !== "object" || node === null || !("props" in node)) return [];

  const element = node as ReactElement<{
    children?: unknown;
    to?: string;
    className?: string;
  }>;
  const current =
    typeof element.props.to === "string"
      ? [
          {
            to: element.props.to,
            className: element.props.className ?? "",
            text: textContent(element).join(""),
          },
        ]
      : [];
  return [...current, ...links(element.props.children)];
}

afterEach(() => {
  vi.clearAllMocks();
});

describe("admin navigation visibility", () => {
  it("shows admin links for an ADMIN profile", () => {
    useAuthMock.mockReturnValue({ session: {}, user: { id: "user-1" }, loading: false });
    useProfileRoleMock.mockReturnValue({ role: "ADMIN", loading: false });

    expect(textContent(Header())).toContain("Admin dashboard");
    const page = HomePage();
    const pageLinks = links(page);
    expect(pageLinks).toContainEqual(
      expect.objectContaining({
        to: "/admin/overview",
        className: "dashboard-primary-action",
        text: expect.stringContaining("Admin dashboard"),
      }),
    );
    expect(textContent(page)).toContain(
      "Review security activity and manage protected access requests.",
    );
    expect(pageLinks.map((link) => link.to)).toEqual(
      expect.arrayContaining(["/access", "/history", "/account", "/admin/events"]),
    );
    expect(textContent(page)).toContain("Quick access");
  });

  it("hides admin links for a USER profile", () => {
    useAuthMock.mockReturnValue({ session: {}, user: { id: "user-1" }, loading: false });
    useProfileRoleMock.mockReturnValue({ role: "USER", loading: false });

    const page = HomePage();
    const pageLinks = links(page);
    expect(textContent(Header())).not.toContain("Admin");
    expect(pageLinks.map((link) => link.to)).not.toContain("/admin/overview");
    expect(pageLinks.map((link) => link.to)).not.toContain("/admin/events");
    expect(textContent(page)).not.toContain("Admin dashboard");
    expect(textContent(page)).not.toContain("Security events");
    expect(textContent(Header())).toContain("Access history");
    expect(pageLinks).toContainEqual(
      expect.objectContaining({
        to: "/access",
        className: "dashboard-primary-action",
        text: expect.stringContaining("Request access"),
      }),
    );
    expect(pageLinks.map((link) => link.to)).toEqual(
      expect.arrayContaining(["/access", "/history", "/account"]),
    );
    expect(textContent(page)).toContain("Every access request is evaluated independently");
    expect(textContent(page).join(" ")).toContain("Access checks");
    expect(textContent(page).join(" ")).not.toContain("Backend decisions");
    expect(textContent(page).join(" ")).not.toContain("backend evaluation");
    expect(textContent(page)).toContain("Review your access activity.");
  });

  it("keeps employee navigation available to administrators", () => {
    useAuthMock.mockReturnValue({ session: {}, user: { id: "user-1" }, loading: false });
    useProfileRoleMock.mockReturnValue({ role: "ADMIN", loading: false });

    const navigationLinks = links(Header());
    expect(navigationLinks.map((link) => link.to)).toEqual(
      expect.arrayContaining([
        "/dashboard",
        "/access",
        "/history",
        "/account",
        "/admin/overview",
        "/admin/events",
      ]),
    );
  });
});

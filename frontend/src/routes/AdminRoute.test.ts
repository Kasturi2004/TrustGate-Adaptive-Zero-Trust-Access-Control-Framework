import type { ReactElement, ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

const { useAuthMock, useProfileRoleMock } = vi.hoisted(() => ({
  useAuthMock: vi.fn(),
  useProfileRoleMock: vi.fn(),
}));

vi.mock("../auth/AuthProvider.tsx", () => ({ useAuth: useAuthMock }));
vi.mock("../auth/useProfileRole.ts", () => ({ useProfileRole: useProfileRoleMock }));
vi.mock("react-router-dom", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router-dom")>();
  return {
    ...actual,
    Navigate: function Navigate() {
      return null;
    },
  };
});

import { Navigate } from "react-router-dom";
import { Route } from "react-router-dom";
import { ProtectedRoute } from "../auth/ProtectedRoute.tsx";
import { AdminRoute } from "./AdminRoute.tsx";
import { AppRoutes } from "./AppRoutes.tsx";

const child = "admin content";
interface TestElementProps {
  children?: ReactNode;
  role?: string;
  path?: string;
  element?: TestElement;
}
type TestElement = ReactElement<TestElementProps>;

afterEach(() => {
  vi.clearAllMocks();
});

describe("AdminRoute", () => {
  it("renders admin content for an authenticated database ADMIN profile", () => {
    useAuthMock.mockReturnValue({ session: {}, user: { id: "user-1" }, loading: false });
    useProfileRoleMock.mockReturnValue({ role: "ADMIN", loading: false });

    const element = AdminRoute({ children: child }) as TestElement;

    expect(element.type).toBe(ProtectedRoute);
    expect(element.props.children).toBe(child);
  });

  it("redirects a USER profile away from admin content", () => {
    useAuthMock.mockReturnValue({ session: {}, user: { id: "user-1" }, loading: false });
    useProfileRoleMock.mockReturnValue({ role: "USER", loading: false });

    const element = AdminRoute({ children: child }) as TestElement;

    expect(element.type).toBe(Navigate);
    expect(element.props).toEqual({ to: "/access", replace: true });
    expect(element.props.children).toBeUndefined();
  });

  it("delegates unauthenticated navigation to the existing ProtectedRoute", () => {
    useAuthMock.mockReturnValue({ session: null, user: null, loading: false });
    useProfileRoleMock.mockReturnValue({ role: null, loading: false });

    const element = AdminRoute({ children: child }) as TestElement;

    expect(element.type).toBe(ProtectedRoute);
    expect(element.props.children).toBe(child);
  });

  it("does not render admin content during auth restoration or profile lookup", () => {
    useAuthMock.mockReturnValue({ session: null, user: null, loading: true });
    useProfileRoleMock.mockReturnValue({ role: null, loading: true });

    const authLoading = AdminRoute({ children: child }) as TestElement;
    expect(authLoading.props.role).toBe("status");
    expect(authLoading.props.children).not.toBe(child);

    useAuthMock.mockReturnValue({ session: {}, user: { id: "user-1" }, loading: false });
    useProfileRoleMock.mockReturnValue({ role: null, loading: true });
    const profileLoading = AdminRoute({ children: child }) as TestElement;
    expect(profileLoading.props.role).toBe("status");
    expect(profileLoading.props.children).not.toBe(child);
  });

  it("wraps every existing admin route in AdminRoute", () => {
    const routeElements = (AppRoutes() as TestElement).props.children as TestElement[];
    const adminRoutes = routeElements.filter(
      (route) => typeof route.props.path === "string" && route.props.path.startsWith("/admin/"),
    );

    expect(adminRoutes).toHaveLength(3);
    for (const route of adminRoutes) {
      expect(route.type).toBe(Route);
      expect(route.props.element?.type).toBe(AdminRoute);
    }
  });

  it("protects both access history and access request detail routes", () => {
    const routeElements = (AppRoutes() as TestElement).props.children as TestElement[];
    const historyRoutes = routeElements.filter(
      (route) => typeof route.props.path === "string" && route.props.path.startsWith("/history"),
    );

    expect(historyRoutes.map((route) => route.props.path)).toEqual([
      "/history",
      "/history/:accessRequestId",
    ]);
    for (const route of historyRoutes) {
      expect(route.type).toBe(Route);
      expect(route.props.element?.type).toBe(ProtectedRoute);
    }
  });
});

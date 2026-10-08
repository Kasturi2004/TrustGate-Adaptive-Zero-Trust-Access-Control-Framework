import type { FormEvent } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { hookHarness, apiRequestMock, setSessionMock, navigateMock, locationMock } = vi.hoisted(
  () => ({
    hookHarness: {
      states: [] as unknown[],
      stateCursor: 0,
      refs: [] as Array<{ current: unknown }>,
      refCursor: 0,
    },
    apiRequestMock: vi.fn(),
    setSessionMock: vi.fn(),
    navigateMock: vi.fn(),
    locationMock: vi.fn(),
  }),
);

vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  return {
    ...actual,
    useState: (initialValue: unknown) => {
      const index = hookHarness.stateCursor;
      hookHarness.stateCursor += 1;
      if (!(index in hookHarness.states)) {
        hookHarness.states[index] = initialValue;
      }
      return [
        hookHarness.states[index],
        (nextValue: unknown) => {
          hookHarness.states[index] = nextValue;
        },
      ];
    },
    useRef: (initialValue: unknown) => {
      const index = hookHarness.refCursor;
      hookHarness.refCursor += 1;
      hookHarness.refs[index] ??= { current: initialValue };
      return hookHarness.refs[index];
    },
  } as unknown as typeof actual;
});

vi.mock("../api/client.ts", () => ({ apiRequest: apiRequestMock }));
vi.mock("../lib/supabase.ts", () => ({ supabase: { auth: { setSession: setSessionMock } } }));
vi.mock("react-router-dom", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router-dom")>();
  return {
    ...actual,
    useLocation: locationMock,
    useNavigate: () => navigateMock,
  };
});

import { LoginPage } from "./LoginPage.tsx";
import { AuthPageLayout } from "../components/AuthPageLayout.tsx";

interface UiNode {
  type: unknown;
  props: Record<string, unknown>;
}

function renderLogin(): UiNode {
  hookHarness.stateCursor = 0;
  hookHarness.refCursor = 0;
  return LoginPage() as UiNode;
}

function findNode(node: unknown, predicate: (candidate: UiNode) => boolean): UiNode | undefined {
  if (Array.isArray(node)) {
    for (const child of node) {
      const result = findNode(child, predicate);
      if (result) return result;
    }
    return undefined;
  }
  if (typeof node !== "object" || node === null || !("type" in node) || !("props" in node)) {
    return undefined;
  }

  const candidate = node as UiNode;
  if (predicate(candidate)) return candidate;
  return findNode(candidate.props.children, predicate);
}

function textContent(node: unknown): string {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(textContent).join("");
  if (typeof node !== "object" || node === null || !("props" in node)) return "";
  return textContent((node as UiNode).props.children);
}

function requiredNode(root: UiNode, elementType: string): UiNode {
  const found = findNode(root, (candidate) => candidate.type === elementType);
  if (!found) throw new Error(`Expected ${elementType} in LoginPage`);
  return found;
}

function inputNode(root: UiNode, name: string): UiNode {
  const found = findNode(
    root,
    (candidate) =>
      candidate.type === "input" && (candidate.props.name as string | undefined) === name,
  );
  if (!found) throw new Error(`Expected ${name} input in LoginPage`);
  return found;
}

function changeInput(root: UiNode, name: string, value: string): void {
  const input = inputNode(root, name);
  const onChange = input.props.onChange as (event: { currentTarget: { value: string } }) => void;
  onChange({ currentTarget: { value } });
}

function submitHandler(root: UiNode): (event: FormEvent<HTMLFormElement>) => Promise<void> {
  return requiredNode(root, "form").props.onSubmit as (
    event: FormEvent<HTMLFormElement>,
  ) => Promise<void>;
}

function submitEvent(): FormEvent<HTMLFormElement> {
  return { preventDefault: vi.fn() } as unknown as FormEvent<HTMLFormElement>;
}

function response(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const tokenBody = {
  access_token: "test-access-token",
  refresh_token: "test-refresh-token",
};

beforeEach(() => {
  hookHarness.states = [];
  hookHarness.stateCursor = 0;
  hookHarness.refs = [];
  hookHarness.refCursor = 0;
  apiRequestMock.mockReset();
  setSessionMock.mockReset();
  setSessionMock.mockResolvedValue({ data: { session: null }, error: null });
  navigateMock.mockReset();
  locationMock.mockReturnValue({ state: null });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("LoginPage", () => {
  it("uses the shared Figma-inspired authentication layout and retains signup navigation", () => {
    const root = renderLogin();
    expect(root.type).toBe(AuthPageLayout);
    expect(root.props).toMatchObject({
      eyebrow: "Secure sign in",
      title: "Welcome back",
    });
    expect(findNode(root, (candidate) => candidate.type === "form")).toBeDefined();
    expect(textContent(root.props.footer)).toContain("Don’t have an account?");
  });

  it("renders labeled email and password inputs with autocomplete", () => {
    const root = renderLogin();

    expect(inputNode(root, "email").props).toMatchObject({
      type: "email",
      autoComplete: "username",
    });
    expect(inputNode(root, "password").props).toMatchObject({
      type: "password",
      autoComplete: "current-password",
    });
    expect(requiredNode(root, "button").props.type).toBe("submit");
  });

  it("posts trimmed email, sets the session, and lands on Dashboard by default", async () => {
    apiRequestMock.mockResolvedValue(response(200, tokenBody));
    const root = renderLogin();
    changeInput(root, "email", "  user@example.test  ");
    changeInput(root, "password", " pass word ");

    await submitHandler(renderLogin())(submitEvent());

    expect(apiRequestMock).toHaveBeenCalledWith("/auth/login", {
      method: "POST",
      body: { email: "user@example.test", password: " pass word " },
    });
    expect(setSessionMock).toHaveBeenCalledWith(tokenBody);
    expect(navigateMock).toHaveBeenCalledWith("/dashboard", { replace: true });
  });

  it("returns to a valid protected destination after login", async () => {
    locationMock.mockReturnValue({
      state: { from: { pathname: "/history", search: "?range=week", hash: "#recent" } },
    });
    apiRequestMock.mockResolvedValue(response(200, tokenBody));

    await submitHandler(renderLogin())(submitEvent());

    expect(navigateMock).toHaveBeenCalledWith("/history?range=week#recent", { replace: true });
  });

  it("preserves an access-history detail destination after login", async () => {
    const requestId = "123e4567-e89b-12d3-a456-426614174000";
    locationMock.mockReturnValue({ state: { from: { pathname: `/history/${requestId}` } } });
    apiRequestMock.mockResolvedValue(response(200, tokenBody));

    await submitHandler(renderLogin())(submitEvent());

    expect(navigateMock).toHaveBeenCalledWith(`/history/${requestId}`, { replace: true });
  });

  it("ignores an external return destination", async () => {
    locationMock.mockReturnValue({ state: { from: { pathname: "//attacker.example" } } });
    apiRequestMock.mockResolvedValue(response(200, tokenBody));

    await submitHandler(renderLogin())(submitEvent());

    expect(navigateMock).toHaveBeenCalledWith("/dashboard", { replace: true });
  });

  it.each([
    { pathname: "/dashboard" },
    { pathname: "/login" },
    { pathname: "/unsupported" },
    { pathname: "\\\\attacker.example" },
    { pathname: "/history/not-an-id" },
  ])("uses Dashboard for a non-protected or malformed return destination", async (from) => {
    locationMock.mockReturnValue({ state: { from } });
    apiRequestMock.mockResolvedValue(response(200, tokenBody));

    await submitHandler(renderLogin())(submitEvent());

    expect(navigateMock).toHaveBeenCalledWith("/dashboard", { replace: true });
  });

  it.each([
    [401, "Invalid email or password."],
    [429, "Too many login attempts. Please try again later."],
    [422, "Enter a valid email address and password."],
    [500, "Unable to sign in right now. Please try again."],
  ])("shows a safe message for HTTP %i", async (status, message) => {
    apiRequestMock.mockResolvedValue(response(status, { detail: "private backend detail" }));

    await submitHandler(renderLogin())(submitEvent());

    const alert = findNode(renderLogin(), (candidate) => candidate.props.role === "alert");
    expect(alert?.props.children).toBe(message);
    expect(setSessionMock).not.toHaveBeenCalled();
    expect(navigateMock).not.toHaveBeenCalled();
  });

  it("shows a safe message when the API request fails", async () => {
    apiRequestMock.mockRejectedValue(new Error("private network detail"));

    await submitHandler(renderLogin())(submitEvent());

    expect(
      findNode(renderLogin(), (candidate) => candidate.props.role === "alert")?.props.children,
    ).toBe("Unable to sign in right now. Please try again.");
    expect(setSessionMock).not.toHaveBeenCalled();
  });

  it.each([
    { access_token: "", refresh_token: "test-refresh-token" },
    { access_token: "test-access-token" },
    { access_token: 123, refresh_token: "test-refresh-token" },
  ])("does not establish a session from an invalid token response", async (tokens) => {
    apiRequestMock.mockResolvedValue(response(200, tokens));

    await submitHandler(renderLogin())(submitEvent());

    expect(setSessionMock).not.toHaveBeenCalled();
    expect(navigateMock).not.toHaveBeenCalled();
    expect(
      findNode(renderLogin(), (candidate) => candidate.props.role === "alert")?.props.children,
    ).toBe("Unable to sign in right now. Please try again.");
  });

  it("shows a safe message when Supabase cannot establish the session", async () => {
    apiRequestMock.mockResolvedValue(response(200, tokenBody));
    setSessionMock.mockResolvedValue({ data: { session: null }, error: new Error("private") });

    await submitHandler(renderLogin())(submitEvent());

    expect(navigateMock).not.toHaveBeenCalled();
    expect(
      findNode(renderLogin(), (candidate) => candidate.props.role === "alert")?.props.children,
    ).toBe("Unable to sign in right now. Please try again.");
  });

  it("disables submission while a request is pending and prevents duplicates", async () => {
    let resolveRequest: (value: Response) => void = () => undefined;
    apiRequestMock.mockReturnValue(
      new Promise<Response>((resolve) => {
        resolveRequest = resolve;
      }),
    );
    const firstHandler = submitHandler(renderLogin());
    const firstRequest = firstHandler(submitEvent());
    await firstHandler(submitEvent());

    expect(apiRequestMock).toHaveBeenCalledOnce();
    expect(requiredNode(renderLogin(), "button").props.disabled).toBe(true);

    resolveRequest(response(200, tokenBody));
    await firstRequest;
    expect(requiredNode(renderLogin(), "button").props.disabled).toBe(false);
  });

  it("does not log credentials or tokens", async () => {
    const log = vi.spyOn(console, "log");
    const warn = vi.spyOn(console, "warn");
    const error = vi.spyOn(console, "error");
    apiRequestMock.mockResolvedValue(response(200, tokenBody));
    changeInput(renderLogin(), "email", "user@example.test");
    changeInput(renderLogin(), "password", "test-password");

    await submitHandler(renderLogin())(submitEvent());

    const logs = [log, warn, error].flatMap((spy) => spy.mock.calls.flat());
    for (const sensitiveValue of [
      "user@example.test",
      "test-password",
      ...Object.values(tokenBody),
    ]) {
      expect(logs).not.toContain(sensitiveValue);
    }
  });
});

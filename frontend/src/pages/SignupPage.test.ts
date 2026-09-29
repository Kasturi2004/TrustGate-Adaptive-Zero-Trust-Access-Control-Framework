import type { FormEvent } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { hookHarness, signUpMock, setSessionMock, navigateMock } = vi.hoisted(() => ({
  hookHarness: {
    states: [] as unknown[],
    stateCursor: 0,
    refs: [] as Array<{ current: unknown }>,
    refCursor: 0,
  },
  signUpMock: vi.fn(),
  setSessionMock: vi.fn(),
  navigateMock: vi.fn(),
}));

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

vi.mock("../lib/supabase.ts", () => ({
  supabase: { auth: { signUp: signUpMock, setSession: setSessionMock } },
}));
vi.mock("react-router-dom", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router-dom")>();
  return { ...actual, useNavigate: () => navigateMock };
});

import { SignupPage } from "./SignupPage.tsx";

interface UiNode {
  type: unknown;
  props: Record<string, unknown>;
}

function renderSignup(): UiNode {
  hookHarness.stateCursor = 0;
  hookHarness.refCursor = 0;
  return SignupPage() as UiNode;
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

function requiredNode(root: UiNode, elementType: string): UiNode {
  const found = findNode(root, (candidate) => candidate.type === elementType);
  if (!found) throw new Error(`Expected ${elementType} in SignupPage`);
  return found;
}

function inputNode(root: UiNode, name: string): UiNode {
  const found = findNode(
    root,
    (candidate) =>
      candidate.type === "input" && (candidate.props.name as string | undefined) === name,
  );
  if (!found) throw new Error(`Expected ${name} input in SignupPage`);
  return found;
}

function changeInput(root: UiNode, name: string, value: string): void {
  const onChange = inputNode(root, name).props.onChange as (event: {
    currentTarget: { value: string };
  }) => void;
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

function fillForm(email = "user@example.test", password = "test-password"): UiNode {
  const root = renderSignup();
  changeInput(root, "email", email);
  changeInput(root, "password", password);
  changeInput(root, "confirmPassword", password);
  return renderSignup();
}

const session = {
  access_token: "test-session-access-token",
  refresh_token: "test-session-refresh-token",
  user: { id: "test-user" },
};

beforeEach(() => {
  hookHarness.states = [];
  hookHarness.stateCursor = 0;
  hookHarness.refs = [];
  hookHarness.refCursor = 0;
  signUpMock.mockReset();
  setSessionMock.mockReset();
  navigateMock.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("SignupPage", () => {
  it("renders labeled email, password, and confirmation fields", () => {
    const root = renderSignup();

    expect(inputNode(root, "email").props).toMatchObject({
      type: "email",
      autoComplete: "email",
      required: true,
    });
    expect(inputNode(root, "password").props).toMatchObject({
      type: "password",
      autoComplete: "new-password",
      required: true,
    });
    expect(inputNode(root, "confirmPassword").props).toMatchObject({
      type: "password",
      autoComplete: "new-password",
      required: true,
    });
    expect(requiredNode(root, "button").props.type).toBe("submit");
  });

  it("trims email and sends only the unchanged password to Supabase", async () => {
    signUpMock.mockResolvedValue({ data: { session }, error: null });
    const root = fillForm("  user@example.test  ", " pass word ");

    await submitHandler(root)(submitEvent());

    expect(signUpMock).toHaveBeenCalledWith({
      email: "user@example.test",
      password: " pass word ",
    });
    expect(signUpMock.mock.calls[0]?.[0]).not.toHaveProperty("confirmPassword");
    expect(setSessionMock).not.toHaveBeenCalled();
    expect(navigateMock).toHaveBeenCalledWith("/access", { replace: true });
  });

  it("reports confirmation instructions when signup succeeds without a session", async () => {
    signUpMock.mockResolvedValue({ data: { session: null, user: null }, error: null });
    const root = fillForm();

    await submitHandler(root)(submitEvent());

    expect(
      findNode(renderSignup(), (candidate) => candidate.props.role === "status")?.props.children,
    ).toBe("Signup submitted. Check your email for a verification link before signing in.");
    expect(setSessionMock).not.toHaveBeenCalled();
    expect(navigateMock).not.toHaveBeenCalled();
  });

  it("does not submit when passwords do not match", async () => {
    const root = renderSignup();
    changeInput(root, "email", "user@example.test");
    changeInput(root, "password", "first-password");
    changeInput(root, "confirmPassword", "different-password");

    await submitHandler(renderSignup())(submitEvent());

    expect(signUpMock).not.toHaveBeenCalled();
    expect(
      findNode(renderSignup(), (candidate) => candidate.props.role === "alert")?.props.children,
    ).toBe("Passwords do not match.");
  });

  it.each([
    ["", "password", "password", "Enter your email address."],
    ["user@example.test", "", "", "Enter a password."],
    ["user@example.test", "password", "", "Confirm your password."],
  ])("validates required fields before signup", async (email, password, confirm, message) => {
    const root = renderSignup();
    changeInput(root, "email", email);
    changeInput(root, "password", password);
    changeInput(root, "confirmPassword", confirm);

    await submitHandler(renderSignup())(submitEvent());

    expect(signUpMock).not.toHaveBeenCalled();
    expect(
      findNode(renderSignup(), (candidate) => candidate.props.role === "alert")?.props.children,
    ).toBe(message);
  });

  it("shows a safe message when Supabase reports an error", async () => {
    signUpMock.mockResolvedValue({
      data: { session: null, user: null },
      error: new Error("private email-exists and backend details"),
    });

    await submitHandler(fillForm())(submitEvent());

    const alert = findNode(renderSignup(), (candidate) => candidate.props.role === "alert");
    expect(alert?.props.children).toBe(
      "Unable to create your account right now. Please try again.",
    );
    expect(String(alert?.props.children)).not.toContain("private");
    expect(navigateMock).not.toHaveBeenCalled();
  });

  it("prevents duplicate submissions while signup is pending", async () => {
    let resolveSignup: (value: unknown) => void = () => undefined;
    signUpMock.mockReturnValue(
      new Promise((resolve) => {
        resolveSignup = resolve;
      }),
    );
    const root = fillForm();
    const handler = submitHandler(root);
    const firstRequest = handler(submitEvent());
    await handler(submitEvent());

    expect(signUpMock).toHaveBeenCalledOnce();
    expect(requiredNode(renderSignup(), "button").props.disabled).toBe(true);

    resolveSignup({ data: { session: null, user: null }, error: null });
    await firstRequest;
    expect(requiredNode(renderSignup(), "button").props.disabled).toBe(false);
  });

  it("does not log credentials or returned session tokens", async () => {
    const log = vi.spyOn(console, "log");
    const warn = vi.spyOn(console, "warn");
    const error = vi.spyOn(console, "error");
    signUpMock.mockResolvedValue({ data: { session }, error: null });

    await submitHandler(fillForm("user@example.test", "test-password"))(submitEvent());

    const logs = [log, warn, error].flatMap((spy) => spy.mock.calls.flat());
    for (const sensitiveValue of [
      "user@example.test",
      "test-password",
      session.access_token,
      session.refresh_token,
    ]) {
      expect(logs).not.toContain(sensitiveValue);
    }
  });
});

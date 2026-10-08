import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const {
  hookHarness,
  startEnrollmentMock,
  verifyEnrollmentMock,
  fetchDeviceRecognitionMock,
  forgetDeviceMock,
} = vi.hoisted(() => ({
  hookHarness: {
    states: [] as unknown[],
    cursor: 0,
    refs: [] as Array<{ current: unknown }>,
    refCursor: 0,
    effect: null as (() => unknown) | null,
  },
  startEnrollmentMock: vi.fn(),
  verifyEnrollmentMock: vi.fn(),
  fetchDeviceRecognitionMock: vi.fn(),
  forgetDeviceMock: vi.fn(),
}));

vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  return {
    ...actual,
    useState: (initialValue: unknown) => {
      const index = hookHarness.cursor++;
      if (!(index in hookHarness.states)) hookHarness.states[index] = initialValue;
      return [hookHarness.states[index], (value: unknown) => (hookHarness.states[index] = value)];
    },
    useRef: (initialValue: unknown) => {
      const index = hookHarness.refCursor++;
      if (!(index in hookHarness.refs)) hookHarness.refs[index] = { current: initialValue };
      return hookHarness.refs[index];
    },
    useEffect: (effect: () => unknown) => {
      hookHarness.effect = effect;
    },
  } as unknown as typeof actual;
});

vi.mock("../api/mfaEnrollment.ts", () => ({
  MfaEnrollmentApiError: class MfaEnrollmentApiError extends Error {
    readonly status: number;

    constructor(status: number) {
      super("request failed");
      this.status = status;
    }
  },
  startTotpEnrollment: startEnrollmentMock,
  verifyTotpEnrollment: verifyEnrollmentMock,
}));
vi.mock("../api/deviceRecognition.ts", () => ({
  fetchCurrentDeviceRecognition: fetchDeviceRecognitionMock,
  forgetCurrentDevice: forgetDeviceMock,
}));

import { ProtectedRoute } from "../auth/ProtectedRoute.tsx";
import { AppRoutes } from "../routes/AppRoutes.tsx";
import { AccountPage } from "./AccountPage.tsx";

interface UiNode {
  type: unknown;
  props: Record<string, unknown>;
}

const setupMaterial = {
  otpauth_uri: "otpauth://totp/TrustGate:user%40example.test?secret=PRIVATE-SECRET",
  manual_entry_key: "PRIVATE-MANUAL-KEY",
};

function renderPage(): UiNode {
  hookHarness.cursor = 0;
  hookHarness.refCursor = 0;
  return AccountPage() as UiNode;
}

function findNode(node: unknown, predicate: (candidate: UiNode) => boolean): UiNode | undefined {
  if (Array.isArray(node)) {
    for (const child of node) {
      const found = findNode(child, predicate);
      if (found) return found;
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

function nodeText(node: unknown): string {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(nodeText).join("");
  if (typeof node !== "object" || node === null || !("props" in node)) return "";
  return nodeText((node as UiNode).props.children);
}

function buttonWithText(root: UiNode, text: string): UiNode {
  const button = findNode(
    root,
    (candidate) => candidate.type === "button" && nodeText(candidate).includes(text),
  );
  if (!button) throw new Error(`Missing button: ${text}`);
  return button;
}

function response(): Promise<{ enrollment_status: "verified"; verified_at: string }> {
  return Promise.resolve({ enrollment_status: "verified", verified_at: "2026-10-08T10:00:00Z" });
}

beforeEach(() => {
  hookHarness.states = [];
  hookHarness.cursor = 0;
  hookHarness.refs = [];
  hookHarness.refCursor = 0;
  hookHarness.effect = null;
  startEnrollmentMock.mockReset();
  verifyEnrollmentMock.mockReset();
  fetchDeviceRecognitionMock.mockReset();
  forgetDeviceMock.mockReset();
});

afterEach(() => vi.restoreAllMocks());

describe("AccountPage authenticator enrollment", () => {
  it("renders on the existing protected /account route", () => {
    const routes = (AppRoutes() as UiNode).props.children as UiNode[];
    const accountRoute = routes.find((route) => route.props.path === "/account");
    expect(accountRoute).toBeDefined();
    const wrapper = accountRoute?.props.element as UiNode;
    expect(wrapper.type).toBe(ProtectedRoute);
    expect((wrapper.props.children as UiNode).type).toBe(AccountPage);
    expect(nodeText(renderPage())).toContain("Authenticator");
    expect(nodeText(renderPage())).toContain(
      "Set up and manage the authenticator used when TrustGate requires additional verification.",
    );
    expect(nodeText(renderPage())).not.toContain("TOTP");
    expect(nodeText(renderPage())).toContain("Set up Authenticator");
  });

  it("starts enrollment and displays the returned manual key without displaying the URI", async () => {
    startEnrollmentMock.mockResolvedValue(setupMaterial);
    const root = renderPage();

    await (buttonWithText(root, "Set up Authenticator").props.onClick as () => Promise<void>)();

    const configured = renderPage();
    expect(startEnrollmentMock).toHaveBeenCalledOnce();
    expect(nodeText(configured)).toContain("PRIVATE-MANUAL-KEY");
    expect(nodeText(configured)).not.toContain("PRIVATE-SECRET");
    expect(nodeText(configured)).toContain("Open your authenticator application");
  });

  it("filters non-digits, verifies the six-digit code, then clears code and setup material", async () => {
    startEnrollmentMock.mockResolvedValue(setupMaterial);
    verifyEnrollmentMock.mockResolvedValue(await response());
    await (
      buttonWithText(renderPage(), "Set up Authenticator").props.onClick as () => Promise<void>
    )();

    let configured = renderPage();
    const input = findNode(configured, (candidate) => candidate.type === "input");
    expect(input).toBeDefined();
    (input?.props.onChange as (event: { currentTarget: { value: string } }) => void)({
      currentTarget: { value: "01a23456" },
    });
    configured = renderPage();
    const filteredInput = findNode(configured, (candidate) => candidate.type === "input");
    expect(filteredInput?.props.value).toBe("012345");

    const form = findNode(configured, (candidate) => candidate.type === "form");
    await (form?.props.onSubmit as (event: { preventDefault: () => void }) => Promise<void>)({
      preventDefault: vi.fn(),
    });

    const success = renderPage();
    expect(verifyEnrollmentMock).toHaveBeenCalledWith("012345");
    expect(nodeText(success)).toContain("Authenticator set up successfully.");
    expect(nodeText(success)).toContain("additional verification");
    expect(nodeText(success)).not.toContain("PRIVATE-MANUAL-KEY");
    expect(hookHarness.states[1]).toBeNull();
    expect(hookHarness.states[2]).toBe("");
    const accessLink = findNode(success, (candidate) => candidate.props.to === "/access");
    expect(accessLink).toBeDefined();
  });

  it("shows a safe start error and permits retry", async () => {
    startEnrollmentMock.mockRejectedValueOnce(new Error("private backend detail"));
    await (
      buttonWithText(renderPage(), "Set up Authenticator").props.onClick as () => Promise<void>
    )();

    const page = renderPage();
    expect(nodeText(page)).toContain("We couldn't start authenticator setup.");
    expect(nodeText(page)).not.toContain("private backend detail");
    expect(nodeText(page)).toContain("Set up Authenticator");
  });

  it("clears the code and shows a safe verification error on failure", async () => {
    startEnrollmentMock.mockResolvedValue(setupMaterial);
    verifyEnrollmentMock.mockRejectedValue(new Error("private backend detail"));
    await (
      buttonWithText(renderPage(), "Set up Authenticator").props.onClick as () => Promise<void>
    )();

    let page = renderPage();
    const input = findNode(page, (candidate) => candidate.type === "input");
    (input?.props.onChange as (event: { currentTarget: { value: string } }) => void)({
      currentTarget: { value: "123456" },
    });
    page = renderPage();
    const form = findNode(page, (candidate) => candidate.type === "form");
    await (form?.props.onSubmit as (event: { preventDefault: () => void }) => Promise<void>)({
      preventDefault: vi.fn(),
    });

    page = renderPage();
    expect(nodeText(page)).toContain("We couldn't verify the authenticator code.");
    expect(nodeText(page)).not.toContain("private backend detail");
    expect(nodeText(page)).not.toContain("123456");
    expect(hookHarness.states[2]).toBe("");
    expect(nodeText(page)).toContain("PRIVATE-MANUAL-KEY");
  });

  it("prevents duplicate enrollment-start submissions while pending", async () => {
    let resolveStart!: (value: typeof setupMaterial) => void;
    startEnrollmentMock.mockReturnValueOnce(
      new Promise<typeof setupMaterial>((resolve) => (resolveStart = resolve)),
    );
    const click = buttonWithText(renderPage(), "Set up Authenticator").props
      .onClick as () => Promise<void>;
    const pending = click();
    await click();
    expect(startEnrollmentMock).toHaveBeenCalledOnce();
    expect(buttonWithText(renderPage(), "Preparing setup").props.disabled).toBe(true);
    resolveStart(setupMaterial);
    await pending;
  });
});

describe("AccountPage device recognition", () => {
  it("shows a safe current-device status and supports forgetting recognition", async () => {
    fetchDeviceRecognitionMock.mockResolvedValue({ recognized: true });
    forgetDeviceMock.mockResolvedValue({ recognized: false });
    renderPage();
    const cleanup = hookHarness.effect?.() as (() => void) | undefined;
    await vi.waitFor(() => expect(hookHarness.states[4]).toBe("recognized"));

    let page = renderPage();
    expect(nodeText(page)).toContain("This device is recognized for your account.");
    expect(nodeText(page)).toContain("Recognition is a familiarity signal");
    expect(nodeText(page)).not.toContain("device_hash");
    expect(nodeText(page)).not.toContain("device-id");
    const forget = buttonWithText(page, "Forget this device");
    await (forget.props.onClick as () => Promise<void>)();

    page = renderPage();
    expect(forgetDeviceMock).toHaveBeenCalledOnce();
    expect(nodeText(page)).toContain("This device is not recognized.");
    cleanup?.();
  });

  it("renders an unrecognized state and hides revocation when status is false", async () => {
    fetchDeviceRecognitionMock.mockResolvedValue({ recognized: false });
    renderPage();
    const cleanup = hookHarness.effect?.() as (() => void) | undefined;
    await vi.waitFor(() => expect(hookHarness.states[4]).toBe("unrecognized"));

    const page = renderPage();
    expect(nodeText(page)).toContain("This device is not recognized.");
    expect(findNode(page, (candidate) => nodeText(candidate).includes("Forget this device"))).toBe(
      undefined,
    );
    cleanup?.();
  });
});

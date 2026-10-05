import { afterEach, beforeEach, describe, expect, expectTypeOf, it, vi } from "vitest";
import type { ComponentProps } from "react";

const { hookHarness, apiRequestMock, uuidMock } = vi.hoisted(() => ({
  hookHarness: {
    states: [] as unknown[],
    cursor: 0,
    refs: [] as Array<{ current: unknown }>,
    refCursor: 0,
  },
  apiRequestMock: vi.fn(),
  uuidMock: vi.fn(),
}));

vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  return {
    ...actual,
    useState: (initialValue: unknown) => {
      const index = hookHarness.cursor;
      hookHarness.cursor += 1;
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
      if (!(index in hookHarness.refs)) {
        hookHarness.refs[index] = { current: initialValue };
      }
      return hookHarness.refs[index];
    },
  } as unknown as typeof actual;
});

vi.mock("../api/client.ts", () => ({ apiRequest: apiRequestMock }));

import { Link, Route } from "react-router-dom";
import { ProtectedRoute } from "../auth/ProtectedRoute.tsx";
import { DecisionPresentation } from "../components/DecisionPresentation.tsx";
import type { ApiRequestOptions } from "../api/client.ts";
import { AppRoutes } from "../routes/AppRoutes.tsx";
import type { AccessDecision, AccessEvaluationResponse } from "../types/access.ts";
import { RequestAccessPage } from "./RequestAccessPage.tsx";

interface UiNode {
  type: unknown;
  props: Record<string, unknown>;
}

const DEVICE_TOKEN = "phase5-demo-test-uuid";
const MFA_CHALLENGE_ID = "9a535c87-0d62-4a3e-a090-e8862392224a";
const PRIVATE_ERROR = "secret-token private stack trace";

function renderPage(): UiNode {
  hookHarness.cursor = 0;
  hookHarness.refCursor = 0;
  return expandDecisionPresentation(RequestAccessPage()) as UiNode;
}

function expandDecisionPresentation(node: unknown): unknown {
  if (Array.isArray(node)) return node.map(expandDecisionPresentation);
  if (typeof node !== "object" || node === null || !("type" in node) || !("props" in node)) {
    return node;
  }
  const candidate = node as UiNode;
  if (candidate.type === DecisionPresentation) {
    return expandDecisionPresentation(
      DecisionPresentation(candidate.props as ComponentProps<typeof DecisionPresentation>),
    );
  }
  return {
    ...candidate,
    props: { ...candidate.props, children: expandDecisionPresentation(candidate.props.children) },
  };
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

function nodeText(node: unknown): string {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(nodeText).join("");
  if (typeof node !== "object" || node === null || !("props" in node)) return "";
  return nodeText((node as UiNode).props.children);
}

function requiredNode(root: UiNode, elementType: string): UiNode {
  const found = findNode(root, (candidate) => candidate.type === elementType);
  if (!found) throw new Error(`Expected ${elementType} in RequestAccessPage`);
  return found;
}

function clickRequest(root: UiNode): Promise<void> {
  const button = findNode(
    root,
    (candidate) => candidate.type === "button" && candidate.props.type === "button",
  );
  if (!button) throw new Error("Expected Request Access action");
  return (button.props.onClick as () => Promise<void>)();
}

function enterTotpCode(root: UiNode, code: string): void {
  const input = requiredNode(root, "input");
  (input.props.onChange as (event: { currentTarget: { value: string } }) => void)({
    currentTarget: { value: code },
  });
}

function submitTotp(root: UiNode): Promise<void> {
  const form = requiredNode(root, "form");
  return (form.props.onSubmit as (event: { preventDefault: () => void }) => Promise<void>)({
    preventDefault: vi.fn(),
  });
}

function verificationResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status });
}

function responseFor(
  decision: AccessDecision,
  overrides: Partial<AccessEvaluationResponse> = {},
): Response {
  return new Response(
    JSON.stringify({
      evaluation_id: "evaluation-test-id",
      decision,
      explanation:
        decision === "ALLOW"
          ? "Access is approved."
          : decision === "STEP_UP"
            ? "Additional verification is required to continue."
            : "Access is not approved.",
      mfa_challenge_id: null,
      trust_score: 87,
      policy_threshold: 80,
      policy_weights: { device: 0.4 },
      policy_version_id: "private-policy-id",
      decision_reason: "private-decision-reason",
      exception_details: "private-exception-details",
      raw_context_signals: {
        device_token: "private-device-token",
        user_agent: "private-user-agent",
      },
      factor_calculations: { identity: 0.95 },
      ...overrides,
    }),
    { status: 200 },
  );
}

beforeEach(() => {
  hookHarness.states = [];
  hookHarness.cursor = 0;
  hookHarness.refs = [];
  hookHarness.refCursor = 0;
  apiRequestMock.mockReset();
  uuidMock.mockReset().mockReturnValue(DEVICE_TOKEN);
  vi.stubGlobal("crypto", { randomUUID: uuidMock });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("RequestAccessPage", () => {
  it("keeps the backend decision contract free of prototype-only values", () => {
    expectTypeOf<AccessDecision>().toEqualTypeOf<"ALLOW" | "STEP_UP" | "BLOCK">();
  });

  it("renders the placeholder resource action and remains behind ProtectedRoute", () => {
    const page = renderPage();
    expect(
      findNode(page, (candidate) => candidate.props.className === "request-page"),
    ).toBeDefined();
    expect(
      findNode(page, (candidate) => candidate.props.className === "request-layout"),
    ).toBeDefined();
    expect(nodeText(page)).toContain("Operations Dashboard");
    expect(nodeText(page)).toContain("ops-dashboard");
    expect(nodeText(page)).toContain("Request Access");

    const routes = (AppRoutes() as UiNode).props.children as UiNode[];
    const accessRoute = routes.find((route) => route.props.path === "/access");
    expect(accessRoute?.type).toBe(Route);
    const protectedElement = accessRoute?.props.element as UiNode | undefined;
    expect(protectedElement?.type).toBe(ProtectedRoute);
    const requestPage = protectedElement?.props.children as UiNode | undefined;
    expect(requestPage?.type).toBe(RequestAccessPage);
  });

  it("posts the resource ID and demo device token through the authenticated API client", async () => {
    apiRequestMock.mockResolvedValue(responseFor("BLOCK"));

    await clickRequest(renderPage());

    expect(apiRequestMock).toHaveBeenCalledOnce();
    const [path, options] = apiRequestMock.mock.calls[0] as [string, ApiRequestOptions];
    expect(path).toBe("/access/evaluate");
    expect(options.method).toBe("POST");
    expect(options.body).toEqual({ resource_id: "ops-dashboard" });
    expect(options.headers).toEqual({ "X-Device-Token": `phase5-demo-${DEVICE_TOKEN}` });
    expect(uuidMock).toHaveBeenCalledOnce();
    expect(nodeText(renderPage())).not.toContain(DEVICE_TOKEN);
  });

  it.each([
    ["ALLOW", "Access granted", "Access is approved.", "decision-allow"],
    [
      "STEP_UP",
      "Additional verification required",
      "Additional verification is required to continue.",
      "decision-step",
    ],
    ["BLOCK", "Access denied", "Access is not approved.", "decision-block"],
  ] as const)(
    "renders the backend %s decision without recalculating it",
    async (decision, label, explanation, tone) => {
      apiRequestMock.mockResolvedValue(
        responseFor(decision, {
          mfa_challenge_id: decision === "STEP_UP" ? MFA_CHALLENGE_ID : null,
        }),
      );

      await clickRequest(renderPage());

      const result = renderPage();
      expect(nodeText(result)).toContain(label);
      if (decision === "ALLOW") expect(nodeText(result)).toContain("Your request was approved.");
      if (decision === "STEP_UP") {
        expect(nodeText(result)).toContain("Additional verification is required to continue.");
      }
      if (decision === "BLOCK") {
        expect(nodeText(result)).toContain("Access is not approved.");
        expect(findNode(result, (candidate) => candidate.type === Link)?.props.to).toBe(
          "/dashboard",
        );
      }
      expect(nodeText(result)).toContain(explanation);
      const presentation = findNode(result, (candidate) =>
        String(candidate.props.className ?? "").includes("decision-presentation"),
      );
      expect(presentation?.props.className).toContain(tone);
      expect(nodeText(result)).not.toContain("evaluation-test-id");
      if (decision !== "STEP_UP") {
        expect(findNode(result, (candidate) => candidate.type === "form")).toBeUndefined();
        expect(findNode(result, (candidate) => candidate.type === "input")).toBeUndefined();
      }
      if (decision === "STEP_UP") {
        expect(nodeText(result)).toContain("Verify with your authenticator");
        expect(nodeText(result)).not.toContain(MFA_CHALLENGE_ID);
      }
      expect(nodeText(result)).not.toMatch(
        /trust score|threshold|weight|policy id|private-policy-id|decision_reason|private-decision-reason|exception|private-exception-details|private-device-token|private-user-agent|factor calculation|challenge-private-id/i,
      );
    },
  );

  it("renders a labeled six-digit text input for STEP_UP with a challenge ID", async () => {
    apiRequestMock.mockResolvedValue(
      responseFor("STEP_UP", { mfa_challenge_id: MFA_CHALLENGE_ID }),
    );

    await clickRequest(renderPage());

    const page = renderPage();
    const input = requiredNode(page, "input");
    expect(nodeText(page)).toContain("Enter the six-digit code from your authenticator app");
    expect(findNode(page, (candidate) => candidate.type === "label")?.props.htmlFor).toBe(
      "totp-code",
    );
    expect(input.props.id).toBe("totp-code");
    expect(input.props.type).toBe("text");
    expect(input.props.inputMode).toBe("numeric");
    expect(input.props.autoComplete).toBe("one-time-code");
    expect(input.props.maxLength).toBe(6);
    expect(input.props.pattern).toBe("[0-9]{6}");
    expect(nodeText(page)).toContain("Verify code");
    expect(nodeText(page)).not.toContain(MFA_CHALLENGE_ID);
  });

  it("does not render TOTP verification controls for STEP_UP without a challenge ID", async () => {
    apiRequestMock.mockResolvedValue(responseFor("STEP_UP", { mfa_challenge_id: null }));

    await clickRequest(renderPage());

    const page = renderPage();
    expect(findNode(page, (candidate) => candidate.type === "form")).toBeUndefined();
    expect(findNode(page, (candidate) => candidate.type === "input")).toBeUndefined();
    expect(nodeText(page)).not.toContain("Verify with authenticator");
    expect(nodeText(page)).not.toContain("Verify code");
    expect(nodeText(page)).not.toContain("Access Granted");
    expect(apiRequestMock).toHaveBeenCalledOnce();
    expect(apiRequestMock.mock.calls[0]?.[0]).toBe("/access/evaluate");
  });

  it("rejects a code with a non-digit locally and does not call an MFA API", async () => {
    apiRequestMock.mockResolvedValue(
      responseFor("STEP_UP", { mfa_challenge_id: MFA_CHALLENGE_ID }),
    );

    await clickRequest(renderPage());
    enterTotpCode(renderPage(), "12a456");
    submitTotp(renderPage());

    const page = renderPage();
    expect(findNode(page, (candidate) => candidate.props.role === "alert")).toBeDefined();
    expect(nodeText(page)).toContain("Enter a six-digit authenticator code.");
    expect(apiRequestMock).toHaveBeenCalledOnce();
    expect(apiRequestMock.mock.calls[0]?.[0]).toBe("/access/evaluate");
  });

  it("preserves and submits leading zeroes through the authenticated API client", async () => {
    apiRequestMock
      .mockResolvedValueOnce(responseFor("STEP_UP", { mfa_challenge_id: MFA_CHALLENGE_ID }))
      .mockResolvedValueOnce(
        verificationResponse(200, {
          verification_status: "verified",
          verified_at: "2026-10-05T12:00:00Z",
        }),
      );

    await clickRequest(renderPage());
    enterTotpCode(renderPage(), "012345");

    const input = requiredNode(renderPage(), "input");
    expect(input.props.value).toBe("012345");
    expect(input.props.type).toBe("text");
    await submitTotp(renderPage());

    const page = renderPage();
    expect(nodeText(page)).toContain("Access Granted");
    expect(nodeText(page)).toContain(
      "Your authenticator was verified and access has been approved.",
    );
    expect(nodeText(page)).not.toContain("012345");
    expect(apiRequestMock).toHaveBeenCalledTimes(2);
    expect(apiRequestMock.mock.calls[0]?.[0]).toBe("/access/evaluate");
    expect(apiRequestMock.mock.calls[1]?.[0]).toBe("/auth/mfa/totp/step-up/verify");
    const verificationOptions = apiRequestMock.mock.calls[1]?.[1] as ApiRequestOptions;
    expect(verificationOptions.method).toBe("POST");
    expect(verificationOptions.body).toEqual({
      mfa_challenge_id: MFA_CHALLENGE_ID,
      code: "012345",
    });
    expect(String(apiRequestMock.mock.calls[1]?.[0])).not.toContain(MFA_CHALLENGE_ID);
    expect(nodeText(page)).toContain("MFA VERIFIED");
    expect(nodeText(page)).not.toContain(MFA_CHALLENGE_ID);
    expect(nodeText(page)).not.toContain("evaluation-test-id");
    expect(hookHarness.states[2]).toMatchObject({ decision: "STEP_UP" });
    expect(apiRequestMock.mock.calls.filter(([path]) => path === "/access/evaluate")).toHaveLength(
      1,
    );
  });

  it("prevents duplicate form submissions, including repeated Enter, while pending", async () => {
    let resolveVerification!: (response: Response) => void;
    apiRequestMock
      .mockResolvedValueOnce(responseFor("STEP_UP", { mfa_challenge_id: MFA_CHALLENGE_ID }))
      .mockReturnValueOnce(
        new Promise<Response>((resolve) => {
          resolveVerification = resolve;
        }),
      );

    await clickRequest(renderPage());
    enterTotpCode(renderPage(), "123456");
    const pending = submitTotp(renderPage());

    const pendingPage = renderPage();
    const verifyButton = findNode(
      pendingPage,
      (candidate) => candidate.type === "button" && candidate.props.type === "submit",
    );
    expect(requiredNode(pendingPage, "input").props.disabled).toBe(true);
    expect(verifyButton?.props.disabled).toBe(true);
    expect(nodeText(verifyButton)).toContain("Verifying");
    await submitTotp(pendingPage);
    expect(apiRequestMock).toHaveBeenCalledTimes(2);
    expect(apiRequestMock.mock.calls[1]?.[0]).toBe("/auth/mfa/totp/step-up/verify");

    resolveVerification(
      verificationResponse(200, {
        verification_status: "verified",
        verified_at: "2026-10-05T12:00:00Z",
      }),
    );
    await pending;
  });

  it("shows a generic error and clears the code after a non-success response", async () => {
    apiRequestMock
      .mockResolvedValueOnce(responseFor("STEP_UP", { mfa_challenge_id: MFA_CHALLENGE_ID }))
      .mockResolvedValueOnce(verificationResponse(400, { detail: "private backend detail" }));

    await clickRequest(renderPage());
    enterTotpCode(renderPage(), "123456");
    await submitTotp(renderPage());

    const page = renderPage();
    expect(nodeText(page)).toContain("Verification could not be completed. Please try again.");
    expect(nodeText(page)).toContain("Verify code");
    expect(nodeText(page)).not.toContain("Access Granted");
    expect(nodeText(page)).not.toContain("private backend detail");
    expect(nodeText(page)).not.toContain("123456");
    expect(apiRequestMock.mock.calls[1]?.[1]).toMatchObject({
      method: "POST",
      body: { mfa_challenge_id: MFA_CHALLENGE_ID, code: "123456" },
    });

    enterTotpCode(page, "654321");
    const retryPage = renderPage();
    expect(requiredNode(retryPage, "input").props.value).toBe("654321");
    expect(nodeText(retryPage)).not.toContain("Verification could not be completed.");
  });

  it("treats an unexpected 2xx response as a generic verification failure", async () => {
    apiRequestMock
      .mockResolvedValueOnce(responseFor("STEP_UP", { mfa_challenge_id: MFA_CHALLENGE_ID }))
      .mockResolvedValueOnce(verificationResponse(200, { verification_status: "pending" }));

    await clickRequest(renderPage());
    enterTotpCode(renderPage(), "123456");
    await submitTotp(renderPage());

    const page = renderPage();
    expect(nodeText(page)).toContain("Verification could not be completed. Please try again.");
    expect(nodeText(page)).not.toContain("Access Granted");
    expect(nodeText(page)).not.toContain("pending");
    expect(nodeText(page)).not.toContain("123456");
  });

  it("shows a generic error after a verification network failure", async () => {
    apiRequestMock
      .mockResolvedValueOnce(responseFor("STEP_UP", { mfa_challenge_id: MFA_CHALLENGE_ID }))
      .mockRejectedValueOnce(new Error(PRIVATE_ERROR));

    await clickRequest(renderPage());
    enterTotpCode(renderPage(), "123456");
    await submitTotp(renderPage());

    const page = renderPage();
    expect(nodeText(page)).toContain("Verification could not be completed. Please try again.");
    expect(nodeText(page)).not.toContain("Access Granted");
    expect(nodeText(page)).not.toContain(PRIVATE_ERROR);
    expect(nodeText(page)).not.toContain("123456");
    expect(requiredNode(page, "input").props.disabled).toBe(false);
  });

  it("clears MFA success when a new access request receives a new STEP_UP challenge", async () => {
    apiRequestMock
      .mockResolvedValueOnce(responseFor("STEP_UP", { mfa_challenge_id: MFA_CHALLENGE_ID }))
      .mockResolvedValueOnce(
        verificationResponse(200, {
          verification_status: "verified",
          verified_at: "2026-10-05T12:00:00Z",
        }),
      )
      .mockResolvedValueOnce(
        responseFor("STEP_UP", {
          mfa_challenge_id: "4bb41d2a-fcc0-48cd-a48d-0fa7342dc087",
        }),
      );

    await clickRequest(renderPage());
    enterTotpCode(renderPage(), "123456");
    await submitTotp(renderPage());
    expect(nodeText(renderPage())).toContain("Access Granted");

    await clickRequest(renderPage());

    const page = renderPage();
    expect(nodeText(page)).toContain("Additional verification required");
    expect(nodeText(page)).toContain("Verify code");
    expect(nodeText(page)).not.toContain("Access Granted");
    expect(nodeText(page)).not.toContain(MFA_CHALLENGE_ID);
    expect(apiRequestMock.mock.calls.filter(([path]) => path === "/access/evaluate")).toHaveLength(
      2,
    );
  });

  it("clears a previous verification error when a new access request starts", async () => {
    apiRequestMock
      .mockResolvedValueOnce(responseFor("STEP_UP", { mfa_challenge_id: MFA_CHALLENGE_ID }))
      .mockResolvedValueOnce(verificationResponse(429, { detail: "private rate-limit detail" }))
      .mockResolvedValueOnce(responseFor("BLOCK"));

    await clickRequest(renderPage());
    enterTotpCode(renderPage(), "123456");
    await submitTotp(renderPage());
    expect(nodeText(renderPage())).toContain(
      "Verification could not be completed. Please try again.",
    );

    await clickRequest(renderPage());

    const page = renderPage();
    expect(nodeText(page)).toContain("Access denied");
    expect(nodeText(page)).not.toContain("Verification could not be completed.");
    expect(nodeText(page)).not.toContain("private rate-limit detail");
  });

  it("disables the action while the access request is pending", async () => {
    let resolveRequest!: (response: Response) => void;
    apiRequestMock.mockReturnValue(
      new Promise<Response>((resolve) => {
        resolveRequest = resolve;
      }),
    );

    const pending = clickRequest(renderPage());
    const loadingPage = renderPage();
    const button = requiredNode(loadingPage, "button");
    expect(button.props.disabled).toBe(true);
    expect(nodeText(button)).toContain("Requesting access");

    resolveRequest(responseFor("BLOCK"));
    await pending;
  });

  it("shows a generic retryable error for API/network failures", async () => {
    apiRequestMock.mockRejectedValue(new Error(PRIVATE_ERROR));

    await clickRequest(renderPage());

    const page = renderPage();
    expect(nodeText(requiredNode(page, "p"))).toBeTruthy();
    expect(findNode(page, (candidate) => candidate.props.role === "alert")).toBeDefined();
    expect(nodeText(page)).toContain("We couldn't complete the access request. Please try again.");
    expect(nodeText(page)).not.toContain(PRIVATE_ERROR);
  });

  it("does not expose an unsuccessful API response body", async () => {
    apiRequestMock.mockResolvedValue(new Response(PRIVATE_ERROR, { status: 500 }));

    await clickRequest(renderPage());

    const page = renderPage();
    expect(nodeText(page)).toContain("We couldn't complete the access request. Please try again.");
    expect(nodeText(page)).not.toContain(PRIVATE_ERROR);
  });
});

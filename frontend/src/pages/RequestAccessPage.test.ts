import { afterEach, beforeEach, describe, expect, expectTypeOf, it, vi } from "vitest";
import type { ComponentProps } from "react";

const { hookHarness, apiRequestMock, uuidMock } = vi.hoisted(() => ({
  hookHarness: {
    states: [] as unknown[],
    cursor: 0,
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
const PRIVATE_ERROR = "secret-token private stack trace";

function renderPage(): UiNode {
  hookHarness.cursor = 0;
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
          mfa_challenge_id: decision === "STEP_UP" ? "challenge-private-id" : null,
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
      if (decision === "STEP_UP") {
        expect(nodeText(result)).toContain("Verify with authenticator");
        expect(nodeText(result)).not.toContain("challenge-private-id");
      }
      expect(nodeText(result)).not.toMatch(
        /trust score|threshold|weight|policy id|private-policy-id|decision_reason|private-decision-reason|exception|private-exception-details|private-device-token|private-user-agent|factor calculation|challenge-private-id/i,
      );
    },
  );

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

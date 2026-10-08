import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { hookHarness, historyMock, detailMock, profileRoleMock, routeParams } = vi.hoisted(() => ({
  hookHarness: {
    states: [] as unknown[],
    stateCursor: 0,
    effects: [] as Array<{ deps: readonly unknown[] | undefined; cleanup?: () => void }>,
    effectCursor: 0,
  },
  historyMock: vi.fn(),
  detailMock: vi.fn(),
  profileRoleMock: vi.fn(),
  routeParams: { accessRequestId: undefined as string | undefined },
}));

vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  return {
    ...actual,
    useState: (initialValue: unknown) => {
      const index = hookHarness.stateCursor++;
      if (!(index in hookHarness.states)) hookHarness.states[index] = initialValue;
      return [
        hookHarness.states[index],
        (nextValue: unknown) => {
          hookHarness.states[index] =
            typeof nextValue === "function"
              ? (nextValue as (current: unknown) => unknown)(hookHarness.states[index])
              : nextValue;
        },
      ];
    },
    useEffect: (effect: () => (() => void) | undefined, deps?: readonly unknown[]) => {
      const index = hookHarness.effectCursor++;
      const previous = hookHarness.effects[index];
      const changed =
        !previous ||
        !deps ||
        !previous.deps ||
        deps.length !== previous.deps.length ||
        deps.some(
          (dependency, dependencyIndex) => !Object.is(dependency, previous.deps?.[dependencyIndex]),
        );
      if (changed) {
        previous?.cleanup?.();
        const cleanup = effect();
        hookHarness.effects[index] = {
          deps: deps ? [...deps] : undefined,
          cleanup: typeof cleanup === "function" ? cleanup : undefined,
        };
      }
    },
  } as unknown as typeof actual;
});

vi.mock("../api/accessHistory.ts", () => ({
  fetchAccessHistory: historyMock,
  fetchAccessRequest: detailMock,
}));
vi.mock("../auth/useProfileRole.ts", () => ({ useProfileRole: profileRoleMock }));
vi.mock("react-router-dom", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router-dom")>();
  return { ...actual, useParams: () => routeParams };
});

import { AccessHistoryPage, DetailFields } from "./AccessHistoryPage.tsx";
import { AdminEventInvestigationPage, Field } from "./AdminEventInvestigationPage.tsx";
import type { AdminEventInvestigation } from "../types/admin.ts";

interface UiNode {
  type: unknown;
  props: Record<string, unknown>;
}

const row = {
  id: "123e4567-e89b-12d3-a456-426614174000",
  resource_id: "ops-dashboard",
  requested_at: "2026-10-02T12:00:00Z",
  initial_decision: "STEP_UP",
  final_outcome: "ALLOW",
  mfa_was_required: true,
  mfa_status: "SUCCESS",
};

const investigation: AdminEventInvestigation = {
  event: {
    id: "223e4567-e89b-12d3-a456-426614174000",
    event_type: "ACCESS_STEP_UP",
    actor_id: "323e4567-e89b-12d3-a456-426614174000",
    target_user_id: null,
    decision: "STEP_UP",
    risk_category: "MEDIUM",
    created_at: "2026-10-02T12:00:00Z",
  },
  access_request: {
    id: row.id,
    user_id: "323e4567-e89b-12d3-a456-426614174000",
    resource_id: row.resource_id,
    source_ip: "192.0.2.10",
    resolved_region: "Example region",
    initial_decision: "STEP_UP",
    mfa_required: true,
    final_outcome: "ALLOW",
    requested_at: row.requested_at,
    resolved_at: "2026-10-02T12:01:00Z",
    device: { id: "423e4567-e89b-12d3-a456-426614174000", device_hash: "abcd…" },
  },
  context_signals: {
    captured_at: "2026-10-02T12:00:00Z",
    device_familiarity_raw: "unknown_device",
    device_health_raw: "healthy",
    location_raw: "expected_region",
    time_raw: "usual_time",
  },
  trust_evaluation: {
    id: "523e4567-e89b-12d3-a456-426614174000",
    trust_score: 67,
    risk_classification: "MEDIUM",
    status: "COMPLETE",
    evaluated_at: "2026-10-02T12:00:00Z",
    factors: [
      {
        factor_name: "device_familiarity",
        raw_value: "unknown_device",
        normalized_score: 20,
        weight: 0.3,
        weighted_contribution: 6,
        explanation: "Device familiarity explanation",
      },
    ],
  },
  policy_decision: {
    id: "623e4567-e89b-12d3-a456-426614174000",
    decision: "STEP_UP",
    decision_reason: "Additional verification required",
    decided_at: "2026-10-02T12:00:00Z",
    policy_version: {
      id: "723e4567-e89b-12d3-a456-426614174000",
      version_label: "v1",
      created_at: "2026-10-01T12:00:00Z",
    },
  },
  otp_challenges: [
    {
      id: "823e4567-e89b-12d3-a456-426614174000",
      status: "SUCCESS",
      attempt_count: 1,
      created_at: "2026-10-02T12:00:00Z",
      expires_at: "2026-10-02T12:05:00Z",
      verified_at: "2026-10-02T12:01:00Z",
    },
  ],
  related_events: [],
  behavioral_indicators: {
    repeated_failed_access_attempts: { count: 0, normalized_value: 0, flagged: false },
    recent_blocks: { count: 0, normalized_value: 0, flagged: false },
  },
};

function renderPage(): UiNode {
  hookHarness.stateCursor = 0;
  hookHarness.effectCursor = 0;
  let element = AccessHistoryPage() as UiNode;
  while (typeof element.type === "function") {
    element = (element.type as (props: Record<string, unknown>) => UiNode)(element.props);
  }
  return expandAdminInvestigation(element) as UiNode;
}

function expandAdminInvestigation(node: unknown): unknown {
  if (Array.isArray(node)) return node.map(expandAdminInvestigation);
  if (typeof node !== "object" || node === null || !("type" in node) || !("props" in node)) {
    return node;
  }
  const candidate = node as UiNode;
  if (candidate.type === AdminEventInvestigationPage) {
    return expandAdminInvestigation(
      AdminEventInvestigationPage(
        candidate.props as {
          investigation: AdminEventInvestigation;
          backTo: string;
          backLabel: string;
        },
      ),
    );
  }
  if (candidate.type === Field) {
    return expandAdminInvestigation(
      Field(candidate.props as { label: string; value: string | null | undefined }),
    );
  }
  return {
    ...candidate,
    props: { ...candidate.props, children: expandAdminInvestigation(candidate.props.children) },
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

function countNodes(node: unknown, predicate: (candidate: UiNode) => boolean): number {
  if (Array.isArray(node)) {
    return node.reduce((count, child) => count + countNodes(child, predicate), 0);
  }
  if (typeof node !== "object" || node === null || !("type" in node) || !("props" in node)) {
    return 0;
  }
  const candidate = node as UiNode;
  return Number(predicate(candidate)) + countNodes(candidate.props.children, predicate);
}

function textContent(node: unknown): string {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(textContent).join(" ");
  if (typeof node !== "object" || node === null || !("props" in node)) return "";
  return textContent((node as UiNode).props.children);
}

async function flushPromises(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

beforeEach(() => {
  hookHarness.states = [];
  hookHarness.stateCursor = 0;
  hookHarness.effects = [];
  hookHarness.effectCursor = 0;
  routeParams.accessRequestId = undefined;
  historyMock.mockReset();
  detailMock.mockReset();
  profileRoleMock.mockReset().mockReturnValue({ role: "USER", loading: false });
});

afterEach(() => {
  for (const effect of hookHarness.effects) effect.cleanup?.();
  vi.clearAllMocks();
});

describe("AccessHistoryPage", () => {
  it("renders only the curated history fields and links to its detail route", async () => {
    historyMock.mockResolvedValue([row]);

    const loadingPage = renderPage();
    expect(findNode(loadingPage, (node) => node.props.role === "status")).toBeDefined();
    await flushPromises();
    const page = renderPage();

    expect(textContent(page)).toContain("Access history");
    expect(textContent(page)).toContain(row.id);
    expect(textContent(page)).toContain("Operations Dashboard");
    expect(textContent(page)).not.toContain("ops-dashboard");
    expect(textContent(page)).toContain("Additional verification required");
    expect(textContent(page)).toContain("Access granted");
    expect(textContent(page)).toMatch(/Request result:\s+Additional verification required/);
    expect(textContent(page)).toMatch(/Outcome:\s+Access granted/);
    expect(textContent(page)).not.toMatch(/\bALLOW\b|\bSTEP_UP\b|\bBLOCK\b/);
    expect(textContent(page)).toMatch(/Authenticator:\s+Verified/);
    expect(textContent(page)).toMatch(/Authenticator\s+required/);
    expect(textContent(page)).not.toContain("SUCCESS");
    expect(textContent(page)).not.toMatch(
      /trust score|factor|weight|threshold|policy version|decision reason|fingerprint|IP address|location|OTP/i,
    );
    expect(textContent(page)).not.toMatch(
      /behavioral risk indicators|repeated failed access attempts|recent blocks/i,
    );
    expect(findNode(page, (node) => node.props.to === `/history/${row.id}`)).toBeDefined();
    expect(historyMock).toHaveBeenCalledWith(1, 10, expect.any(AbortSignal));
  });

  it("fetches the next page and supports returning to the previous page", async () => {
    historyMock
      .mockResolvedValueOnce(
        Array.from({ length: 10 }, (_, index) => ({
          ...row,
          id: `123e4567-e89b-12d3-a456-${String(index).padStart(12, "0")}`,
        })),
      )
      .mockResolvedValueOnce([{ ...row, id: "223e4567-e89b-12d3-a456-426614174000" }])
      .mockResolvedValueOnce([{ ...row, id: "323e4567-e89b-12d3-a456-426614174000" }]);

    renderPage();
    await flushPromises();
    let page = renderPage();
    const nextButton = findNode(page, (node) => textContent(node) === "Next");
    expect(nextButton?.props.disabled).toBe(false);
    (nextButton?.props.onClick as () => void)();

    page = renderPage();
    await flushPromises();
    page = renderPage();
    expect(textContent(page)).toContain("223e4567-e89b-12d3-a456-426614174000");
    expect(textContent(page)).toMatch(/Page\s+2/);
    expect(historyMock).toHaveBeenNthCalledWith(1, 1, 10, expect.any(AbortSignal));
    expect(historyMock).toHaveBeenNthCalledWith(2, 2, 10, expect.any(AbortSignal));

    const previousButton = findNode(page, (node) => textContent(node) === "Previous");
    (previousButton?.props.onClick as () => void)();
    renderPage();
    await flushPromises();
    expect(historyMock).toHaveBeenCalledWith(1, 10, expect.any(AbortSignal));
  });

  it("shows an empty state when no history is returned", async () => {
    historyMock.mockResolvedValue([]);
    renderPage();
    await flushPromises();

    expect(textContent(renderPage())).toContain("No access history yet");
  });

  it("shows a generic error without rendering backend details", async () => {
    historyMock.mockRejectedValue(new Error("private backend decision_reason payload"));
    renderPage();
    await flushPromises();
    const page = renderPage();

    expect(textContent(page)).toContain("Access history is temporarily unavailable.");
    expect(textContent(page)).not.toContain("private backend decision_reason payload");
    expect(findNode(page, (node) => node.props.role === "alert")).toBeDefined();
  });

  it("loads the detail endpoint and renders the same seven-field allow-list", async () => {
    routeParams.accessRequestId = row.id;
    detailMock.mockResolvedValue({ kind: "user", record: row });
    renderPage();
    await flushPromises();
    const page = renderPage();

    expect(detailMock).toHaveBeenCalledWith(row.id, expect.any(AbortSignal));
    expect(textContent(page)).toContain("Access request");
    const detailFields = findNode(page, (node) => node.type === DetailFields);
    expect(detailFields).toBeDefined();
    const detailContent = textContent(DetailFields(detailFields?.props as { record: typeof row }));
    expect(detailContent).toContain(row.id);
    expect(detailContent).toContain("Operations Dashboard");
    expect(detailContent).not.toContain("ops-dashboard");
    expect(detailContent).toContain("Additional verification required");
    expect(detailContent).toContain("Access granted");
    expect(detailContent).not.toMatch(/\bALLOW\b|\bSTEP_UP\b|\bBLOCK\b/);
    expect(detailContent).toContain("Authenticator required");
    expect(detailContent).toContain("Authenticator");
    expect(detailContent).toContain("Verified");
    expect(textContent(page)).not.toMatch(
      /trust score|factor|weight|threshold|policy version|decision reason|fingerprint|IP address|location|OTP/i,
    );
    expect(detailContent).not.toMatch(
      /trust score|factor|weight|threshold|policy version|decision reason|fingerprint|IP address|location|OTP/i,
    );
    expect(findNode(page, (node) => node.props.to === "/history")).toBeDefined();
  });

  it("renders an ADMIN investigation response using the existing investigation presentation", async () => {
    routeParams.accessRequestId = row.id;
    profileRoleMock.mockReturnValue({ role: "ADMIN", loading: false });
    detailMock.mockResolvedValue({ kind: "admin", investigation });

    renderPage();
    await flushPromises();
    const page = renderPage();
    const text = textContent(page);

    expect(text).toContain("Access request investigation");
    expect(text).toContain("Trust evaluation and factors");
    expect(text).toContain("67");
    expect(text).toContain("Policy decision");
    expect(text).toContain("MFA / OTP challenges");
    expect(findNode(page, (node) => node.props.to === "/history")).toBeDefined();
    expect(countNodes(page, (node) => node.type === "h1")).toBe(1);
    expect(countNodes(page, (node) => node.props.to === "/history")).toBe(1);
    expect(detailMock).toHaveBeenCalledWith(row.id, expect.any(AbortSignal));
  });

  it("does not render an ADMIN investigation response for a USER", async () => {
    routeParams.accessRequestId = row.id;
    profileRoleMock.mockReturnValue({ role: "USER", loading: false });
    detailMock.mockResolvedValue({ kind: "admin", investigation });

    renderPage();
    await flushPromises();
    const page = renderPage();
    const text = textContent(page);

    expect(text).toContain("Access history is temporarily unavailable.");
    expect(text).not.toContain("Trust evaluation and factors");
    expect(text).not.toContain("Policy decision");
    expect(text).not.toContain("192.0.2.10");
  });

  it("shows a safe error for malformed or unexpected detail responses", async () => {
    routeParams.accessRequestId = row.id;
    detailMock.mockRejectedValue(new Error("private malformed investigation"));

    renderPage();
    await flushPromises();
    const page = renderPage();
    const text = textContent(page);

    expect(text).toContain("Access history is temporarily unavailable.");
    expect(text).not.toContain("private malformed investigation");
    expect(text).not.toContain("Trust evaluation and factors");
  });
});

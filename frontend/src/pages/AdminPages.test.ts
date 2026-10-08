import type { ReactElement } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

const { hooks, dashboardMock, eventsMock, investigationMock, routeParams, searchParams } =
  vi.hoisted(() => ({
    hooks: {
      states: [] as unknown[],
      stateCursor: 0,
      effects: [] as Array<{ deps: readonly unknown[] | undefined; cleanup?: () => void }>,
      effectCursor: 0,
    },
    dashboardMock: vi.fn(),
    eventsMock: vi.fn(),
    investigationMock: vi.fn(),
    routeParams: { eventId: "event-1" },
    searchParams: new URLSearchParams(),
  }));

vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  return {
    ...actual,
    useState: (initial: unknown) => {
      const index = hooks.stateCursor++;
      if (!(index in hooks.states)) {
        hooks.states[index] =
          typeof initial === "function" ? (initial as () => unknown)() : initial;
      }
      return [
        hooks.states[index],
        (next: unknown) => {
          hooks.states[index] =
            typeof next === "function"
              ? (next as (current: unknown) => unknown)(hooks.states[index])
              : next;
        },
      ];
    },
    useEffect: (effect: () => (() => void) | undefined, deps?: readonly unknown[]) => {
      const index = hooks.effectCursor++;
      const previous = hooks.effects[index];
      const changed =
        !previous ||
        !deps ||
        !previous.deps ||
        deps.length !== previous.deps.length ||
        deps.some((value, depIndex) => !Object.is(value, previous.deps?.[depIndex]));
      if (changed) {
        previous?.cleanup?.();
        const cleanup = effect();
        hooks.effects[index] = {
          deps: deps ? [...deps] : undefined,
          cleanup: typeof cleanup === "function" ? cleanup : undefined,
        };
      }
    },
  };
});

vi.mock("../api/admin.ts", () => ({
  fetchAdminDashboard: dashboardMock,
  fetchAdminEvents: eventsMock,
  fetchAdminEventInvestigation: investigationMock,
}));
vi.mock("react-router-dom", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router-dom")>();
  return {
    ...actual,
    useParams: () => routeParams,
    useSearchParams: () => [searchParams, vi.fn()],
  };
});

import { AdminDashboardPage } from "./AdminDashboardPage.tsx";
import {
  AdminEventInvestigationPage,
  ChallengeHistory,
  EventFields,
  Field,
} from "./AdminEventInvestigationPage.tsx";
import { AdminEventsPage } from "./AdminEventsPage.tsx";
import { AdminDecision } from "../components/AdminDecision.tsx";
import { AdminLoadingState } from "../components/AdminLoadingState.tsx";
import {
  BehavioralRiskIndicatorsView,
  IndicatorCard,
} from "../components/BehavioralRiskIndicators.tsx";

const dashboard = {
  total_requests: 12,
  allow_count: 5,
  step_up_count: 4,
  block_count: 3,
  average_trust_score: 67.5,
  high_risk_count: 2,
  mfa_success_rate: 0.75,
  behavioral_indicators: {
    repeated_failed_access_attempts: { count: 4, normalized_value: 0.8, flagged: false },
    recent_blocks: { count: 3, normalized_value: 1, flagged: true },
  },
};

const eventPage = {
  items: [
    {
      id: "event-1",
      event_type: "ACCESS_REQUEST_SUBMITTED",
      created_at: "2026-10-01T12:00:00Z",
      user_id: "user-1",
      decision: "BLOCK",
      risk_category: "HIGH",
      trust_score: 30,
      device: "abcdef012345…",
    },
  ],
  total: 41,
  page: 1,
  page_size: 20,
};

const investigation = {
  event: {
    id: "event-1",
    event_type: "ACCESS_REQUEST_SUBMITTED",
    actor_id: "user-1",
    target_user_id: "user-1",
    decision: "STEP_UP",
    risk_category: "MEDIUM",
    created_at: "2026-10-01T12:00:00Z",
  },
  access_request: {
    id: "request-1",
    user_id: "user-1",
    resource_id: "ops-dashboard",
    source_ip: "203.0.113.45",
    resolved_region: "Example region",
    initial_decision: "STEP_UP",
    mfa_required: true,
    final_outcome: "ALLOW",
    requested_at: "2026-10-01T12:00:00Z",
    resolved_at: "2026-10-01T12:02:00Z",
    device: { id: "device-1", device_hash: "abc123…" },
  },
  context_signals: {
    captured_at: "2026-10-01T12:00:00Z",
    device_familiarity_raw: "known_device",
    device_health_raw: "healthy",
    location_raw: "known_region",
    time_raw: "normal_hours",
  },
  trust_evaluation: {
    id: "evaluation-1",
    trust_score: 65.5,
    risk_classification: "MEDIUM",
    status: "COMPLETE",
    evaluated_at: "2026-10-01T12:00:00Z",
    factors: [
      {
        factor_name: "device_familiarity",
        raw_value: "known_device",
        normalized_score: 90,
        weight: 0.35,
        weighted_contribution: 31.5,
        explanation: "Known device contributes to the Trust Score.",
      },
    ],
  },
  policy_decision: {
    id: "policy-decision-1",
    decision: "STEP_UP",
    decision_reason: "Additional verification required.",
    decided_at: "2026-10-01T12:00:00Z",
    policy_version: { id: "policy-1", version_label: "v1", created_at: "2026-09-01T00:00:00Z" },
  },
  otp_challenges: [
    {
      id: "challenge-1",
      status: "EXPIRED",
      attempt_count: 2,
      created_at: "2026-10-01T12:01:00Z",
      expires_at: "2026-10-01T12:06:00Z",
      verified_at: null,
    },
    {
      id: "challenge-2",
      status: "SUCCESS",
      attempt_count: 1,
      created_at: "2026-10-01T12:02:00Z",
      expires_at: "2026-10-01T12:07:00Z",
      verified_at: "2026-10-01T12:03:00Z",
      otp_hash: "DO_NOT_RENDER_HASH",
    },
  ],
  related_events: [
    {
      id: "event-2",
      event_type: "MFA_SUCCESS",
      actor_id: "user-1",
      target_user_id: null,
      decision: "ALLOW",
      risk_category: "LOW",
      created_at: "2026-10-01T12:03:00Z",
    },
  ],
  behavioral_indicators: {
    repeated_failed_access_attempts: { count: 5, normalized_value: 1, flagged: true },
    recent_blocks: { count: 2, normalized_value: 2 / 3, flagged: false },
  },
};

interface UiNode {
  type: unknown;
  props: Record<string, unknown>;
}

function childrenOf(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  if (typeof value === "object" && value !== null && "props" in value) {
    return [(value as UiNode).props.children];
  }
  return [];
}

function textContent(value: unknown): string[] {
  if (typeof value === "string" || typeof value === "number") return [String(value)];
  if (Array.isArray(value)) return value.flatMap(textContent);
  if (typeof value !== "object" || value === null || !("props" in value)) return [];
  const node = value as ReactElement<{ children?: unknown }>;
  const result = textContent(node.props.children);
  if (node.type === AdminDecision) {
    result.push(...textContent(AdminDecision(node.props as { decision: string | null })));
  } else if (
    [
      AdminLoadingState,
      BehavioralRiskIndicatorsView,
      IndicatorCard,
      ChallengeHistory,
      EventFields,
      Field,
    ].includes(node.type as never)
  ) {
    const component = node.type as (props: never) => unknown;
    result.push(...textContent(component(node.props as never)));
  }
  return result;
}

function findNode(value: unknown, predicate: (node: UiNode) => boolean): UiNode | undefined {
  if (Array.isArray(value)) {
    for (const child of value) {
      const found = findNode(child, predicate);
      if (found) return found;
    }
  } else if (typeof value === "object" && value !== null && "props" in value) {
    const node = value as UiNode;
    if (predicate(node)) return node;
    for (const child of childrenOf(value)) {
      const found = findNode(child, predicate);
      if (found) return found;
    }
  }
  return undefined;
}

function resetHooks() {
  for (const effect of hooks.effects) effect.cleanup?.();
  hooks.states = [];
  hooks.stateCursor = 0;
  hooks.effects = [];
  hooks.effectCursor = 0;
}

function render(component: () => ReactElement) {
  hooks.stateCursor = 0;
  hooks.effectCursor = 0;
  return component();
}

async function settle() {
  await Promise.resolve();
  await Promise.resolve();
}

afterEach(() => {
  resetHooks();
  vi.clearAllMocks();
  routeParams.eventId = "event-1";
  searchParams.forEach((_value, key) => searchParams.delete(key));
});

describe("admin dashboard", () => {
  it("shows loading, successful backend data, and matching event-filter navigation", async () => {
    dashboardMock.mockResolvedValue(dashboard);
    const loading = render(AdminDashboardPage);
    expect(textContent(loading).join(" ")).toContain("Loading dashboard metrics");
    await settle();
    const page = render(AdminDashboardPage);
    const text = textContent(page).join(" ");
    expect(text).toContain("12");
    expect(text).toContain("67.50");
    expect(text).toContain("75.0%");
    expect(text).toContain("Recent suspicious activity");
    expect(text).toContain("not included in the current dashboard API response");
    expect(text).toContain("Repeated failed access attempts");
    expect(text).toContain("Recent blocks");
    expect(text).toContain("Current count 4");
    expect(text).toMatch(/Normalized value 0\.80\s+\/ 1\.00/);
    expect(text).toContain("Not flagged");
    expect(text).toContain("Flagged");
    expect(text).toContain("do not modify Trust Score or access decisions");
    expect(text).toContain("Total requests");
    expect(text).toContain("Initial ALLOW decisions");
    expect(text).toContain("Initial STEP-UP decisions");
    expect(text).toContain("Initial BLOCK decisions");
    expect(text).toContain("initial decision");
    expect(text).toContain("different final outcome");
    expect(text).toContain("MFA success rate");
    expect(dashboardMock).toHaveBeenCalledWith(
      expect.stringMatching(/T00:00:00Z$/),
      expect.stringMatching(/T23:59:59\.999Z$/),
      expect.any(AbortSignal),
    );
    const links: string[] = [];
    const walk = (node: unknown) => {
      if (Array.isArray(node)) node.forEach(walk);
      else if (typeof node === "object" && node !== null && "props" in node) {
        const current = node as UiNode;
        if (typeof current.props.to === "string") links.push(current.props.to);
        walk(current.props.children);
      }
    };
    walk(page);
    expect(links.some((href) => href.includes("decision=ALLOW"))).toBe(true);
    expect(links.some((href) => href.includes("decision=STEP_UP"))).toBe(true);
    expect(links.some((href) => href.includes("decision=BLOCK"))).toBe(true);
    expect(links.some((href) => href.includes("risk_category=HIGH"))).toBe(true);
    expect(links.filter((href) => href.startsWith("/admin/events?")).length).toBe(7);
  });

  it("shows an API error without exposing its response details", async () => {
    dashboardMock.mockRejectedValue(new Error("secret backend payload"));
    render(AdminDashboardPage);
    await settle();
    const page = render(AdminDashboardPage);
    expect(textContent(page).join(" ")).toContain("Dashboard data is temporarily unavailable");
    expect(textContent(page).join(" ")).not.toContain("secret backend payload");
  });

  it("shows an empty-period message from zero backend requests", async () => {
    dashboardMock.mockResolvedValue({ ...dashboard, total_requests: 0 });
    render(AdminDashboardPage);
    await settle();
    expect(textContent(render(AdminDashboardPage)).join(" ")).toContain(
      "No access requests were recorded in this date range.",
    );
  });

  it("labels normalized indicator progress accessibly without adding keyboard traps", () => {
    const card = IndicatorCard({
      title: "Recent blocks",
      description: "Access requests ending in BLOCK.",
      indicator: { count: 2, normalized_value: 2 / 3, flagged: false },
    });
    const progress = findNode(card, (node) => node.type === "progress");
    const article = findNode(card, (node) => node.type === "article");
    expect(progress?.props["aria-label"]).toBe("Recent blocks normalized value");
    expect(progress?.props.max).toBe(1);
    expect(progress?.props.value).toBeCloseTo(2 / 3);
    expect(article?.props["aria-labelledby"]).toBe("recent-blocks-indicator-title");
    expect(findNode(card, (node) => node.props.tabIndex !== undefined)).toBeUndefined();
  });
});

describe("admin security events", () => {
  it("renders events with accessible decision text and event detail navigation", async () => {
    eventsMock.mockResolvedValue(eventPage);
    expect(textContent(render(AdminEventsPage)).join(" ")).toContain("Loading security events");
    await settle();
    const page = render(AdminEventsPage);
    const text = textContent(page).join(" ");
    expect(text).toContain("ACCESS_REQUEST_SUBMITTED");
    expect(text).toContain("BLOCK");
    const decision = AdminDecision({ decision: "BLOCK" }) as ReactElement<{
      "aria-label": string;
      className: string;
    }>;
    expect(decision.props["aria-label"]).toBe("Decision: BLOCK");
    expect(decision.props.className).toContain("block");
    expect(textContent(decision).join(" ")).toContain("BLOCK");
    expect(textContent(decision).join(" ")).toContain("×");
    expect(findNode(page, (node) => node.props.to === "/admin/events/event-1")).toBeDefined();
  });

  it("renders empty and error states", async () => {
    eventsMock.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 20 });
    render(AdminEventsPage);
    await settle();
    expect(textContent(render(AdminEventsPage)).join(" ")).toContain(
      "No events match these filters",
    );
    expect(
      findNode(
        render(AdminEventsPage),
        (node) => textContent(node.props.children).join("") === "Reset filters",
      ),
    ).toBeDefined();

    resetHooks();
    eventsMock.mockRejectedValue(new Error("secret backend payload"));
    render(AdminEventsPage);
    await settle();
    const errorPage = render(AdminEventsPage);
    expect(textContent(errorPage).join(" ")).toContain(
      "Security events are temporarily unavailable",
    );
    expect(textContent(errorPage).join(" ")).not.toContain("secret backend payload");
  });

  it("applies keyboard-operable filters and changes request parameters on pagination", async () => {
    eventsMock.mockResolvedValue(eventPage);
    let page = render(AdminEventsPage);
    await settle();
    page = render(AdminEventsPage);
    const userInput = findNode(
      page,
      (node) => node.type === "input" && node.props.type !== "date" && node.props.value === "",
    );
    expect(userInput).toBeDefined();
    (userInput?.props.onChange as (event: unknown) => void)({
      currentTarget: { value: "user-42" },
    });
    page = render(AdminEventsPage);
    const form = findNode(page, (node) => node.props["aria-label"] === "Security event filters");
    (form?.props.onSubmit as (event: { preventDefault: () => void }) => void)({
      preventDefault: () => undefined,
    });
    render(AdminEventsPage);
    await settle();
    expect(eventsMock).toHaveBeenLastCalledWith(
      expect.objectContaining({ user_id: "user-42", page: 1, page_size: 20 }),
      expect.any(AbortSignal),
    );

    page = render(AdminEventsPage);
    const next = findNode(page, (node) => textContent(node.props.children).join("") === "Next");
    (next?.props.onClick as () => void)();
    render(AdminEventsPage);
    await settle();
    expect(eventsMock).toHaveBeenLastCalledWith(
      expect.objectContaining({ user_id: "user-42", page: 2, page_size: 20 }),
      expect.any(AbortSignal),
    );

    page = render(AdminEventsPage);
    const reset = findNode(
      page,
      (node) => textContent(node.props.children).join("") === "Reset filters",
    );
    (reset?.props.onClick as () => void)();
    render(AdminEventsPage);
    await settle();
    expect(eventsMock).toHaveBeenLastCalledWith(
      expect.objectContaining({ page: 1, page_size: 20 }),
      expect.any(AbortSignal),
    );
    expect(eventsMock.mock.calls.at(-1)?.[0]).not.toHaveProperty("user_id");
  });
});

describe("admin event investigation", () => {
  it("renders the full chain and OTP history without hashes or secrets", async () => {
    investigationMock.mockResolvedValue(investigation);
    expect(textContent(render(AdminEventInvestigationPage)).join(" ")).toContain(
      "Loading event investigation",
    );
    await settle();
    const page = render(AdminEventInvestigationPage);
    const text = textContent(page).join(" ");
    for (const section of [
      "Security event",
      "Access request",
      "Context",
      "Trust evaluation and factors",
      "Trust factor breakdown",
      "Policy decision",
      "MFA / OTP challenges",
      "Related events",
    ])
      expect(text).toContain(section);
    expect(text).toContain("EXPIRED");
    expect(text).toContain("SUCCESS");
    expect(text).toContain("Attempts");
    expect(text).toContain("Behavioral risk indicators");
    expect(text).toContain("Current count 5");
    expect(text).toMatch(/Normalized value 0\.67\s+\/ 1\.00/);
    expect(text).toContain("Flagged");
    expect(text).not.toMatch(/otp_hash|DO_NOT_RENDER_HASH|secret value/i);
    expect(investigationMock).toHaveBeenCalledWith("event-1", expect.any(AbortSignal));
  });

  it("handles event-only records and missing optional sections clearly", async () => {
    investigationMock.mockResolvedValue({
      event: investigation.event,
      access_request: null,
      context_signals: null,
      trust_evaluation: null,
      policy_decision: null,
      otp_challenges: [],
      related_events: [],
      behavioral_indicators: null,
    });
    render(AdminEventInvestigationPage);
    await settle();
    const page = render(AdminEventInvestigationPage);
    const text = textContent(page).join(" ");
    expect(text).toContain("Event-only record");
    expect(text).toContain("not linked to an access request");
    expect(text).toContain("Not applicable: this event is not linked to an access request");
    expect(text).not.toContain("Trust evaluation and factors");
    expect(text).not.toContain("No MFA challenge");
  });

  it("renders empty optional sections and no challenge state for a linked request", async () => {
    investigationMock.mockResolvedValue({
      ...investigation,
      context_signals: null,
      trust_evaluation: null,
      policy_decision: null,
      otp_challenges: [],
      related_events: [],
    });
    render(AdminEventInvestigationPage);
    await settle();
    const text = textContent(render(AdminEventInvestigationPage)).join(" ");
    expect(text).toContain("No context signals are available");
    expect(text).toContain("No trust evaluation is available");
    expect(text).toContain("No policy decision is available");
    expect(text).toContain("No MFA challenge was recorded");
    expect(text).toContain("No related events are available");
  });

  it("shows a generic error when investigation data cannot be loaded", async () => {
    investigationMock.mockRejectedValue(new Error("private investigation payload"));
    render(AdminEventInvestigationPage);
    await settle();
    const page = render(AdminEventInvestigationPage);
    const text = textContent(page).join(" ");
    expect(text).toContain("Investigation data is temporarily unavailable");
    expect(text).not.toContain("private investigation payload");
    expect(findNode(page, (node) => node.props.role === "alert")).toBeDefined();
  });
});

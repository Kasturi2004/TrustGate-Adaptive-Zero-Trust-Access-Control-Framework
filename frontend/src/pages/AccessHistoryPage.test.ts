import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { hookHarness, historyMock, detailMock, routeParams } = vi.hoisted(() => ({
  hookHarness: {
    states: [] as unknown[],
    stateCursor: 0,
    effects: [] as Array<{ deps: readonly unknown[] | undefined; cleanup?: () => void }>,
    effectCursor: 0,
  },
  historyMock: vi.fn(),
  detailMock: vi.fn(),
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
vi.mock("react-router-dom", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router-dom")>();
  return { ...actual, useParams: () => routeParams };
});

import { AccessHistoryPage, DetailFields } from "./AccessHistoryPage.tsx";

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

function renderPage(): UiNode {
  hookHarness.stateCursor = 0;
  hookHarness.effectCursor = 0;
  let element = AccessHistoryPage() as UiNode;
  while (typeof element.type === "function") {
    element = (element.type as (props: Record<string, unknown>) => UiNode)(element.props);
  }
  return element;
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
    expect(textContent(page)).toContain(row.resource_id);
    expect(textContent(page)).toContain("STEP_UP");
    expect(textContent(page)).toContain("ALLOW");
    expect(textContent(page)).toMatch(/MFA\s+required/);
    expect(textContent(page)).toContain("SUCCESS");
    expect(textContent(page)).not.toMatch(
      /trust score|factor|weight|threshold|policy version|decision reason|fingerprint|IP address|location|OTP/i,
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
    detailMock.mockResolvedValue(row);
    renderPage();
    await flushPromises();
    const page = renderPage();

    expect(detailMock).toHaveBeenCalledWith(row.id, expect.any(AbortSignal));
    expect(textContent(page)).toContain("Access request");
    const detailFields = findNode(page, (node) => node.type === DetailFields);
    expect(detailFields).toBeDefined();
    const detailContent = textContent(DetailFields(detailFields?.props as { record: typeof row }));
    expect(detailContent).toContain(row.id);
    expect(detailContent).toContain(row.resource_id);
    expect(detailContent).toContain("STEP_UP");
    expect(detailContent).toContain("ALLOW");
    expect(detailContent).toContain("MFA required");
    expect(detailContent).toContain("SUCCESS");
    expect(textContent(page)).not.toMatch(
      /trust score|factor|weight|threshold|policy version|decision reason|fingerprint|IP address|location|OTP/i,
    );
    expect(detailContent).not.toMatch(
      /trust score|factor|weight|threshold|policy version|decision reason|fingerprint|IP address|location|OTP/i,
    );
    expect(findNode(page, (node) => node.props.to === "/history")).toBeDefined();
  });
});

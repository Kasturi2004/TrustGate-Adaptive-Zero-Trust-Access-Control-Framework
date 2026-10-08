import { beforeEach, describe, expect, it, vi } from "vitest";

const { apiRequestMock, hookHarness, deviceStatusMock, recognizeDeviceMock } = vi.hoisted(() => ({
  apiRequestMock: vi.fn(),
  deviceStatusMock: vi.fn(),
  recognizeDeviceMock: vi.fn(),
  hookHarness: {
    states: [] as unknown[],
    cursor: 0,
    effect: null as (() => undefined | (() => void)) | null,
    locationState: null as unknown,
  },
}));

vi.mock("react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react")>();
  return {
    ...actual,
    useState: (initialValue: unknown) => {
      const index = hookHarness.cursor++;
      if (!(index in hookHarness.states)) hookHarness.states[index] = initialValue;
      return [
        hookHarness.states[index],
        (nextValue: unknown) => (hookHarness.states[index] = nextValue),
      ];
    },
    useEffect: (effect: () => undefined | (() => void)) => {
      hookHarness.effect = effect;
    },
  } as unknown as typeof actual;
});

vi.mock("react-router-dom", async (importOriginal) => ({
  ...(await importOriginal<typeof import("react-router-dom")>()),
  useLocation: () => ({ state: hookHarness.locationState }),
}));
vi.mock("../api/client.ts", () => ({ apiRequest: apiRequestMock }));
vi.mock("../api/deviceRecognition.ts", () => ({
  fetchCurrentDeviceRecognition: deviceStatusMock,
  recognizeCurrentDevice: recognizeDeviceMock,
}));

import { OperationsDashboardPage } from "./OperationsDashboardPage.tsx";

interface UiNode {
  type: unknown;
  props: Record<string, unknown>;
}

const dashboardResponse = {
  resource_id: "ops-dashboard",
  title: "Operations Dashboard",
  summary: "Your workspace is ready for daily operations.",
  status: "operational",
};

function renderPage(): UiNode {
  hookHarness.cursor = 0;
  return OperationsDashboardPage() as UiNode;
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

function text(node: unknown): string {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(text).join(" ");
  if (typeof node !== "object" || node === null || !("props" in node)) return "";
  return text((node as UiNode).props.children);
}

function linkTo(root: UiNode, path: string): UiNode | undefined {
  return findNode(root, (node) => node.props.to === path);
}

async function finishLoading(): Promise<(() => void) | undefined> {
  const runEffect = hookHarness.effect;
  if (!runEffect) throw new Error("Expected protected-resource loader");
  const cleanup = runEffect();
  await vi.waitFor(() => expect(hookHarness.states[0]).not.toMatchObject({ status: "loading" }));
  return cleanup;
}

describe("OperationsDashboardPage", () => {
  beforeEach(() => {
    hookHarness.states = [];
    hookHarness.cursor = 0;
    hookHarness.effect = null;
    hookHarness.locationState = null;
    apiRequestMock.mockReset();
    deviceStatusMock.mockReset().mockResolvedValue({ recognized: false });
    recognizeDeviceMock.mockReset().mockResolvedValue({ recognized: true });
  });

  it("shows a clear loading state while the server checks access", () => {
    hookHarness.locationState = { accessRequestId: "request-selector" };
    const page = renderPage();

    expect(findNode(page, (node) => node.props.role === "status")).toBeDefined();
    expect(text(page)).toContain("Opening Operations Dashboard");
    expect(text(page)).toContain("Checking your access to this workspace");
    expect(text(page)).not.toContain("Access granted");
  });

  it("renders the protected workspace and access-granted state only after successful redemption", async () => {
    hookHarness.locationState = { accessRequestId: "request-selector" };
    apiRequestMock.mockResolvedValue(
      new Response(JSON.stringify(dashboardResponse), { status: 200 }),
    );

    renderPage();
    await finishLoading();
    const page = renderPage();
    const pageText = text(page);

    expect(pageText).toContain("Operations Dashboard");
    expect(pageText).toContain("Access granted");
    expect(pageText).toContain("You have been granted access to this protected workspace.");
    expect(pageText).toContain("Your workspace is ready for daily operations.");
    expect(pageText).toMatch(/Workspace status\s+Available/);
    expect(pageText).toContain("This workspace is ready to use.");
    expect(pageText).not.toMatch(
      /ops-dashboard|trust score|risk score|policy|evaluation|request UUID/i,
    );
    expect(linkTo(page, "/dashboard")).toBeDefined();
    expect(apiRequestMock).toHaveBeenCalledWith("/resources/ops-dashboard", {
      method: "POST",
      body: { access_request_id: "request-selector" },
    });
    expect(
      findNode(page, (node) => node.type === "button" && text(node).includes("Trust this device")),
    ).toBeDefined();
    expect(pageText).toContain("does not replace sign-in or required verification");
  });

  it("requires an explicit post-redemption action and shows safe recognition success", async () => {
    hookHarness.locationState = { accessRequestId: "redeemed-request" };
    apiRequestMock.mockResolvedValue(
      new Response(JSON.stringify(dashboardResponse), { status: 200 }),
    );

    renderPage();
    await finishLoading();
    let page = renderPage();
    expect(deviceStatusMock).toHaveBeenCalledOnce();
    expect(recognizeDeviceMock).not.toHaveBeenCalled();
    const trustButton = findNode(
      page,
      (node) => node.type === "button" && text(node).includes("Trust this device"),
    );
    expect(trustButton).toBeDefined();
    await (trustButton?.props.onClick as () => Promise<void>)();

    page = renderPage();
    expect(recognizeDeviceMock).toHaveBeenCalledWith("redeemed-request");
    expect(text(page)).toContain("This device is recognized");
    expect(text(page)).not.toContain("device_hash");
    expect(text(page)).not.toContain("redeemed-request");
  });

  it("shows a safe retryable message when explicit recognition fails", async () => {
    hookHarness.locationState = { accessRequestId: "redeemed-request" };
    apiRequestMock.mockResolvedValue(
      new Response(JSON.stringify(dashboardResponse), { status: 200 }),
    );
    recognizeDeviceMock.mockRejectedValue(new Error("private device hash and database detail"));

    renderPage();
    await finishLoading();
    const page = renderPage();
    const trustButton = findNode(
      page,
      (node) => node.type === "button" && text(node).includes("Trust this device"),
    );
    await (trustButton?.props.onClick as () => Promise<void>)();

    expect(text(renderPage())).toContain(
      "We couldn’t save this device preference. Please try again.",
    );
    expect(text(renderPage())).not.toContain("private device hash");
  });

  it("denies direct navigation without a request selector and offers safe navigation", async () => {
    apiRequestMock.mockResolvedValue(
      new Response('{"detail":"private authorization detail"}', { status: 403 }),
    );

    renderPage();
    await finishLoading();
    const page = renderPage();

    expect(text(page)).toContain("Access denied");
    expect(text(page)).toContain("We couldn’t open Operations Dashboard.");
    expect(text(page)).not.toContain("private authorization detail");
    expect(linkTo(page, "/access")).toBeDefined();
    expect(linkTo(page, "/dashboard")).toBeDefined();
    expect(apiRequestMock).toHaveBeenCalledWith("/resources/ops-dashboard", {
      method: "POST",
      body: {},
    });
  });

  it("passes an invalid request selector to server verification and denies access", async () => {
    hookHarness.locationState = { accessRequestId: "not-a-request-id" };
    apiRequestMock.mockResolvedValue(new Response("{}", { status: 403 }));

    renderPage();
    await finishLoading();

    expect(text(renderPage())).toContain("Access denied");
    expect(apiRequestMock).toHaveBeenCalledWith("/resources/ops-dashboard", {
      method: "POST",
      body: { access_request_id: "not-a-request-id" },
    });
  });

  it("shows a safe denial on network or unexpected-response failures", async () => {
    apiRequestMock.mockRejectedValueOnce(new Error("private backend detail"));
    renderPage();
    await finishLoading();
    let page = renderPage();
    expect(text(page)).toContain("We couldn’t open Operations Dashboard.");
    expect(text(page)).not.toContain("private backend detail");

    hookHarness.states = [];
    hookHarness.cursor = 0;
    hookHarness.effect = null;
    apiRequestMock.mockReset();
    apiRequestMock.mockResolvedValue(
      new Response(JSON.stringify({ ...dashboardResponse, summary: { private: "detail" } }), {
        status: 200,
      }),
    );
    renderPage();
    await finishLoading();
    page = renderPage();
    expect(text(page)).toContain("Access denied");
    expect(text(page)).not.toContain("private");
  });

  it("hides previously loaded content while a different request is checked", async () => {
    hookHarness.locationState = { accessRequestId: "first-request" };
    apiRequestMock
      .mockResolvedValueOnce(new Response(JSON.stringify(dashboardResponse), { status: 200 }))
      .mockResolvedValueOnce(new Response("{}", { status: 403 }));

    renderPage();
    const cleanup = await finishLoading();
    expect(text(renderPage())).toContain("Your workspace is ready for daily operations.");

    hookHarness.locationState = { accessRequestId: "second-request" };
    const pendingPage = renderPage();
    expect(text(pendingPage)).toContain("Checking your access to this workspace");
    expect(text(pendingPage)).not.toContain("Your workspace is ready for daily operations.");
    cleanup?.();

    renderPage();
    await finishLoading();
    expect(text(renderPage())).toContain("Access denied");
  });
});

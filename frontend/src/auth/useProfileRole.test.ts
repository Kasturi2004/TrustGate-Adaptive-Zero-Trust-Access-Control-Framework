import { afterEach, describe, expect, it, vi } from "vitest";

const { apiRequestMock } = vi.hoisted(() => ({ apiRequestMock: vi.fn() }));

vi.mock("../api/client.ts", () => ({ apiRequest: apiRequestMock }));
vi.mock("./AuthProvider.tsx", () => ({ useAuth: vi.fn() }));

import { fetchProfileRole } from "./useProfileRole.ts";

afterEach(() => {
  vi.clearAllMocks();
});

describe("fetchProfileRole", () => {
  it("uses the authenticated FastAPI profile role, not user metadata", async () => {
    apiRequestMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          id: "user-1",
          email: "user@example.test",
          role: "USER",
          user_metadata: { role: "ADMIN" },
        }),
        { status: 200 },
      ),
    );

    await expect(fetchProfileRole("user-1")).resolves.toBe("USER");
    expect(apiRequestMock).toHaveBeenCalledWith("/auth/me");
  });

  it("fails closed when the profile identity does not match the session user", async () => {
    apiRequestMock.mockResolvedValue(
      new Response(JSON.stringify({ id: "another-user", role: "ADMIN" }), { status: 200 }),
    );

    await expect(fetchProfileRole("user-1")).resolves.toBeNull();
  });

  it("fails closed when the profile endpoint is not successful", async () => {
    apiRequestMock.mockResolvedValue(new Response(null, { status: 403 }));

    await expect(fetchProfileRole("user-1")).resolves.toBeNull();
  });
});

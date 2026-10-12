import { describe, expect, it, vi } from "vitest";
import { ApiError, api } from "../api/client";
import type { Profile } from "../types/api";
import { adminAccess } from "./adminAccess";
import { AuthSessionController } from "./AuthSessionController";
import type { AuthSessionLike } from "./AuthSessionController";

const admin: Profile = { id: "admin-id", email: "admin@example.com", role: "ADMIN" };
const user: Profile = { id: "user-id", email: "user@example.com", role: "USER" };
const session = (id: string, token = `${id}-token`): AuthSessionLike => ({
  access_token: token,
  user: { id },
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

describe("AuthSessionController", () => {
  it("resolves ADMIN and grants the protected route", async () => {
    const controller = new AuthSessionController(async () => admin);
    controller.setSession(session("admin-id"));
    await flush();
    expect(controller.getSnapshot().status).toBe("authenticated");
    expect(adminAccess(controller.getSnapshot())).toBe("allow");
  });

  it("resolves a non-admin but denies admin access", async () => {
    const controller = new AuthSessionController(async () => user);
    controller.setSession(session("user-id"));
    await flush();
    expect(controller.getSnapshot().status).toBe("authenticated");
    expect(adminAccess(controller.getSnapshot())).toBe("denied");
  });

  it("treats unauthorized profile responses as verification failures", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => new Response(JSON.stringify({ detail: "Unauthorized" }), { status: 401 });
    try {
      const controller = new AuthSessionController((token, signal) => api.profile(token, signal));
      controller.setSession(session("admin-id"));
      await new Promise((resolve) => setTimeout(resolve, 0));
      expect(controller.getSnapshot().status).toBe("profile_error");
      expect(controller.getSnapshot().profile).toBeNull();
      expect(adminAccess(controller.getSnapshot())).toBe("profile_error");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("fails closed on network errors, malformed profiles, and identity mismatch", async () => {
    const network = new AuthSessionController(async () => { throw new TypeError("offline"); });
    network.setSession(session("admin-id"));
    await flush();
    expect(network.getSnapshot().status).toBe("profile_error");
    const mismatch = new AuthSessionController(async () => admin);
    mismatch.setSession(session("someone-else"));
    await flush();
    expect(mismatch.getSnapshot().status).toBe("profile_error");
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => new Response(JSON.stringify({ id: "admin-id", role: "ROOT", email: null }), { status: 200 });
    try {
      await expect(api.profile("token")).rejects.toBeInstanceOf(ApiError);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("ends profile verification when the backend request never settles", async () => {
    vi.useFakeTimers();
    try {
      const pending = deferred<Profile>();
      const controller = new AuthSessionController(() => pending.promise);
      controller.setSession(session("admin-id"));
      expect(controller.getSnapshot().status).toBe("resolving_profile");
      await vi.advanceTimersByTimeAsync(15_000);
      expect(controller.getSnapshot().status).toBe("profile_error");
      expect(controller.getSnapshot().profile).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it("clears ADMIN immediately when a different session arrives", async () => {
    const next = deferred<Profile>();
    const controller = new AuthSessionController(async (token) => {
      return token === "admin-id-token" ? admin : next.promise;
    });
    controller.setSession(session("admin-id"));
    await flush();
    expect(adminAccess(controller.getSnapshot())).toBe("allow");
    controller.setSession(session("other-admin", "other-token"));
    expect(controller.getSnapshot().profile).toBeNull();
    expect(controller.getSnapshot().status).toBe("resolving_profile");
    expect(adminAccess(controller.getSnapshot())).toBe("loading");
  });

  it("does not retain ADMIN after profile failure and ignores an older late response", async () => {
    const first = deferred<Profile>();
    const second = deferred<Profile>();
    const controller = new AuthSessionController((token) => token === "first" ? first.promise : second.promise);
    controller.setSession(session("admin-id", "first"));
    controller.setSession(session("admin-id", "second"));
    second.resolve(admin);
    await flush();
    expect(adminAccess(controller.getSnapshot())).toBe("allow");
    first.resolve(user);
    await flush();
    expect(controller.getSnapshot().profile).toEqual(admin);

    const replacement = deferred<Profile>();
    let calls = 0;
    const failure = new AuthSessionController(async () => {
      calls += 1;
      if (calls === 1) return admin;
      return replacement.promise;
    });
    failure.setSession(session("admin-id"));
    await flush();
    expect(adminAccess(failure.getSnapshot())).toBe("allow");
    failure.setSession(session("admin-id", "new-token"));
    expect(failure.getSnapshot().profile).toBeNull();
    replacement.reject(new Error("/auth/me failed"));
    await flush();
    expect(adminAccess(failure.getSnapshot())).toBe("profile_error");
  });

  it("clears state on logout and resolves a subsequent login", async () => {
    const controller = new AuthSessionController(async (token) => token.startsWith("admin") ? admin : user);
    controller.setSession(session("admin-id", "admin-token"));
    await flush();
    controller.setSession(null);
    expect(controller.getSnapshot().status).toBe("unauthenticated");
    expect(controller.getSnapshot().profile).toBeNull();
    controller.setSession(session("user-id", "user-token"));
    await flush();
    expect(adminAccess(controller.getSnapshot())).toBe("denied");
  });
});

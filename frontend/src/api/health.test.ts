import { describe, expect, it } from "vitest";
import { parseHealthResponse } from "./health.ts";
import { PROTOTYPE_NOTICE } from "../content/prototype.ts";

describe("parseHealthResponse", () => {
  it("accepts the liveness payload", () => {
    expect(parseHealthResponse({ status: "ok" })).toEqual({ status: "ok" });
  });

  it("rejects an unexpected payload", () => {
    expect(() => parseHealthResponse({ status: "degraded", database: "up" })).toThrow(
      /not recognized/,
    );
  });
});

describe("prototype notice", () => {
  it("states that TrustGate is an educational prototype", () => {
    expect(PROTOTYPE_NOTICE).toContain("Educational / portfolio prototype");
    expect(PROTOTYPE_NOTICE).toContain("not a production security product");
  });
});

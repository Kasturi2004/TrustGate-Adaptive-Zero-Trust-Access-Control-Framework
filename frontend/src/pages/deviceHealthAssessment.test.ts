import { describe, expect, it } from "vitest";
import { formatEvidenceCoverage, formatPostureScore } from "./deviceHealthAssessment";

describe("device posture assessment display", () => {
  it("does not present a missing score as verified posture", () => {
    expect(formatPostureScore(null)).toBe("No verified score");
    expect(formatPostureScore("n/a")).toBe("Score unavailable");
  });

  it("formats a verified score and reports evidence coverage", () => {
    expect(formatPostureScore("85.25")).toBe("85 / 100");
    expect(formatEvidenceCoverage(2, 5)).toBe("2 of 5 checks verified");
  });

  it("clamps malformed coverage values before display", () => {
    expect(formatEvidenceCoverage(7, 5)).toBe("5 of 5 checks verified");
    expect(formatEvidenceCoverage(-1, 5)).toBe("0 of 5 checks verified");
    expect(formatEvidenceCoverage(1, Number.NaN)).toBe("0 of 0 checks verified");
  });
});

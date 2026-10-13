export function formatPostureScore(score: string | number | null): string {
  if (score === null) return "No verified score";
  const parsed = Number(score);
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 100) {
    return "Score unavailable";
  }
  return `${Math.round(parsed)} / 100`;
}

export function formatEvidenceCoverage(verified: number, total: number): string {
  const safeTotal = Number.isInteger(total) && total >= 0 ? total : 0;
  const safeVerified = Number.isInteger(verified)
    ? Math.min(Math.max(verified, 0), safeTotal)
    : 0;
  return `${safeVerified} of ${safeTotal} checks verified`;
}

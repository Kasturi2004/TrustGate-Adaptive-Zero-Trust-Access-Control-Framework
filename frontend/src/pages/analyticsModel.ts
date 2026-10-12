import type { DashboardMetrics } from "../types/api";

export interface DecisionSlice {
  decision: "ALLOW" | "STEP_UP" | "BLOCK";
  count: number;
  percentage: number;
}

function safeCount(value: number | null | undefined): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0
    ? value
    : 0;
}

export function decisionDistribution(
  metrics: Pick<DashboardMetrics, "allow_count" | "step_up_count" | "block_count">,
): DecisionSlice[] {
  const counts = [
    { decision: "ALLOW" as const, count: safeCount(metrics.allow_count) },
    { decision: "STEP_UP" as const, count: safeCount(metrics.step_up_count) },
    { decision: "BLOCK" as const, count: safeCount(metrics.block_count) },
  ];
  const total = counts.reduce((sum, item) => sum + item.count, 0);
  return counts.map(({ decision, count }) => ({
    decision,
    count,
    percentage: total ? (count / total) * 100 : 0,
  }));
}

export function customDashboardInterval(fromDate: string, toDate: string) {
  if (!fromDate || !toDate) throw new Error("Choose both a start and end date.");
  const from = new Date(`${fromDate}T00:00:00.000Z`);
  const to = new Date(`${toDate}T23:59:59.999Z`);
  if (!Number.isFinite(from.getTime()) || !Number.isFinite(to.getTime())) {
    throw new Error("Enter valid dates.");
  }
  if (from > to) throw new Error("The start date must not be after the end date.");
  return { from, to };
}

export function utcDateInput(date: Date): string {
  return date.toISOString().slice(0, 10);
}

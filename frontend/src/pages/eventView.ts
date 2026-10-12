export function investigationPath(eventId: string): string {
  return `/investigations/${encodeURIComponent(eventId)}`;
}

export function paginationRange(page: number, pageSize: number, total: number) {
  if (total <= 0) return { start: 0, end: 0 };
  return {
    start: (page - 1) * pageSize + 1,
    end: Math.min(page * pageSize, total),
  };
}

export function formatAuditTimestamp(value: string | Date): string {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown time";

  const parts = new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
    hour12: true,
  }).formatToParts(date);
  const part = (type: Intl.DateTimeFormatPartTypes) =>
    parts.find((item) => item.type === type)?.value ?? "";

  return `${part("day")} ${part("month")} ${part("year")}, ${part("hour")}:${part("minute")} ${part("dayPeriod").toUpperCase()}`;
}

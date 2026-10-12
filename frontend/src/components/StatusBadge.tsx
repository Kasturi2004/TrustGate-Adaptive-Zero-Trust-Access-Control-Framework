export function StatusBadge({
  value,
  label: displayLabel,
  variant = "decision",
}: {
  value: string | null | undefined;
  label?: string;
  variant?: "decision" | "risk";
}) {
  const normalized = value?.toUpperCase() ?? "UNKNOWN";
  const tone =
    normalized === "ALLOW" || normalized === "LOW"
      ? "good"
      : normalized === "STEP-UP" || normalized === "MEDIUM"
        ? "warning"
        : normalized === "BLOCK" || normalized === "HIGH"
          ? "danger"
          : "neutral";
  const label = displayLabel ?? normalized.replaceAll("_", " ");
  return (
    <span className={`badge badge-${tone}${variant === "risk" ? " badge-risk" : ""}`}>
      <span className="badge-dot" aria-hidden="true" />
      {label}
    </span>
  );
}

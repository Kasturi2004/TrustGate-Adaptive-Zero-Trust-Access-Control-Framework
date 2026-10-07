type Decision = "ALLOW" | "STEP_UP" | "BLOCK" | string | null;

const decisionLabels: Record<string, { label: string; icon: string; tone: string }> = {
  ALLOW: { label: "ALLOW", icon: "✓", tone: "allow" },
  STEP_UP: { label: "STEP-UP", icon: "!", tone: "step" },
  BLOCK: { label: "BLOCK", icon: "×", tone: "block" },
};

export function AdminDecision({ decision }: { decision: Decision }) {
  const item = decision ? decisionLabels[decision] : undefined;
  const label = item?.label ?? decision ?? "No decision";
  return (
    <span className={`admin-decision ${item?.tone ?? "unknown"}`} aria-label={`Decision: ${label}`}>
      {item && <span aria-hidden="true">{item.icon}</span>}
      <strong>{label}</strong>
    </span>
  );
}

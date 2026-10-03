import { Link } from "react-router-dom";
import { useProfileRole } from "../auth/useProfileRole.ts";

const workspaceRoutes = [
  {
    to: "/access",
    label: "Request protected access",
    detail: "Submit a request for backend evaluation.",
    marker: "→",
  },
  { to: "/history", label: "Access history", detail: "Review your access activity.", marker: "03" },
  {
    to: "/account",
    label: "Account settings",
    detail: "Manage your TrustGate account.",
    marker: "04",
  },
];

export function HomePage() {
  const { role } = useProfileRole();
  const routes = [
    ...workspaceRoutes,
    ...(role === "ADMIN"
      ? [
          {
            to: "/admin/overview",
            label: "Security overview",
            detail: "Open the administrator workspace.",
            marker: "05",
          },
          {
            to: "/admin/events",
            label: "Security events",
            detail: "Open security event records.",
            marker: "06",
          },
        ]
      : []),
  ];

  return (
    <div className="dashboard-page">
      <header className="page-heading">
        <div>
          <span className="page-eyebrow">TrustGate workspace</span>
          <h1>Dashboard</h1>
          <p>Manage protected access requests and your account.</p>
        </div>
        <Link className="dashboard-primary-action" to="/access">
          <span aria-hidden="true">＋</span> Request access
        </Link>
      </header>

      <section className="trust-boundary" aria-label="Access security notice">
        <span className="boundary-icon" aria-hidden="true">
          ◇
        </span>
        <div>
          <strong>Every access request is evaluated independently</strong>
          <p>
            A signed-in session does not automatically authorize access to a protected resource.
          </p>
        </div>
        <span className="boundary-status">
          <i /> Backend decisions
        </span>
      </section>

      <section className="dashboard-section" aria-labelledby="workspace-title">
        <div className="section-heading">
          <div>
            <span className="page-eyebrow">Your workspace</span>
            <h2 id="workspace-title">Quick access</h2>
          </div>
          <span className="section-hint">Available TrustGate areas</span>
        </div>
        <div className="workspace-cards">
          {routes.map((route) => (
            <Link className="workspace-card" to={route.to} key={route.to}>
              <span className="workspace-card-marker" aria-hidden="true">
                {route.marker}
              </span>
              <span className="workspace-card-copy">
                <strong>{route.label}</strong>
                <small>{route.detail}</small>
              </span>
              <span className="workspace-card-arrow" aria-hidden="true">
                ↗
              </span>
            </Link>
          ))}
        </div>
      </section>
    </div>
  );
}

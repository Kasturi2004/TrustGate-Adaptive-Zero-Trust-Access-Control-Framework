import { useEffect, useState } from "react";
import {
  Activity,
  ChartBars,
  Computer,
  FileSearch,
  LayoutDashboard,
  LogOut,
  Menu,
  Shield,
  ShieldAlert,
  Sliders,
  Users,
  X,
} from "./Icons";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/useAuth";

const navGroups = [
  {
    label: "Monitor",
    items: [
      { to: "/", label: "Security overview", icon: LayoutDashboard, end: true },
      { to: "/analytics", label: "Analytics", icon: ChartBars },
    ],
  },
  {
    label: "Manage",
    items: [
      { to: "/users", label: "Users", icon: Users },
      { to: "/devices", label: "Devices", icon: Computer },
      { to: "/policy-settings", label: "Policy settings", icon: Sliders },
    ],
  },
  {
    label: "Investigate",
    items: [
      { to: "/events", label: "Audit logs", icon: ShieldAlert },
      { to: "/investigations", label: "Investigations", icon: FileSearch },
      { to: "/risk-indicators", label: "Behavioral risk", icon: Activity },
    ],
  },
];

function pageInfo(pathname: string) {
  if (pathname === "/analytics")
    return ["Analytics", "Decision and risk summaries from TrustGate data"];
  if (pathname === "/users")
    return ["Users", "Verified profile information available to this administrator"];
  if (pathname === "/devices")
    return ["Devices", "Device information available through current TrustGate APIs"];
  if (pathname === "/policy-settings")
    return ["Policy settings", "Policy configuration access and availability"];
  if (pathname === "/events")
    return [
      "Audit logs",
      "Review persisted security events and recorded decisions",
    ];
  if (pathname === "/investigations")
    return ["Investigations", "Explore events and open the recorded context"];
  if (pathname.startsWith("/investigations/"))
    return ["Investigation", "Review the recorded event context"];
  if (pathname === "/risk-indicators")
    return [
      "Behavioral risk indicators",
      "Signals derived from recent security activity",
    ];
  return ["Security overview", "A clear view of TrustGate access decisions"];
}

export function AdminLayout() {
  const [open, setOpen] = useState(false);
  const [logoutError, setLogoutError] = useState("");
  const location = useLocation();
  const navigate = useNavigate();
  const { profile, signOut } = useAuth();
  const [title, subtitle] = pageInfo(location.pathname);
  const initials = profile?.email?.slice(0, 1).toUpperCase() ?? "A";

  useEffect(() => {
    if (!open) return;
    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [open]);

  async function logout() {
    try {
      await signOut();
      setLogoutError("");
      navigate("/login", { replace: true });
    } catch {
      setLogoutError("Could not complete sign-out. Please retry.");
    }
  }

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      {open && (
        <button
          className="sidebar-scrim"
          aria-label="Close navigation"
          onClick={() => setOpen(false)}
        />
      )}
      <aside id="admin-navigation-panel" className={`sidebar ${open ? "sidebar-open" : ""}`}>
        <div className="brand">
          <span className="brand-symbol">
            <Shield size={19} />
          </span>
          <span>
            Trust<span className="brand-accent">Gate</span>
          </span>
          <button
            className="mobile-close icon-button"
            onClick={() => setOpen(false)}
            aria-label="Close menu"
            aria-controls="admin-navigation-panel"
            aria-expanded={open}
          >
            <X size={18} />
          </button>
        </div>
        <nav id="admin-navigation" aria-label="Admin navigation">
          {navGroups.map(({ label: groupLabel, items }) => (
            <div className="nav-group" key={groupLabel}>
              <p className="nav-caption">{groupLabel}</p>
              {items.map(({ to, label, icon: Icon, end }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={end}
                  onClick={() => setOpen(false)}
                  className={({ isActive }) =>
                    `nav-link ${isActive ? "active" : ""}`
                  }
                >
                  <Icon size={17} />
                  <span>{label}</span>
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-bottom">
          {logoutError && <p className="logout-error" role="alert">{logoutError}</p>}
          <button
            type="button"
            className="nav-link logout-link"
            onClick={() => void logout()}
          >
            <LogOut size={17} />
            <span>Sign out</span>
          </button>
        </div>
      </aside>
      <main className="main-area">
        <header className="topbar">
          <button
            className="icon-button mobile-menu"
            onClick={() => setOpen(true)}
            aria-label="Open navigation"
            aria-controls="admin-navigation-panel"
            aria-expanded={open}
          >
            <Menu size={20} />
          </button>
          <div className="page-label">
            <span>TrustGate / Admin</span>
            <h1>{title}</h1>
          </div>
          <div className="topbar-actions">
            <div className="profile-chip">
              <span className="avatar" aria-hidden="true">
                {initials}
              </span>
              <span className="profile-copy">
                <b
                  title={profile?.email ?? "Administrator"}
                  aria-label={profile?.email ?? "Administrator"}
                >
                  {profile?.email ?? "Administrator"}
                </b>
                <small>{profile?.role ?? "Verified account"}</small>
              </span>
            </div>
          </div>
        </header>
        <div className="page-content" id="main-content" tabIndex={-1}>
          <div className="page-intro">
            <div>
              <p>{subtitle}</p>
            </div>
            {location.pathname === "/" && (
              <div className="period-pill">
                <span className="period-dot" />
                Last 30 days
              </div>
            )}
          </div>
          <Outlet />
        </div>
        <footer className="app-footer">
          <span>
            <Shield size={13} /> TrustGate · Server-authoritative access
          </span>
          <span>
            <FileSearch size={13} /> Review decisions in context
          </span>
        </footer>
      </main>
    </div>
  );
}

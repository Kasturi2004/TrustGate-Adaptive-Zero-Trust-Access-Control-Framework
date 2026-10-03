import { NavLink } from "react-router-dom";
import { useAuth } from "../auth/AuthProvider.tsx";
import { useProfileRole } from "../auth/useProfileRole.ts";
import { LogoutButton } from "./LogoutButton.tsx";

const links = [
  { to: "/dashboard", label: "Dashboard", marker: "01" },
  { to: "/access", label: "Request access", marker: "02" },
  { to: "/history", label: "Access history", marker: "03" },
  { to: "/account", label: "Account", marker: "04" },
];

type HeaderProps = { open?: boolean; onClose?: () => void };

export function Header({ open = false, onClose = () => undefined }: HeaderProps = {}) {
  const { session, user } = useAuth();
  const { role } = useProfileRole();
  const isAuthenticated = Boolean(session && user);

  return (
    <>
      {open && (
        <button
          className="sidebar-scrim"
          type="button"
          aria-label="Close navigation"
          onClick={onClose}
        />
      )}
      <aside className={`site-sidebar ${open ? "open" : ""}`}>
        <div className="sidebar-heading">
          <NavLink className="brand" to="/dashboard" onClick={onClose}>
            <span className="brand-mark" aria-hidden="true">
              TG
            </span>
            <span className="brand-copy">
              <strong>TrustGate</strong>
              <small>ADAPTIVE ACCESS</small>
            </span>
          </NavLink>
          <button
            className="sidebar-close"
            type="button"
            aria-label="Close navigation"
            onClick={onClose}
          >
            ×
          </button>
        </div>
        <div className="workspace-status">
          <span className="workspace-dot" aria-hidden="true" />
          <span>
            <strong>{isAuthenticated ? "Protected session" : "TrustGate workspace"}</strong>
            <small>{isAuthenticated ? "Identity verified" : "Secure access portal"}</small>
          </span>
        </div>
        <nav aria-label="Primary navigation">
          <span className="nav-caption">WORKSPACE</span>
          <ul className="nav-list">
            {links.map((link) => (
              <li key={link.to}>
                <NavLink
                  to={link.to}
                  className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}
                  onClick={onClose}
                >
                  <span className="nav-marker" aria-hidden="true">
                    {link.marker}
                  </span>
                  {link.label}
                </NavLink>
              </li>
            ))}
            {/* Navigation visibility is UX only; FastAPI authorizes admin API routes. */}
            {role === "ADMIN" && (
              <li>
                <NavLink
                  to="/admin/overview"
                  className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}
                  onClick={onClose}
                >
                  <span className="nav-marker" aria-hidden="true">
                    05
                  </span>
                  Admin
                </NavLink>
              </li>
            )}
            {role === "ADMIN" && (
              <li>
                <NavLink
                  to="/admin/events"
                  className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}
                  onClick={onClose}
                >
                  <span className="nav-marker" aria-hidden="true">
                    06
                  </span>
                  Security events
                </NavLink>
              </li>
            )}
          </ul>
        </nav>
        <div className="sidebar-bottom">
          <span className="sidebar-role">
            {role === "ADMIN" ? "SECURITY ADMINISTRATOR" : "TRUSTGATE ACCOUNT"}
          </span>
          <ul className="logout-list">
            <LogoutButton />
          </ul>
          {!isAuthenticated && (
            <NavLink className="sidebar-signin" to="/login">
              Sign in
            </NavLink>
          )}
        </div>
      </aside>
    </>
  );
}

import { NavLink } from "react-router-dom";
import { useAuth } from "../auth/AuthProvider.tsx";
import { useProfileRole } from "../auth/useProfileRole.ts";
import { LogoutButton } from "./LogoutButton.tsx";

const links = [
  { to: "/", label: "Home", end: true },
  { to: "/login", label: "Login", end: false },
  { to: "/dashboard", label: "Dashboard", end: false },
];

export function Header() {
  const { session, user } = useAuth();
  const { role } = useProfileRole();
  const isAuthenticated = Boolean(session && user);

  return (
    <header className="site-header">
      <div className="brand">
        <span className="brand-mark" aria-hidden="true">
          TG
        </span>
        <div>
          <p className="brand-name">TrustGate</p>
          <p className="brand-tag">Adaptive access control</p>
        </div>
      </div>
      <nav aria-label="Primary">
        <ul className="nav-list">
          {links
            .filter((link) => link.to !== "/login" || !isAuthenticated)
            .map((link) => (
              <li key={link.to}>
                <NavLink
                  to={link.to}
                  end={link.end}
                  className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}
                >
                  {link.label}
                </NavLink>
              </li>
            ))}
          {/* Navigation visibility is UX only; FastAPI must authorize every admin API route. */}
          {role === "ADMIN" && (
            <li>
              <NavLink
                to="/admin/overview"
                className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}
              >
                Admin
              </NavLink>
            </li>
          )}
          <LogoutButton />
        </ul>
      </nav>
    </header>
  );
}

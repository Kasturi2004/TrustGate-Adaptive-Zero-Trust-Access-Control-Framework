import { NavLink } from "react-router-dom";

const links = [
  { to: "/", label: "Home", end: true },
  { to: "/login", label: "Login", end: false },
  { to: "/dashboard", label: "Dashboard", end: false },
  { to: "/admin/overview", label: "Admin", end: false },
];

export function Header() {
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
          {links.map((link) => (
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
        </ul>
      </nav>
    </header>
  );
}

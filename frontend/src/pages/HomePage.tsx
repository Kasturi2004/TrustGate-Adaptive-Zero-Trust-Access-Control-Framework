import { Link } from "react-router-dom";

const routes = [
  { to: "/login", label: "Login" },
  { to: "/dashboard", label: "User dashboard" },
  { to: "/access", label: "Protected resource" },
  { to: "/history", label: "Access history" },
  { to: "/account", label: "Account" },
  { to: "/admin/overview", label: "Security overview" },
  { to: "/admin/events", label: "Security events" },
];

export function HomePage() {
  return (
    <section className="panel">
      <h1>Project shell</h1>
      <p className="lede">
        Phase 1 is the development foundation. These routes are placeholders for later phases.
        Nothing here signs a user in, scores a request, or reads a database.
      </p>
      <ul className="route-list">
        {routes.map((route) => (
          <li key={route.to}>
            <Link to={route.to}>{route.label}</Link>
            <span className="route-path">{route.to}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

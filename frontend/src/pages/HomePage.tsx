import { Link } from "react-router-dom";
import { useProfileRole } from "../auth/useProfileRole.ts";

const routes = [
  { to: "/login", label: "Login" },
  { to: "/dashboard", label: "User dashboard" },
  { to: "/access", label: "Protected resource" },
  { to: "/history", label: "Access history" },
  { to: "/account", label: "Account" },
  { to: "/admin/overview", label: "Security overview", adminOnly: true },
  { to: "/admin/events", label: "Security events", adminOnly: true },
];

export function HomePage() {
  const { role } = useProfileRole();

  return (
    <section className="panel">
      <h1>Project shell</h1>
      <p className="lede">
        This project shell links to routes for later phases. Admin links reflect the verified
        profile role; FastAPI remains responsible for authorizing every admin API request.
      </p>
      <ul className="route-list">
        {routes
          .filter((route) => !route.adminOnly || role === "ADMIN")
          .map((route) => (
            <li key={route.to}>
              <Link to={route.to}>{route.label}</Link>
              <span className="route-path">{route.to}</span>
            </li>
          ))}
      </ul>
    </section>
  );
}

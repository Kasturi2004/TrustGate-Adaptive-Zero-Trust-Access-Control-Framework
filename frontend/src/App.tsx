import { useState } from "react";
import { useLocation } from "react-router-dom";
import { Header } from "./components/Header.tsx";
import { HealthStatus } from "./components/HealthStatus.tsx";
import { PrototypeNotice } from "./components/PrototypeNotice.tsx";
import { AppRoutes } from "./routes/AppRoutes.tsx";

export function App() {
  const location = useLocation();
  const [navigationOpen, setNavigationOpen] = useState(false);
  const isAuthRoute = location.pathname === "/login" || location.pathname === "/signup";

  return (
    <div className={`app-shell ${isAuthRoute ? "auth-app-shell" : "workspace-app-shell"}`}>
      <PrototypeNotice />
      {!isAuthRoute && <Header open={navigationOpen} onClose={() => setNavigationOpen(false)} />}
      <div className={isAuthRoute ? "auth-main-wrap" : "main-wrap"}>
        {!isAuthRoute && (
          <header className="topbar">
            <button
              className="menu-button"
              type="button"
              aria-label="Open navigation"
              aria-expanded={navigationOpen}
              onClick={() => setNavigationOpen(true)}
            >
              <span aria-hidden="true">☰</span>
            </button>
            <span className="topbar-context">Adaptive access control</span>
            <HealthStatus />
          </header>
        )}
        <main className={`content ${isAuthRoute ? "auth-content" : ""}`}>
          <AppRoutes />
        </main>
      </div>
    </div>
  );
}

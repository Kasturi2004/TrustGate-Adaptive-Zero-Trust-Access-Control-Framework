import { Header } from "./components/Header.tsx";
import { HealthStatus } from "./components/HealthStatus.tsx";
import { PrototypeNotice } from "./components/PrototypeNotice.tsx";
import { AppRoutes } from "./routes/AppRoutes.tsx";

export function App() {
  return (
    <div className="app-shell">
      <PrototypeNotice />
      <Header />
      <main className="content">
        <HealthStatus />
        <AppRoutes />
      </main>
    </div>
  );
}

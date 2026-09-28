import { Route, Routes } from "react-router-dom";
import { ProtectedRoute } from "../auth/ProtectedRoute.tsx";
import { HomePage } from "../pages/HomePage.tsx";
import { LoginPage } from "../pages/LoginPage.tsx";
import { PlaceholderPage } from "../pages/PlaceholderPage.tsx";

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<HomePage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/dashboard" element={<PlaceholderPage title="Dashboard" />} />
      <Route
        path="/access"
        element={
          <ProtectedRoute>
            <PlaceholderPage title="Protected resource" />
          </ProtectedRoute>
        }
      />
      <Route path="/history" element={<PlaceholderPage title="Access history" />} />
      <Route path="/account" element={<PlaceholderPage title="Account" />} />
      <Route path="/admin/overview" element={<PlaceholderPage title="Security overview" />} />
      <Route path="/admin/events" element={<PlaceholderPage title="Security events" />} />
      <Route path="*" element={<PlaceholderPage title="Page not found" />} />
    </Routes>
  );
}

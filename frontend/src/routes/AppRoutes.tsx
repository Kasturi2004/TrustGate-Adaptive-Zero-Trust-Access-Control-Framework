import { Route, Routes } from "react-router-dom";
import { ProtectedRoute } from "../auth/ProtectedRoute.tsx";
import { AuthEntryRoute } from "../auth/AuthEntryRoute.tsx";
import { HomePage } from "../pages/HomePage.tsx";
import { LoginPage } from "../pages/LoginPage.tsx";
import { PlaceholderPage } from "../pages/PlaceholderPage.tsx";
import { RequestAccessPage } from "../pages/RequestAccessPage.tsx";
import { SignupPage } from "../pages/SignupPage.tsx";
import { AdminRoute } from "./AdminRoute.tsx";

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<HomePage />} />
      <Route
        path="/login"
        element={
          <AuthEntryRoute>
            <LoginPage />
          </AuthEntryRoute>
        }
      />
      <Route
        path="/signup"
        element={
          <AuthEntryRoute>
            <SignupPage />
          </AuthEntryRoute>
        }
      />
      <Route path="/dashboard" element={<HomePage />} />
      <Route
        path="/access"
        element={
          <ProtectedRoute>
            <RequestAccessPage />
          </ProtectedRoute>
        }
      />
      <Route path="/history" element={<PlaceholderPage title="Access history" />} />
      <Route path="/account" element={<PlaceholderPage title="Account" />} />
      <Route
        path="/admin/overview"
        element={
          <AdminRoute>
            <PlaceholderPage title="Security overview" />
          </AdminRoute>
        }
      />
      <Route
        path="/admin/events"
        element={
          <AdminRoute>
            <PlaceholderPage title="Security events" />
          </AdminRoute>
        }
      />
      <Route path="*" element={<PlaceholderPage title="Page not found" />} />
    </Routes>
  );
}

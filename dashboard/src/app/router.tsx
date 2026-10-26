import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { lazy, Suspense } from "react";
import { BrowserRouter, Navigate, Outlet, Route, Routes, useLocation } from "react-router-dom";
import { ApiProblem } from "../api/client";
import { SessionProvider, loginUrl, useSession } from "../api/session";
import { LoginPage } from "../features/auth/LoginPage";
import { SignupPage } from "../features/auth/SignupPage";
import { Skeleton } from "../ui/states";
import { ToastProvider } from "../ui/toast";
import { AppShell } from "./AppShell";

const OverviewPage = lazy(() => import("../features/overview/OverviewPage"));
const SessionsPage = lazy(() => import("../features/sessions/SessionsPage"));
const ApprovalsPage = lazy(() => import("../features/approvals/ApprovalsPage"));
const AgentsPage = lazy(() => import("../features/agents/AgentsPage"));
const PoliciesPage = lazy(() => import("../features/policies/PoliciesPage"));
const AlertsPage = lazy(() => import("../features/alerts/AlertsPage"));
const SettingsPage = lazy(() => import("../features/settings/SettingsPage"));
const McpPage = lazy(() => import("../features/mcp/McpPage"));
const ShadowPage = lazy(() => import("../features/shadow/ShadowPage"));

export function makeQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 5_000,
        refetchOnWindowFocus: false,
        retry: (count, err) => !(err instanceof ApiProblem && err.status >= 400 && err.status < 500) && count < 2,
      },
    },
  });
}

function RequireAuth() {
  const { me, loading } = useSession();
  const loc = useLocation();
  if (loading) return <main><Skeleton label="Checking your session" /></main>;
  if (!me) return <Navigate to={loginUrl(loc.pathname + loc.search)} replace />;
  return <Outlet />;
}

export function AppRoutes() {
  return (
    <Suspense fallback={<main><Skeleton /></main>}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/signup" element={<SignupPage />} />
        <Route element={<RequireAuth />}>
          <Route element={<AppShell />}>
            <Route index element={<OverviewPage />} />
            <Route path="sessions" element={<SessionsPage />} />
            <Route path="sessions/:id" element={<SessionsPage />} />
            <Route path="approvals" element={<ApprovalsPage />} />
            <Route path="approvals/:id" element={<ApprovalsPage />} />
            <Route path="agents" element={<AgentsPage />} />
            <Route path="policies" element={<PoliciesPage />} />
            <Route path="policies/:slug" element={<PoliciesPage />} />
            <Route path="mcp" element={<McpPage />} />
            <Route path="mcp/:id" element={<McpPage />} />
            <Route path="shadow" element={<ShadowPage />} />
            <Route path="alerts" element={<AlertsPage />} />
            <Route path="settings" element={<SettingsPage />} />
          </Route>
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Suspense>
  );
}

export function App({ client }: { client?: QueryClient }) {
  const qc = client ?? makeQueryClient();
  return (
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <ToastProvider>
          <SessionProvider>
            <AppRoutes />
          </SessionProvider>
        </ToastProvider>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router";
import { useAuth } from "./lib/auth";
import { SkeletonRows } from "./design/primitives";

const LoginPage = lazy(() => import("./screens/LoginPage").then((m) => ({ default: m.LoginPage })));
const DashboardPage = lazy(() => import("./screens/DashboardPage").then((m) => ({ default: m.DashboardPage })));
const CasesPage = lazy(() => import("./screens/CasesPage").then((m) => ({ default: m.CasesPage })));
const CaseWorkspace = lazy(() => import("./screens/CaseWorkspace").then((m) => ({ default: m.CaseWorkspace })));
const EvidencePage = lazy(() => import("./screens/EvidencePage").then((m) => ({ default: m.EvidencePage })));
const EvidenceDetailPage = lazy(() =>
  import("./screens/EvidenceDetailPage").then((m) => ({ default: m.EvidenceDetailPage })),
);
const InsightsPage = lazy(() => import("./screens/InsightsPage").then((m) => ({ default: m.InsightsPage })));
const AlertsPage = lazy(() => import("./screens/AlertsPage").then((m) => ({ default: m.AlertsPage })));
const ReportsPage = lazy(() => import("./screens/ReportsPage").then((m) => ({ default: m.ReportsPage })));
const ReportDetailPage = lazy(() => import("./screens/ReportsPage").then((m) => ({ default: m.ReportDetailPage })));
const AuditPage = lazy(() => import("./screens/AuditPage").then((m) => ({ default: m.AuditPage })));
const AdminPage = lazy(() => import("./screens/AdminPage").then((m) => ({ default: m.AdminPage })));
const SettingsPage = lazy(() => import("./screens/SettingsPage").then((m) => ({ default: m.SettingsPage })));

function Guard({ children }: { children: React.ReactNode }) {
  const { user, ready } = useAuth();
  if (!ready) return <div className="p-8"><SkeletonRows /></div>;
  if (!user) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

export function App() {
  return (
    <Suspense fallback={<div className="p-8"><SkeletonRows /></div>}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/*"
          element={
            <Guard>
              <Routes>
                <Route path="/" element={<DashboardPage />} />
                <Route path="/cases" element={<CasesPage />} />
                <Route path="/cases/:caseId" element={<CaseWorkspace />} />
                <Route path="/evidence" element={<EvidencePage />} />
                <Route path="/evidence/:evidenceId" element={<EvidenceDetailPage />} />
                <Route path="/intelligence" element={<InsightsPage />} />
                <Route path="/intelligence/entities/:entityId" element={<InsightsPage />} />
                <Route path="/alerts" element={<AlertsPage />} />
                <Route path="/alerts/:alertId" element={<AlertsPage />} />
                <Route path="/reports" element={<ReportsPage />} />
                <Route path="/reports/:reportId" element={<ReportDetailPage />} />
                <Route path="/audit" element={<AuditPage />} />
                <Route path="/admin" element={<AdminPage />} />
                <Route path="/settings" element={<SettingsPage />} />
              </Routes>
            </Guard>
          }
        />
      </Routes>
    </Suspense>
  );
}

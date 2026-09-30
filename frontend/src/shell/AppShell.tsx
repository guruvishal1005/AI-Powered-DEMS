import { NavLink, useNavigate } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { useAuth } from "../lib/auth";
import { api } from "../lib/api";
import { useUi } from "../lib/ui";
import type { Notification } from "../lib/types";
import { Button } from "../design/primitives";
import { CommandPalette } from "./CommandPalette";

const NAV = [
  { to: "/", label: "Command Center", permission: "case:read" },
  { to: "/cases", label: "Cases", permission: "case:read" },
  { to: "/evidence", label: "Evidence", permission: "evidence:read" },
  { to: "/intelligence", label: "Intelligence", permission: "analysis:read" },
  { to: "/alerts", label: "Alerts", permission: "alert:read" },
  { to: "/reports", label: "Reports", permission: "report:read" },
  { to: "/audit", label: "Audit Log", permission: "audit:read" },
  { to: "/admin", label: "Administration", permission: "system:read" },
  { to: "/settings", label: "Settings", permission: "case:read" },
];

export function AppShell({ children, crumbs }: { children: React.ReactNode; crumbs?: string[] }) {
  const { user, logout, has } = useAuth();
  const collapsed = useUi((s) => s.railCollapsed);
  const toggleRail = useUi((s) => s.toggleRail);
  const density = useUi((s) => s.density);
  const toggleDensity = useUi((s) => s.toggleDensity);
  const setCommandOpen = useUi((s) => s.setCommandOpen);
  const navigate = useNavigate();

  const notifications = useQuery({
    queryKey: ["notifications"],
    queryFn: () => api<Notification[]>("/notifications"),
    enabled: has("alert:read"),
    refetchInterval: 30_000,
  });
  const unread = (notifications.data ?? []).filter((item) => !item.read_at).length;

  return (
    <div className={`flex min-h-screen bg-canvas ${density === "compact" ? "text-[13px]" : ""}`}>
      <aside
        className={`sticky top-0 flex h-screen shrink-0 flex-col border-r border-line bg-surface ${
          collapsed ? "w-16" : "w-60"
        }`}
      >
        <div className="flex items-center justify-between px-3 py-4">
          <span className="font-semibold tracking-[0.18em] text-accent">{collapsed ? "CT" : "CYBERTRACE"}</span>
          <button className="text-muted hover:text-ink" onClick={toggleRail} aria-label="Collapse navigation">
            {collapsed ? "›" : "‹"}
          </button>
        </div>
        <nav className="flex flex-1 flex-col gap-0.5 px-2">
          {NAV.filter((item) => has(item.permission)).map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) =>
                `rounded-md px-3 py-2 text-sm ${isActive ? "bg-accent-dim text-accent" : "text-muted hover:bg-raised hover:text-ink"}`
              }
              title={item.label}
            >
              {collapsed ? item.label.slice(0, 1) : item.label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-line px-3 py-3 text-xs text-muted">
          {!collapsed && user ? (
            <div>
              <div className="text-ink">{user.full_name}</div>
              <div>{user.roles[0]?.name}</div>
            </div>
          ) : (
            user?.initials
          )}
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 flex items-center gap-3 border-b border-line bg-surface/95 px-4 py-2 backdrop-blur">
          <nav aria-label="Breadcrumb" className="min-w-0 flex-1 truncate text-sm text-muted">
            {["CYBERTRACE", ...(crumbs ?? [])].join(" / ")}
          </nav>
          <Button variant="ghost" onClick={() => setCommandOpen(true)}>
            Search ⌘K
          </Button>
          <Button variant="ghost" onClick={toggleDensity} aria-label="Toggle density">
            {density === "compact" ? "Comfortable" : "Compact"}
          </Button>
          {has("alert:read") ? (
            <button
              className="relative rounded-md px-2 py-1 text-sm text-muted hover:text-ink"
              onClick={() => navigate("/alerts")}
              aria-label={`Alerts${unread ? `, ${unread} unread` : ""}`}
            >
              Bell
              {unread > 0 ? (
                <span className="absolute -right-1 -top-1 rounded-full bg-status-critical px-1 text-[10px] text-canvas">
                  {unread}
                </span>
              ) : null}
            </button>
          ) : null}
          <Button variant="ghost" onClick={() => void logout()}>
            Sign out
          </Button>
        </header>
        <main className="flex-1 p-6">{children}</main>
      </div>
      <CommandPalette />
    </div>
  );
}

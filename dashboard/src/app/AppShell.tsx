import { NavLink, Outlet } from "react-router-dom";
import { useOne } from "../api/queries";
import { useSession } from "../api/session";
import { ThemeToggle } from "../theme/ThemeToggle";
import type { Page } from "../api/client";
import type { Schemas } from "../api/client";

const NAV: { to: string; label: string; role?: "analyst" | "admin" }[] = [
  { to: "/", label: "Overview" },
  { to: "/sessions", label: "Sessions" },
  { to: "/approvals", label: "Approvals", role: "analyst" },
  { to: "/agents", label: "Agents" },
  { to: "/policies", label: "Policies" },
  { to: "/alerts", label: "Alerts" },
  { to: "/settings", label: "Settings" },
];

export function AppShell() {
  const { me, can, logout } = useSession();
  const pending = useOne<Page<Schemas["ApprovalRead"]>>(["pending-count"], "/v1/admin/approvals", { status: "pending", limit: 200 },
    { refetchInterval: 15_000, enabled: can("analyst") });
  const count = pending.data?.items.length ?? 0;
  return (
    <div className="shell">
      <a className="skip" href="#main">Skip to content</a>
      <nav className="rail" aria-label="Main">
        <div className="brand">
          <svg width="22" height="22" viewBox="0 0 32 32" aria-hidden="true"><path d="M16 3l11 4v8c0 7-5 12-11 14C10 27 5 22 5 15V7z" fill="currentColor" /></svg>
          AgentShield
        </div>
        {NAV.filter((n) => !n.role || can(n.role)).map((n) => (
          <NavLink key={n.to} to={n.to} end={n.to === "/"} className="nav">
            {n.label}
            {n.to === "/approvals" && count > 0 && <span className="count" aria-label={`${count} pending`}>{count}</span>}
          </NavLink>
        ))}
        <div className="foot">
          <ThemeToggle />
          <span className="small muted" title={me?.email}>{me?.email}</span>
          <button className="btn quiet" onClick={() => void logout()}>Sign out</button>
        </div>
      </nav>
      <main id="main" tabIndex={-1}><Outlet /></main>
    </div>
  );
}

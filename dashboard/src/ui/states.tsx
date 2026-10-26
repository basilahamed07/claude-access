import type { ReactNode } from "react";
import { ApiProblem } from "../api/client";

export function Skeleton({ rows = 5, label = "Loading" }: { rows?: number; label?: string }) {
  return (
    <div role="status" aria-label={label} className="stack" style={{ padding: "0.5rem 0" }}>
      {Array.from({ length: rows }, (_, i) => <div key={i} className="skel" style={{ width: `${95 - ((i * 13) % 35)}%` }} />)}
    </div>
  );
}

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      <h3>{title}</h3>
      {children && <p className="muted">{children}</p>}
      {action}
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const p = error instanceof ApiProblem ? error : null;
  return (
    <div className="error-state" role="alert">
      <h3>{p?.status === 403 ? "You don't have access to this" : "Could not load this"}</h3>
      <p>{p ? p.detail : "Something went wrong. Try again."}</p>
      {p?.requestId && <p className="muted small">Request {p.requestId}</p>}
      {onRetry && <button className="btn" onClick={onRetry}>Try again</button>}
    </div>
  );
}

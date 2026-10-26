import { Link } from "react-router-dom";
import { useMemo } from "react";
import type { Page, Schemas } from "../../api/client";
import { useOne } from "../../api/queries";
import { useSession } from "../../api/session";
import { DecisionBadge } from "../../ui/DecisionBadge";
import { EmptyState, ErrorState, Skeleton } from "../../ui/states";
import { Value } from "../../ui/Value";
import { DecisionsChart, hourlyBuckets } from "./DecisionsChart";

type Alert = Schemas["AlertRead"];
export const ALERT_WORDS: Record<Alert["kind"], string> = {
  blocked_call: "Action blocked", malicious_content: "Attack found in content", approval_expired: "Approval expired, counted as denied",
  budget_exceeded: "Budget or rate limit hit", audit_gap: "Audit events were delayed",
};

export default function OverviewPage() {
  const { can, loading } = useSession();
  const stats = useOne<Schemas["StatsOverview"]>(["stats"], "/v1/admin/stats/overview", { window: "24h" }, { refetchInterval: 30_000 });
  const approvals = useOne<Page<Schemas["ApprovalRead"]>>(["approvals", "overview"], "/v1/admin/approvals", { status: "pending", limit: 20 }, { refetchInterval: 10_000, enabled: can("analyst") });
  const alerts = useOne<Page<Alert>>(["alerts", "overview"], "/v1/admin/alerts", { limit: 10 }, { refetchInterval: 30_000 });
  const buckets = useMemo(() => hourlyBuckets(stats.data?.series ?? [], Date.now()), [stats.data]);
  const pending = approvals.data?.items ?? [];
  const attention = alerts.data?.items ?? [];

  return (
    <>
      <header><div><h1>Overview</h1><p className="muted">What needs you, then what happened in the last 24 hours.</p></div></header>
      <section aria-labelledby="needs-h" className="stack">
        <h2 id="needs-h">Needs you</h2>
        {loading || (can("analyst") && approvals.isPending) || alerts.isPending ? <Skeleton rows={3} /> : alerts.error ? <ErrorState error={alerts.error} onRetry={() => void alerts.refetch()} />
          : pending.length === 0 && attention.length === 0 ? <EmptyState title="Nothing needs you right now">New blocks, attacks and held actions appear here.</EmptyState> : (
            <ul className="needs">
              {pending.length > 0 && (
                <li className="card row between"><div className="row"><DecisionBadge decision="ask" /><span>{pending.length} {pending.length === 1 ? "action is" : "actions are"} waiting for an approval</span></div>
                  <Link className="btn" to="/approvals">Review approvals</Link></li>
              )}
              {attention.map((a) => (
                <li key={`${a.seq}`} className="card row between">
                  <div className="row">{a.kind === "blocked_call" || a.kind === "malicious_content" ? <DecisionBadge decision="block" /> : <DecisionBadge decision="ask" />}
                    <span>{ALERT_WORDS[a.kind]}{a.agent_slug ? <> on <Value value={a.agent_slug} copy={false} /></> : null}</span>
                    <span className="small muted">{new Date(a.ts).toLocaleString()}</span></div>
                  {a.session_id ? <Link to={`/sessions/${a.session_id}`}>Open the tape</Link> : <Link to="/alerts">All alerts</Link>}
                </li>
              ))}
            </ul>
          )}
      </section>
      <section className="stack" style={{ marginTop: "2rem" }}>
        {stats.isLoading ? <Skeleton rows={6} label="Loading chart" /> : stats.error ? <ErrorState error={stats.error} onRetry={() => void stats.refetch()} />
          : <div className="card"><DecisionsChart buckets={buckets} /></div>}
      </section>
    </>
  );
}

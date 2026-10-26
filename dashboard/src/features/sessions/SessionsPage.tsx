import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { get, type Page, type Schemas } from "../../api/client";
import { useList } from "../../api/queries";
import { DecisionBadge } from "../../ui/DecisionBadge";
import { Table, type Column } from "../../ui/Table";
import { Value } from "../../ui/Value";
import { SessionTape } from "./SessionTape";

type Session = Schemas["SessionRead"];

export default function SessionsPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [agent, setAgent] = useState("");
  const [risky, setRisky] = useState(false);
  const agents = useQuery({ queryKey: ["agents-all"], queryFn: () => get<Page<Schemas["AgentRead"]>>("/v1/admin/agents", { limit: 200 }) });
  const list = useList<Session>(["sessions"], "/v1/admin/sessions", { agent, min_risk: risky ? 0.5 : undefined }, { enabled: !id });
  if (id) return <SessionTape key={id} id={id} />;
  const cols: Column<Session>[] = [
    { key: "outcome", header: "Outcome", render: (s) => s.blocked > 0 ? <DecisionBadge decision="block" /> : s.calls > 0 ? <DecisionBadge decision="allow" /> : <span className="muted">No tool calls</span> },
    { key: "agent", header: "Agent", render: (s) => <Value value={s.agent_slug} copy={false} /> },
    { key: "user", header: "User", render: (s) => s.end_user ? <Value value={s.end_user} copy={false} limit={40} /> : <span className="muted">Not recorded</span> },
    { key: "req", header: "Request", render: (s) => s.user_request ? <Value value={s.user_request} copy={false} limit={80} /> : <span className="muted">Not recorded</span> },
    { key: "risk", header: "Risk", numeric: true, render: (s) => s.risk_score.toFixed(2) },
    { key: "calls", header: "Calls", numeric: true, render: (s) => s.calls },
    { key: "seen", header: "Last seen", render: (s) => new Date(s.last_seen_at).toLocaleString() },
  ];
  return (
    <>
      <header>
        <div><h1>Sessions</h1><p className="muted">Open one to see exactly what the agent did, step by step.</p></div>
        <div className="row">
          <div className="field"><label htmlFor="f-agent">Agent</label>
            <select id="f-agent" value={agent} onChange={(e) => setAgent(e.target.value)}><option value="">All agents</option>
              {agents.data?.items.map((a) => <option key={a.id} value={a.slug}>{a.slug}</option>)}</select></div>
          <label className="row"><input type="checkbox" checked={risky} onChange={(e) => setRisky(e.target.checked)} /> Risk 0.5 and above</label>
        </div>
      </header>
      <Table caption="Sessions" columns={cols} rows={list.rows} rowKey={(s) => s.id} loading={list.isLoading} error={list.error} onRetry={() => void list.refetch()}
        hasMore={list.hasNextPage} loadingMore={list.isFetchingNextPage} onLoadMore={list.loadMore}
        onRowClick={(s) => navigate(`/sessions/${s.id}`)} rowLabel={(s) => `Open session for ${s.agent_slug}`}
        empty={{ title: "No sessions yet", body: "Connect an agent to see its first request here.", action: <button className="btn primary" onClick={() => navigate("/agents")}>Connect agent</button> }} />
    </>
  );
}

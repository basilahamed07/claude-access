import { useState } from "react";
import { Link } from "react-router-dom";
import type { Schemas } from "../../api/client";
import { useList } from "../../api/queries";
import { DecisionBadge } from "../../ui/DecisionBadge";
import { Table, type Column } from "../../ui/Table";
import { Value } from "../../ui/Value";
import { ALERT_WORDS } from "../overview/OverviewPage";

type Alert = Schemas["AlertRead"];
const SEVERITIES = ["info", "low", "medium", "high", "critical"];

export default function AlertsPage() {
  const [kind, setKind] = useState("");
  const [severity, setSeverity] = useState("");
  const [agent, setAgent] = useState("");
  const [hours, setHours] = useState(24);
  const list = useList<Alert>(["alerts"], "/v1/admin/alerts", { kind, since_hours: hours }, { refetchInterval: 15_000 });
  const rows = list.rows?.filter((a) => (!severity || a.severity === severity) && (!agent || a.agent_slug === agent));
  const agents = [...new Set(list.rows?.map((a) => a.agent_slug).filter((x): x is string => !!x))].sort();
  const cols: Column<Alert>[] = [
    { key: "what", header: "What happened", render: (a) => <div className="row">{a.kind === "blocked_call" || a.kind === "malicious_content" ? <DecisionBadge decision="block" /> : <DecisionBadge decision="ask" />}<span>{ALERT_WORDS[a.kind]}</span></div> },
    { key: "sev", header: "Severity", render: (a) => a.severity },
    { key: "agent", header: "Agent", render: (a) => a.agent_slug ? <Value value={a.agent_slug} copy={false} /> : <span className="muted">None</span> },
    { key: "rule", header: "Rule", render: (a) => a.rule_id ? <Value value={a.rule_id} copy={false} /> : <span className="muted">None</span> },
    { key: "sum", header: "Details", render: (a) => <Value value={a.summary} copy={false} limit={100} /> },
    { key: "time", header: "When", render: (a) => new Date(a.ts).toLocaleString() },
    { key: "open", header: "Tape", render: (a) => a.session_id ? <Link to={`/sessions/${a.session_id}?step=${a.seq}`}>Open the tape</Link> : <span className="muted">No session</span> },
  ];
  return (
    <>
      <header>
        <div><h1>Alerts</h1><p className="muted">Derived from the audit log. Each one opens the session where it happened.</p></div>
        <div className="row">
          <div className="field"><label htmlFor="a-kind">Kind</label><select id="a-kind" value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="">All kinds</option>{Object.entries(ALERT_WORDS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></div>
          <div className="field"><label htmlFor="a-sev">Severity</label><select id="a-sev" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">All severities</option>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}</select></div>
          <div className="field"><label htmlFor="a-agent">Agent</label><select id="a-agent" value={agent} onChange={(e) => setAgent(e.target.value)}>
            <option value="">All agents</option>{agents.map((s) => <option key={s}>{s}</option>)}</select></div>
          <div className="field"><label htmlFor="a-when">Period</label><select id="a-when" value={hours} onChange={(e) => setHours(Number(e.target.value))}>
            <option value={24}>Last 24 hours</option><option value={168}>Last 7 days</option><option value={720}>Last 30 days</option></select></div>
        </div>
      </header>
      <Table caption="Alerts" columns={cols} rows={rows} rowKey={(a) => `${a.seq}-${a.kind}`} loading={list.isLoading} error={list.error} onRetry={() => void list.refetch()}
        hasMore={list.hasNextPage} loadingMore={list.isFetchingNextPage} onLoadMore={list.loadMore}
        empty={{ title: "No alerts", body: "Nothing was blocked, flagged or delayed in this period." }} />
    </>
  );
}

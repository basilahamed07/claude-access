import { useState } from "react";
import type { Schemas } from "../../api/client";
import { useSession } from "../../api/session";
import { useList } from "../../api/queries";
import { Table, type Column } from "../../ui/Table";
import { ConnectAgentFlow } from "./ConnectAgentFlow";
import { KeysPanel } from "./KeysPanel";

type Agent = Schemas["AgentRead"];

export default function AgentsPage() {
  const { can } = useSession();
  const list = useList<Agent>(["agents"], "/v1/admin/agents");
  const [connect, setConnect] = useState(false);
  const [selected, setSelected] = useState<Agent | null>(null);
  const cols: Column<Agent>[] = [
    { key: "name", header: "Agent", render: (a) => <div><strong>{a.name}</strong><div className="small muted mono">{a.slug}</div></div> },
    { key: "status", header: "Status", render: (a) => a.status === "active" ? <span className="badge badge--allow">Active</span> : <span className="badge badge--ask">Suspended</span> },
    { key: "mode", header: "Mode", render: (a) => a.mode === "monitor" ? "Monitor only" : "Enforcing" },
    { key: "policy", header: "Policy", render: (a) => a.active_policy_version ? `v${a.active_policy_version}` : <span className="muted">None (default deny)</span> },
    { key: "seen", header: "Last seen", render: (a) => a.last_seen_at ? new Date(a.last_seen_at).toLocaleString() : <span className="muted">Never</span> },
    { key: "keys", header: "Keys", numeric: true, render: (a) => a.key_count },
  ];
  return (
    <>
      <header>
        <div><h1>Agents</h1><p className="muted">Every agent gets its own key, policy and audit trail.</p></div>
        {can("admin") && <button className="btn primary" onClick={() => setConnect(true)}>Connect agent</button>}
      </header>
      <Table caption="Agents" columns={cols} rows={list.rows} rowKey={(a) => a.id} loading={list.isLoading} error={list.error} onRetry={() => void list.refetch()}
        hasMore={list.hasNextPage} loadingMore={list.isFetchingNextPage} onLoadMore={list.loadMore}
        onRowClick={can("admin") ? setSelected : undefined} rowLabel={(a) => `Manage keys for ${a.name}`}
        empty={{ title: "No agents yet", body: "Connect an agent to see its first request here.", action: can("admin") ? <button className="btn primary" onClick={() => setConnect(true)}>Connect agent</button> : undefined }} />
      <ConnectAgentFlow open={connect} onClose={() => setConnect(false)} />
      <KeysPanel agent={selected} onClose={() => setSelected(null)} />
    </>
  );
}

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { get, type Schemas } from "../../api/client";
import { useSession } from "../../api/session";
import { Table, type Column } from "../../ui/Table";
import { Value } from "../../ui/Value";
import { RegisterServer } from "./RegisterServer";
import { ServerReport } from "./ServerReport";
import { VerdictBadge } from "./VerdictBadge";

type Server = Schemas["McpServerRead"];

export default function McpPage() {
  const { can } = useSession();
  const { id } = useParams();
  const navigate = useNavigate();
  const [registering, setRegistering] = useState(false);
  const list = useQuery({ queryKey: ["mcp", "list"], queryFn: () => get<Server[]>("/v1/admin/mcp-servers"), refetchInterval: 30_000 });
  const cols: Column<Server>[] = [
    { key: "name", header: "Server", render: (s) => <div><strong>{s.name}</strong><div className="small muted">{s.url ? <Value value={s.url} copy={false} limit={60} /> : "Pasted tool list"}</div></div> },
    { key: "verdict", header: "Verdict", render: (s) => <VerdictBadge verdict={s.verdict} /> },
    { key: "tools", header: "Tools", numeric: true, render: (s) => s.allowed_tools ? `${s.allowed_tools.length} of ${s.tool_count}` : s.tool_count },
    { key: "owner", header: "Owner", render: (s) => <Value value={s.owner} copy={false} limit={40} /> },
    { key: "scanned", header: "Last scanned", render: (s) => s.scanned_at ? new Date(s.scanned_at).toLocaleString() : <span className="muted">Never</span> },
  ];
  return (
    <>
      <header>
        <div><h1>MCP servers</h1><p className="muted">Tool servers your agents may use. Each is scanned, then approved by a person; if it changes afterwards it is suspended.</p></div>
        {can("analyst") && <button className="btn primary" onClick={() => setRegistering(true)}>Register server</button>}
      </header>
      <Table caption="MCP servers" columns={cols} rows={list.data} rowKey={(s) => s.id} loading={list.isLoading} error={list.error} onRetry={() => void list.refetch()}
        onRowClick={(s) => navigate(`/mcp/${s.id}`)} rowLabel={(s) => `Open ${s.name}`}
        empty={{ title: "No MCP servers yet", body: "Register a server to scan its tools before an agent uses it.", action: can("analyst") ? <button className="btn primary" onClick={() => setRegistering(true)}>Register server</button> : undefined }} />
      <p className="small muted" style={{ marginTop: "1rem" }}>Agents reach approved servers through <code>{window.location.origin.replace(":5173", ":8000")}/mcp/&lt;agent id&gt;</code> with their AgentShield key. Policy rules apply to every call and results are scanned before the agent reads them.</p>
      <RegisterServer open={registering} onClose={() => setRegistering(false)} onDone={(newId) => { setRegistering(false); navigate(`/mcp/${newId}`); }} />
      {id && <ServerReport key={id} id={id} onClose={() => navigate("/mcp")} />}
    </>
  );
}

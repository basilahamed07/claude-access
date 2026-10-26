import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiProblem, get, patch, type Schemas } from "../../api/client";
import { useSession } from "../../api/session";
import { Table, type Column } from "../../ui/Table";
import { useToast } from "../../ui/toast";
import { Value } from "../../ui/Value";
import { TokenDialog } from "./TokenDialog";
import { UploadDialog } from "./UploadDialog";

type Tool = Schemas["AiToolRead"];
type Cls = Tool["classification"];
const WORDS: Record<Cls, string> = { unknown: "Not reviewed", approved: "Approved", tolerated: "Tolerated", blocked: "Blocked" };
const FILTERS: [string, string][] = [["", "All"], ["unknown", "Not reviewed"], ["blocked", "Blocked"], ["tolerated", "Tolerated"], ["approved", "Approved"]];
const ACTIONS: [Exclude<Cls, "unknown">, string][] = [["approved", "Approve"], ["tolerated", "Tolerate"], ["blocked", "Block"]];

export default function ShadowPage() {
  const { can } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  const [filter, setFilter] = useState("");
  const [upload, setUpload] = useState(false);
  const [token, setToken] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const list = useQuery({ queryKey: ["shadow", filter], queryFn: () => get<Tool[]>("/v1/admin/ai-tools", { classification: filter }), refetchInterval: 30_000 });
  const classify = useMutation({
    mutationFn: ({ id, classification }: { id: string; classification: Exclude<Cls, "unknown"> }) => patch<Tool>(`/v1/admin/ai-tools/${id}`, { classification }),
    onSuccess: (t) => { toast(`${t.domain}: ${WORDS[t.classification].toLowerCase()}`); setError(null); void qc.invalidateQueries({ queryKey: ["shadow"] }); },
    onError: (e) => setError(e instanceof ApiProblem ? e.detail : "Could not save the classification."),
  });
  const cols: Column<Tool>[] = [
    { key: "tool", header: "AI tool", render: (t) => <div><strong><Value value={t.domain} copy={false} limit={50} /></strong><div className="small muted">{t.vendor ?? "Not in the catalog"} · {t.reason?.startsWith("heuristic") ? "found by its API path" : "known service"}</div></div> },
    { key: "cls", header: "Status", render: (t) => <span className={`badge ${t.classification === "blocked" ? "badge--block" : t.classification === "approved" ? "badge--allow" : "badge--ask"}`}>{WORDS[t.classification]}</span> },
    { key: "team", header: "Team", render: (t) => t.team ?? "unassigned" },
    { key: "users", header: "People", numeric: true, render: (t) => `about ${t.users_count}` },
    { key: "hits", header: "Requests", numeric: true, render: (t) => t.hits.toLocaleString() },
    { key: "last", header: "Last seen", render: (t) => new Date(t.last_seen).toLocaleString() },
    ...(can("admin") ? [{ key: "act", header: "Decide", render: (t: Tool) => (
      <div className="row">{ACTIONS.filter(([c]) => c !== t.classification).map(([c, label]) => (
        <button key={c} className="btn" aria-label={`${label} ${t.domain}`} disabled={classify.isPending} onClick={() => classify.mutate({ id: t.id, classification: c })}>{label}</button>))}</div>) } satisfies Column<Tool>] : []),
  ];
  return (
    <>
      <header>
        <div><h1>Shadow AI</h1><p className="muted">AI tools your people use, found in your proxy or DNS logs. This sees which tools and how often, not what was typed into them.</p></div>
        {can("analyst") && <div className="row"><button className="btn" onClick={() => setToken(true)}>Create ingest token</button><button className="btn primary" onClick={() => setUpload(true)}>Upload a log file</button></div>}
      </header>
      <div className="row" role="group" aria-label="Filter by status">
        {FILTERS.map(([v, label]) => <button key={v} className={`btn ${filter === v ? "primary" : "quiet"}`} aria-pressed={filter === v} onClick={() => setFilter(v)}>{label}</button>)}
      </div>
      {error && <p role="alert" className="field"><span className="err">{error}</span></p>}
      <Table caption="AI tools seen" columns={cols} rows={list.data} rowKey={(t) => t.id} loading={list.isLoading} error={list.error} onRetry={() => void list.refetch()}
        empty={{ title: "No AI tools seen yet", body: "Upload a proxy or DNS log, or point your log shipper at the ingest endpoint with a token.", action: can("analyst") ? <button className="btn primary" onClick={() => setUpload(true)}>Upload a log file</button> : undefined }} />
      <p className="small muted" style={{ marginTop: "1rem" }}>Counts of people are estimates and names are never stored. Approving a tool does not route it through AgentShield; connect it to the gateway for that.</p>
      <UploadDialog open={upload} onClose={() => setUpload(false)} />
      <TokenDialog open={token} onClose={() => setToken(false)} />
    </>
  );
}

import { useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { ApiProblem, type Schemas } from "../../api/client";
import { useList } from "../../api/queries";
import { useSession } from "../../api/session";
import { Table, type Column } from "../../ui/Table";
import { Value } from "../../ui/Value";
import { ErrorState } from "../../ui/states";
import { ApprovalDrawer, StatusLine } from "./ApprovalDrawer";
import { Countdown } from "./Countdown";

type Approval = Schemas["ApprovalRead"];
const STATUSES = [["pending", "Pending"], ["approved", "Approved"], ["denied", "Denied"], ["expired", "Expired"]] as const;

export default function ApprovalsPage() {
  const { can } = useSession();
  const { id } = useParams();
  const navigate = useNavigate();
  const [status, setStatus] = useState<(typeof STATUSES)[number][0]>("pending");
  const list = useList<Approval>(["approvals"], "/v1/admin/approvals", { status }, { refetchInterval: 5000 });
  const rows = useMemo(() => status === "pending" ? [...(list.rows ?? [])].sort((a, b) => a.expires_at.localeCompare(b.expires_at)) : list.rows, [list.rows, status]);
  if (!can("analyst")) return <ErrorState error={new ApiProblem(403, "forbidden", "Deciding approvals needs the analyst role.")} />;
  const cols: Column<Approval>[] = [
    { key: "left", header: status === "pending" ? "Time left" : "Outcome", render: (a) => a.status === "pending" ? <Countdown expiresAt={a.expires_at} /> : <StatusLine a={a} /> },
    { key: "agent", header: "Agent", render: (a) => <Value value={a.agent_slug} copy={false} /> },
    { key: "tool", header: "Tool", render: (a) => <Value value={a.tool} copy={false} /> },
    { key: "args", header: "Arguments", render: (a) => <Value value={a.args_redacted} limit={80} copy={false} /> },
    { key: "rule", header: "Rule", render: (a) => <Value value={a.rule_id} copy={false} /> },
  ];
  return (
    <>
      <header>
        <div><h1>Approvals</h1><p className="muted">Actions your policies held for a person. Unanswered requests expire after 5 minutes and count as denied.</p></div>
        <div className="field"><label htmlFor="st">Show</label>
          <select id="st" value={status} onChange={(e) => setStatus(e.target.value as typeof status)}>{STATUSES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></div>
      </header>
      <Table caption="Approvals" columns={cols} rows={rows} rowKey={(a) => a.id} loading={list.isLoading} error={list.error} onRetry={() => void list.refetch()}
        hasMore={list.hasNextPage} loadingMore={list.isFetchingNextPage} onLoadMore={list.loadMore}
        onRowClick={(a) => navigate(`/approvals/${a.id}`)} rowLabel={(a) => `Review ${a.tool} from ${a.agent_slug}`}
        empty={{ title: status === "pending" ? "Nothing is waiting for you" : "No approvals here", body: status === "pending" ? "When a policy holds an action for a person, it appears here." : undefined }} />
      {id && <ApprovalDrawer key={id} id={id} onClose={() => navigate("/approvals")} />}
    </>
  );
}

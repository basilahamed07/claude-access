import { useMutation, useQuery } from "@tanstack/react-query";
import { ApiProblem, get, post, type Schemas } from "../../api/client";
import { useToast } from "../../ui/toast";

type Replay = Schemas["ReplayResult"];

/** "Re-check with policy vN": changed decisions come back as ghost marks on the tape. */
export function ReplayControls({ sessionId, agentSlug, version, onVersion, onResult, result }: {
  sessionId: string; agentSlug: string; version: number | null; onVersion: (v: number | null) => void; onResult: (r: Replay | null) => void; result: Replay | null;
}) {
  const toast = useToast();
  const versions = useQuery({ queryKey: ["versions", agentSlug], queryFn: () => get<Schemas["PolicyVersionRead"][]>(`/v1/admin/agents/${agentSlug}/policy/versions`) });
  const run = useMutation({
    mutationFn: (v: number) => post<Replay>(`/v1/admin/sessions/${sessionId}/replay`, { policy_version: v }),
    onSuccess: (r) => onResult(r),
    onError: (e) => toast(e instanceof ApiProblem ? e.detail : "Could not re-check this session", true),
  });
  return (
    <div className="row" role="group" aria-label="Re-check with another policy">
      <div className="field"><label htmlFor="replay-v">Re-check with policy</label>
        <select id="replay-v" value={version ?? ""} onChange={(e) => { onResult(null); onVersion(e.target.value ? Number(e.target.value) : null); }}>
          <option value="">Choose a version</option>
          {versions.data?.map((v) => <option key={v.version} value={v.version}>v{v.version}{v.active ? " (active)" : ""}</option>)}
        </select></div>
      <button className="btn" disabled={version === null || run.isPending} onClick={() => version !== null && run.mutate(version)}>{run.isPending ? "Checking" : "Re-check"}</button>
      {result && <span role="status">{result.changed === 0 ? `No decision would change under v${result.policy_version}.` : `${result.changed} ${result.changed === 1 ? "decision" : "decisions"} would change under v${result.policy_version}.`}</span>}
    </div>
  );
}

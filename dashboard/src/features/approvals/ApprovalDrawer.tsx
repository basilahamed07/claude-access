import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ApiProblem, apiRaw, get, post, type Schemas } from "../../api/client";
import { Drawer } from "../../ui/Drawer";
import { Value } from "../../ui/Value";
import { Skeleton } from "../../ui/states";
import { useToast } from "../../ui/toast";
import { Countdown } from "./Countdown";
import { loadDraft, saveDraft } from "./draft";

type Approval = Schemas["ApprovalRead"];
type Verb = "approve" | "deny";

/**
 * What the reviewer sees is what the agent literally sent: tool name and redacted arguments, the rule that
 * held it and the session's risk. No model-written text is fetched or shown here, so injected prose cannot steer the decision.
 */
export function ApprovalDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const q = useQuery({ queryKey: ["approval", id], queryFn: () => apiRaw<Approval>("GET", `/v1/admin/approvals/${id}`), refetchInterval: 5000 });
  const a = q.data?.data;
  const session = useQuery({ queryKey: ["session-risk", a?.session_id], enabled: !!a, queryFn: () => get<Schemas["SessionRead"]>(`/v1/admin/sessions/${a!.session_id}`) });
  const [note, setNote] = useState(() => loadDraft(id));
  const [confirm, setConfirm] = useState<Verb | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => { saveDraft(id, note); }, [id, note]);

  const refresh = useCallback(() => {
    void qc.invalidateQueries({ queryKey: ["approval", id] });
    void qc.invalidateQueries({ queryKey: ["approvals"] });
    void qc.invalidateQueries({ queryKey: ["pending-count"] });
  }, [qc, id]);

  const decide = useMutation({
    mutationFn: (verb: Verb) => post<Approval>(`/v1/admin/approvals/${id}/decision`, { approve: verb === "approve", note: note.trim() || null },
      q.data?.etag ? { "If-Match": q.data.etag } : { "If-Match": "*" }),
    onSuccess: (r, verb) => { saveDraft(id, ""); toast(verb === "approve" ? "Approved" : "Denied"); setConfirm(null); refresh(); void r; onClose(); },
    onError: (e) => {
      setConfirm(null);
      if (e instanceof ApiProblem && (e.status === 409 || e.status === 412)) {
        setMessage(e.status === 409 ? e.detail.replace(/^This approval was already (\w+) by (.+)$/, "Already $1 by $2") : "This approval changed while you were reading it. Review it again.");
        refresh();
      } else if (!(e instanceof ApiProblem && e.status === 401)) toast(e instanceof ApiProblem ? e.detail : "Could not record the decision", true);
    },
  });

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null;
      if (el && (el.tagName === "TEXTAREA" || el.tagName === "INPUT" || el.isContentEditable)) return;
      if (e.metaKey || e.ctrlKey || e.altKey || !a || a.status !== "pending") return;
      if (e.key === "a") setConfirm("approve");
      else if (e.key === "d") setConfirm("deny");
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [a]);

  const pending = a?.status === "pending";
  return (
    <Drawer open onClose={onClose} title={a ? `Approve ${a.tool}?` : "Approval"}>
      {q.isLoading ? <Skeleton rows={6} /> : q.error || !a ? <p role="alert">{q.error instanceof ApiProblem ? q.error.detail : "Could not load this approval."}</p> : (
        <>
          {message && <div role="alert" className="error-state"><p>{message}</p></div>}
          <dl className="defs">
            <dt>Agent</dt><dd><Value value={a.agent_slug} copy={false} /></dd>
            <dt>Tool</dt><dd><Value value={a.tool} copy={false} /></dd>
            <dt>Arguments</dt>
            <dd>{Object.keys(a.args_redacted).length === 0 ? <span className="muted">None</span> : (
              <dl className="defs">{Object.entries(a.args_redacted).map(([k, v]) => <div key={k} style={{ display: "contents" }}><dt><code>{k}</code></dt><dd><Value value={v} block /></dd></div>)}</dl>
            )}</dd>
            <dt>Held by rule</dt><dd><Value value={a.rule_id} copy={false} /></dd>
            <dt>Session risk</dt><dd>{session.data ? <span>{session.data.risk_score.toFixed(2)}</span> : <span className="muted">Loading</span>}</dd>
            <dt>Time left</dt><dd>{pending ? <Countdown expiresAt={a.expires_at} onExpire={refresh} /> : <StatusLine a={a} />}</dd>
            <dt>Session</dt><dd><Link to={`/sessions/${a.session_id}`}>Open the session tape</Link></dd>
          </dl>
          {pending && (
            <div className="stack">
              <div className="field"><label htmlFor="note">Note (optional)</label>
                <textarea id="note" value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} /></div>
              {confirm ? (
                <div className="card row" role="group" aria-label="Confirm decision">
                  <span className="grow">{confirm === "approve" ? "Approve this action? It will run." : "Deny this action? It will not run."}</span>
                  <button className="btn primary" onClick={() => decide.mutate(confirm)} disabled={decide.isPending} autoFocus>{confirm === "approve" ? "Approve" : "Deny"}</button>
                  <button className="btn quiet" onClick={() => setConfirm(null)}>Cancel</button>
                </div>
              ) : (
                <div className="row">
                  <button className="btn primary" onClick={() => decide.mutate("approve")} disabled={decide.isPending}>Approve</button>
                  <button className="btn" onClick={() => decide.mutate("deny")} disabled={decide.isPending}>Deny</button>
                  <span className="small muted">Keys: a to approve, d to deny (asks you to confirm)</span>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </Drawer>
  );
}

export function StatusLine({ a }: { a: Pick<Approval, "status" | "decided_by_email" | "note"> }) {
  if (a.status === "expired") return <span>Expired. Counted as denied.</span>;
  const who = a.decided_by_email ? ` by ${a.decided_by_email}` : "";
  return <span>{a.status === "approved" ? "Approved" : "Denied"}{who}{a.note ? `: ${a.note}` : ""}</span>;
}

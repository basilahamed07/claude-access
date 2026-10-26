import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiProblem, del, get, post, type Schemas } from "../../api/client";
import { useSession } from "../../api/session";
import { ConfirmTyped } from "../../ui/ConfirmTyped";
import { Drawer } from "../../ui/Drawer";
import { Value } from "../../ui/Value";
import { Skeleton } from "../../ui/states";
import { useToast } from "../../ui/toast";
import { useQuery } from "@tanstack/react-query";
import { VerdictBadge } from "./VerdictBadge";

type Detail = Schemas["McpServerDetail"];
type Finding = { check: string; severity: string; message: string; tool?: string | null; excerpt?: string };

const SEVERITY_WORD: Record<string, string> = { high: "High", medium: "Medium", low: "Low", info: "Info" };

export function ServerReport({ id, onClose }: { id: string; onClose: () => void }) {
  const { can } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  const q = useQuery({ queryKey: ["mcp", id], queryFn: () => get<Detail>(`/v1/admin/mcp-servers/${id}`) });
  const [limited, setLimited] = useState<string[] | null>(null);
  const [ack, setAck] = useState(false);
  const [removing, setRemoving] = useState(false);
  const d = q.data;
  const report = (d?.report ?? {}) as { findings?: Finding[]; checks?: { id: string; name: string; ran: boolean }[]; limitations?: string[]; recommended_verdict?: string; capabilities?: Record<string, string[]>; error?: string };
  const refresh = () => { void qc.invalidateQueries({ queryKey: ["mcp"] }); };
  const fail = (e: unknown) => toast(e instanceof ApiProblem ? e.detail : "That did not work. Try again.", true);

  const approve = useMutation({
    mutationFn: () => post<Detail>(`/v1/admin/mcp-servers/${id}/approve`, { allowed_tools: limited, acknowledge_findings: ack }),
    onSuccess: () => { toast("Server approved"); refresh(); },
    onError: fail,
  });
  const reject = useMutation({ mutationFn: () => post<Detail>(`/v1/admin/mcp-servers/${id}/reject`), onSuccess: () => { toast("Server rejected"); refresh(); }, onError: fail });
  const rescan = useMutation({ mutationFn: () => post<Detail>(`/v1/admin/mcp-servers/${id}/scan`, {}), onSuccess: () => { toast("Scan finished"); refresh(); }, onError: fail });
  const check = useMutation({
    mutationFn: () => post<{ status: string; verdict: string }>(`/v1/admin/mcp-servers/${id}/check`),
    onSuccess: (r) => { toast(r.status === "unchanged" ? "No changes since approval" : r.status === "drifted" ? "The server changed and is now suspended" : r.status === "unreachable" ? "The server could not be reached" : "Only approved servers can be checked", r.status !== "unchanged"); refresh(); },
    onError: fail,
  });
  const remove = useMutation({ mutationFn: () => del(`/v1/admin/mcp-servers/${id}`), onSuccess: () => { toast("Server removed"); refresh(); setRemoving(false); onClose(); }, onError: fail });

  const names = (d?.tools ?? []).map((t) => String((t as { name: string }).name));
  const canApprove = can("admin") && !!d?.fingerprint;
  const chosen = limited ?? names;
  const needsAck = report.recommended_verdict === "rejected";

  return (
    <>
      <Drawer open onClose={onClose} title={d ? `MCP server ${d.name}` : "MCP server"} wide>
        {q.isLoading || !d ? <Skeleton rows={8} /> : (
          <>
            <dl className="defs">
              <dt>Verdict</dt><dd><VerdictBadge verdict={d.verdict} /></dd>
              <dt>Recommended</dt><dd>{report.recommended_verdict ? report.recommended_verdict.replaceAll("_", " ") : "No scan yet"}</dd>
              <dt>Owner</dt><dd><Value value={d.owner} copy={false} /></dd>
              {d.purpose && <><dt>Purpose</dt><dd><Value value={d.purpose} copy={false} /></dd></>}
              <dt>Address</dt><dd>{d.url ? <Value value={d.url} /> : <span className="muted">Registered from a pasted tool list</span>}</dd>
              <dt>Declared</dt><dd>{d.declared_capabilities?.length ? d.declared_capabilities.join(", ") : "Nothing: any capability is a finding"}</dd>
              <dt>Fingerprint</dt><dd>{d.fingerprint ? <Value value={d.fingerprint} /> : <span className="muted">None</span>}</dd>
              {d.approved_fingerprint && <><dt>Approved</dt><dd><Value value={d.approved_fingerprint} /></dd></>}
            </dl>
            {d.verdict === "suspended" && <div role="alert" className="error-state"><p>This server changed after it was approved, so agents can no longer use it. Review the new scan and approve it again, or reject it.</p></div>}
            {report.error && <div role="alert" className="error-state"><p>The last scan failed: {report.error}</p></div>}

            <section aria-labelledby="f-h" className="stack"><h3 id="f-h">Findings</h3>
              {(report.findings ?? []).length === 0 ? <p className="muted">No findings.</p> : (
                <div className="table-wrap" role="region" aria-label="Findings" tabIndex={0}><table>
                  <thead><tr><th>Severity</th><th>Check</th><th>What was found</th></tr></thead>
                  <tbody>{(report.findings ?? []).map((f, i) => (
                    <tr key={i}><td>{f.severity === "high" ? <span className="badge badge--block">{SEVERITY_WORD.high}</span> : SEVERITY_WORD[f.severity] ?? f.severity}</td><td>{f.check.replaceAll("_", " ")}</td>
                      <td><Value value={f.message} copy={false} limit={240} />{f.excerpt ? <div className="small muted">Excerpt: <Value value={f.excerpt} copy={false} limit={160} /></div> : null}</td></tr>))}</tbody></table></div>)}
            </section>

            <section aria-labelledby="c-h" className="stack"><h3 id="c-h">Checks</h3>
              <ul style={{ margin: 0, paddingLeft: "1.25rem" }}>{(report.checks ?? []).map((c) => <li key={c.id}>{c.name}: <strong>{c.ran ? "ran" : "not run"}</strong></li>)}</ul>
              {(report.limitations ?? []).map((l, i) => <p key={i} className="small muted">{l}</p>)}
            </section>

            <section aria-labelledby="t-h" className="stack"><h3 id="t-h">Tools ({names.length})</h3>
              <ul className="stack" style={{ listStyle: "none", padding: 0, margin: 0 }}>{names.map((n) => (
                <li key={n} className="row">
                  {can("admin") && d.verdict !== "rejected" && <input type="checkbox" aria-label={`Allow ${n}`} checked={chosen.includes(n)} onChange={() => setLimited(chosen.includes(n) ? chosen.filter((x) => x !== n) : [...chosen, n])} />}
                  <code className="mono">{n}</code>
                  {(report.capabilities?.[n] ?? []).length > 0 && <span className="small muted">can: {report.capabilities![n].join(", ")}</span>}
                </li>))}</ul>
            </section>

            {can("analyst") && (
              <div className="row">
                <button className="btn" onClick={() => rescan.mutate()} disabled={rescan.isPending}>Scan again</button>
                <button className="btn" onClick={() => check.mutate()} disabled={check.isPending || !d.url}>Check for changes</button>
              </div>)}
            {can("admin") && (
              <div className="card stack">
                {needsAck && <label className="row"><input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} /> I have read the findings and still want to approve this server</label>}
                <div className="row">
                  <button className="btn primary" disabled={!canApprove || approve.isPending || (needsAck && !ack) || chosen.length === 0} onClick={() => approve.mutate()}>
                    {chosen.length === names.length ? "Approve server" : `Approve with limits (${chosen.length} of ${names.length} tools)`}</button>
                  <button className="btn" onClick={() => reject.mutate()} disabled={reject.isPending || d.verdict === "rejected"}>Reject server</button>
                  <button className="btn quiet" onClick={() => setRemoving(true)}>Remove server</button>
                </div>
              </div>)}
          </>
        )}
      </Drawer>
      <ConfirmTyped open={removing} onClose={() => setRemoving(false)} onConfirm={() => remove.mutate()} title="Remove this server?" phrase={d?.name ?? ""} action="Remove server" busy={remove.isPending}>
        <p>Agents lose access to its tools immediately.</p></ConfirmTyped>
    </>
  );
}

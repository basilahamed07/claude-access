import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ApiProblem, apiRaw, get, post, type Schemas } from "../../api/client";
import { useSession } from "../../api/session";
import { DecisionBadge } from "../../ui/DecisionBadge";
import { Modal } from "../../ui/Modal";
import { ErrorState, Skeleton } from "../../ui/states";
import { useToast } from "../../ui/toast";
import { ReplayControls } from "./ReplayControls";
import { StepDrawer } from "./StepDrawer";
import { LANES, placementOf } from "./TapeLane";
import { VirtualRows } from "./VirtualRows";
import { describe, flatten, ghostsFor, isBlocked, timeOf, type TapeEvent } from "./tape";

type Replay = Schemas["ReplayResult"];
type Export = Schemas["SessionExport"];

export function SessionTape({ id }: { id: string }) {
  const { can } = useSession();
  const analyst = can("analyst");
  const qc = useQueryClient();
  const toast = useToast();
  const [params] = useSearchParams();
  const [live, setLive] = useState(false);
  const [cursor, setCursor] = useState(0);
  const [open, setOpen] = useState<TapeEvent | null>(null);
  const [version, setVersion] = useState<number | null>(null);
  const [replay, setReplay] = useState<Replay | null>(null);
  const [incident, setIncident] = useState(false);
  const [title, setTitle] = useState("");
  const seen = useRef<Set<number> | null>(null);

  const tl = useQuery({ queryKey: ["timeline", id], queryFn: () => get<Schemas["Timeline"]>(`/v1/admin/sessions/${id}/timeline`), refetchInterval: live ? 3000 : false });
  const ex = useQuery({ queryKey: ["export", id], enabled: analyst && !!tl.data, staleTime: 60_000, queryFn: () => get<Export>(`/v1/admin/sessions/${id}/export.json`) });
  const events = useMemo(() => (tl.data ? flatten(tl.data) : []), [tl.data]);
  const ghosts = useMemo(() => (replay ? ghostsFor(events, replay.steps) : new Map()), [events, replay]);

  // the first load is the baseline; anything arriving after it draws in
  const fresh = useMemo(() => {
    const now = new Set(events.map((e) => e.seq));
    if (seen.current === null) return new Set<number>();
    return new Set([...now].filter((s) => !seen.current!.has(s)));
  }, [events]);
  useEffect(() => { if (events.length) seen.current = new Set(events.map((e) => e.seq)); }, [events]);
  // follow the end of the tape in live mode
  const count = events.length;
  const lastCount = useRef(0);
  useEffect(() => { if (live && count > lastCount.current) setCursor(count - 1); lastCount.current = count; }, [live, count]);

  // ?step=<seq> puts the cursor on that step
  const stepParam = params.get("step");
  useEffect(() => {
    if (stepParam && events.length) { const i = events.findIndex((e) => e.seq >= Number(stepParam)); if (i >= 0) setCursor(i); }
  }, [stepParam, events]);

  const mark = useMutation({
    mutationFn: () => post<Schemas["IncidentRead"]>("/v1/admin/incidents", { session_id: id, title: title.trim(), severity: "high" }),
    onSuccess: () => { toast("Incident created"); setIncident(false); setTitle(""); void qc.invalidateQueries({ queryKey: ["incidents"] }); },
    onError: (e) => toast(e instanceof ApiProblem ? e.detail : "Could not create the incident", true),
  });

  if (tl.isLoading) return <Skeleton rows={8} label="Loading session" />;
  if (tl.error || !tl.data) return <ErrorState error={tl.error} onRetry={() => void tl.refetch()} />;
  const s = tl.data.session;

  const download = async () => {
    const data = ex.data ?? (await apiRaw<Export>("GET", `/v1/admin/sessions/${id}/export.json`)).data;
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
    const a = document.createElement("a");
    a.href = url; a.download = `agentshield-session-${id}.json`; a.click();
    URL.revokeObjectURL(url);
  };

  const v = ex.data?.verification;
  const chain = !analyst ? null : ex.isLoading ? "Checking the chain" : ex.error ? "Chain not checked" : v?.verified ? `Chain verified (${v.checked} events)` : `Chain broken at seq ${v?.first_bad_seq}`;
  const head = ex.data?.chain_head?.last_hash ? String(ex.data.chain_head.last_hash) : null;

  return (
    <div className="stack">
      <div><Link to="/sessions">Back to sessions</Link></div>
      <header style={{ marginBottom: 0 }}>
        <div>
          <h1>Session tape</h1>
          <dl className="defs" style={{ marginTop: "0.5rem" }}>
            <dt>Agent</dt><dd><code>{s.agent_slug}</code></dd>
            <dt>Request</dt><dd>{s.user_request ? <span className="value">{s.user_request.slice(0, 200)}{s.user_request.length > 200 ? "…" : ""}</span> : <span className="muted">Not recorded</span>}</dd>
            <dt>Risk</dt><dd>{s.risk_score.toFixed(2)}</dd>
          </dl>
        </div>
        <div className="row" style={{ marginTop: "0.5rem" }}>
          <label className="row"><input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} /> Live</label>
          <button className="btn" onClick={() => setCursor((c) => Math.max(0, c - 1))} disabled={cursor === 0}>Previous step</button>
          <button className="btn" onClick={() => setCursor((c) => Math.min(count - 1, c + 1))} disabled={cursor >= count - 1}>Next step</button>
        </div>
      </header>
      {analyst && <ReplayControls sessionId={id} agentSlug={s.agent_slug} version={version} onVersion={(x) => { setVersion(x); setReplay(null); }} onResult={setReplay} result={replay} />}

      {count === 0 ? <div className="empty"><h3>No events recorded for this session</h3><p className="muted">Events appear here within a few seconds of the agent's next request.</p></div> : (
        <div className="tape">
          <div className="thead" aria-hidden="true"><span>Time</span>{LANES.map((l) => <span key={l}>{l}</span>)}</div>
          <VirtualRows count={count} cursor={cursor} onCursor={setCursor} onOpen={(i) => setOpen(events[i])} label="Session events"
            renderRow={(i, active) => <Row e={events[i]} index={i} active={active} fresh={fresh.has(events[i].seq)} ghost={ghosts.get(events[i].seq)} version={replay?.policy_version ?? null} />} />
          <p className="small muted">Arrow keys step through the tape. Enter opens the recorded payload.</p>
        </div>
      )}

      <div className="row between tape-foot">
        <span role="status">{chain}{head ? <> · head <code className="mono">{head.slice(0, 8)}…</code></> : null}</span>
        <div className="row">
          {analyst && <button className="btn" onClick={() => void download()}>Export JSON</button>}
          {analyst && <button className="btn" onClick={() => { setTitle(`Session ${s.agent_slug}`); setIncident(true); }}>Mark as incident</button>}
        </div>
      </div>

      <StepDrawer event={open} canSeePayload={analyst} onClose={() => setOpen(null)} />
      <Modal open={incident} onClose={() => setIncident(false)} title="Mark as incident">
        <p>Incident sessions keep their recorded payloads for 3 years instead of 30 days.</p>
        <div className="field"><label htmlFor="inc-title">Title</label><input id="inc-title" type="text" maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} /></div>
        <div className="row"><button className="btn primary" disabled={!title.trim() || mark.isPending} onClick={() => mark.mutate()}>Mark as incident</button>
          <button className="btn quiet" onClick={() => setIncident(false)}>Cancel</button></div>
      </Modal>
    </div>
  );
}

export function Row({ e, index, active, fresh, ghost, version }: { e: TapeEvent; index: number; active: boolean; fresh: boolean; ghost?: Schemas["ReplayStep"]; version: number | null }) {
  const place = placementOf(e.type);
  const blocked = isBlocked(e);
  const cls = `trow${blocked ? " is-blocked" : ""}${active ? " is-active" : ""}${fresh ? " draw" : ""}`;
  return (
    <div className={cls} id={`tape-row-${index}`} role="gridcell" aria-selected={active} aria-label={`${timeOf(e.ts)} ${describe(e)}`}>
      <span className="ttime">{timeOf(e.ts)}</span>
      {place.kind === "rule" ? (
        <span className="trule">{e.severity === "info" ? "" : `${e.severity}: `}{e.summary}</span>
      ) : LANES.map((l) => (
        <span key={l} className="tcell" data-lane={l}>
          {l === place.lane && (
            <span className="mark">
              <span className="lane-tag">{l}</span>
              {e.decision ? <DecisionBadge decision={e.decision} /> : null}
              <span className="mtext" title={describe(e)}>{describe(e)}</span>
            </span>
          )}
          {l === "Policy" && ghost && (
            <span className="ghost" title={`Under policy v${version} this would be ${ghost.replay_decision}`}>
              <span className="sr-only">Would be </span><DecisionBadge decision={ghost.replay_decision} />
              <span className="small muted">v{version}</span>
            </span>
          )}
        </span>
      ))}
    </div>
  );
}

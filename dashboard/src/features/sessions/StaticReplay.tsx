import { useEffect, useState } from "react";
import type { Schemas } from "../../api/client";
import { StepDrawer } from "./StepDrawer";
import { Row } from "./SessionTape";
import { LANES } from "./TapeLane";
import { VirtualRows } from "./VirtualRows";
import type { TapeEvent } from "./tape";
import { ThemeToggle } from "../../theme/ThemeToggle";

type Recording = Schemas["SessionExport"];

/** A read-only tape of one recorded session, loaded from a bundled JSON file. It makes no network calls except for that file. */
export function StaticReplay({ src = "./replay.json" }: { src?: string }) {
  const [rec, setRec] = useState<Recording | null>(null);
  const [error, setError] = useState(false);
  const [cursor, setCursor] = useState(0);
  const [open, setOpen] = useState<TapeEvent | null>(null);
  useEffect(() => {
    fetch(src).then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status))))).then(setRec).catch(() => setError(true));
  }, [src]);

  const events = rec ? [...rec.events].sort((a, b) => a.seq - b.seq) : [];
  const blocked = events.findIndex((e) => e.decision === "block");
  useEffect(() => { if (blocked >= 0) setCursor(blocked); }, [blocked]);
  const v = rec?.verification;
  return (
    <main style={{ maxWidth: "72rem", margin: "0 auto" }}>
      <div className="card row between" role="note" style={{ marginBottom: "1rem" }}>
        <strong>Recorded demo. No live agent.</strong>
        <span className="muted small">This is a saved session from AgentShield stopping a hijacked email assistant. Nothing here talks to a server.</span>
        <div style={{ minWidth: "9rem" }}><ThemeToggle /></div>
      </div>
      <h1>Session tape</h1>
      {error ? <div role="alert" className="error-state"><p>The recording could not be loaded.</p></div> : !rec ? <p>Loading the recording</p> : (
        <div className="stack">
          <p className="muted">Agent <code>{rec.session.agent_slug}</code>. Request <span className="value">{rec.session.user_request ?? "not recorded"}</span>. Risk {rec.session.risk_score.toFixed(2)}.</p>
          <div className="tape">
            <div className="thead" aria-hidden="true"><span>Time</span>{LANES.map((l) => <span key={l}>{l}</span>)}</div>
            <VirtualRows count={events.length} cursor={cursor} onCursor={setCursor} onOpen={(i) => setOpen(events[i])} label="Session events"
              renderRow={(i, active) => <Row e={events[i]} index={i} active={active} fresh={false} version={null} />} />
            <p className="small muted">Arrow keys step through the tape. Enter opens the recorded payload.</p>
          </div>
          <p role="status">{v?.verified ? `Chain verified (${v.checked} events) when this was recorded` : "Chain not verified in this recording"}</p>
        </div>
      )}
      <StepDrawer event={open} canSeePayload onClose={() => setOpen(null)} />
    </main>
  );
}

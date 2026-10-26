import { Link } from "react-router-dom";
import type { Schemas } from "../../api/client";
import { DecisionBadge } from "../../ui/DecisionBadge";

export type Simulation = Schemas["SimulateResult"];
type Step = Schemas["ReplayStep"];

/** Steps that went from refused/held to cleared: the "loosens a rule" signal. */
export function loosened(sim: Simulation | null | undefined): Step[] {
  return (sim?.diffs ?? []).filter((d) => (d.recorded_decision === "block" || d.recorded_decision === "ask") && d.replay_decision === "allow");
}

export function SimulatePanel({ sim, version }: { sim: Simulation; version: number }) {
  return (
    <section className="card stack" aria-label={`Simulation of policy v${version}`}>
      <h3>Simulation of v{version} on the last 7 days</h3>
      <p>
        {sim.compared} recorded {sim.compared === 1 ? "call" : "calls"} across {sim.sessions} {sim.sessions === 1 ? "session" : "sessions"}.{" "}
        <strong>{sim.changed === 0 ? "No decision would change." : `${sim.changed} would change.`}</strong>
      </p>
      {sim.changed > 0 && (
        <p className="small muted">Newly cleared {sim.newly_allowed} · newly blocked {sim.newly_blocked} · newly holding {sim.newly_asked}</p>
      )}
      {sim.skipped > 0 && <p className="small muted">{sim.skipped} calls could not be replayed because their payloads were purged.</p>}
      {sim.truncated && <p className="small muted">Showing the first {sim.diffs.length} changes.</p>}
      {sim.diffs.length > 0 && (
        <div className="table-wrap" role="region" aria-label="Changed decisions" tabIndex={0}>
          <table>
            <thead><tr><th>Time</th><th>Tool</th><th>Was</th><th>Would be</th><th>Rule</th><th><span className="sr-only">Open</span></th></tr></thead>
            <tbody>
              {sim.diffs.map((d) => (
                <tr key={`${d.session_id}-${d.seq}`}>
                  <td>{new Date(d.ts).toLocaleString()}</td>
                  <td><code className="mono">{d.tool}</code></td>
                  <td><DecisionBadge decision={d.recorded_decision} /></td>
                  <td><DecisionBadge decision={d.replay_decision} /></td>
                  <td><code className="mono">{d.replay_rule}</code></td>
                  <td>{d.session_id && <Link to={`/sessions/${d.session_id}?step=${d.seq}`}>Open on the tape</Link>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

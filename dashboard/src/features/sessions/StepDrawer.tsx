import { Drawer } from "../../ui/Drawer";
import { DecisionBadge } from "../../ui/DecisionBadge";
import { Value } from "../../ui/Value";
import { placementOf } from "./TapeLane";
import type { TapeEvent } from "./tape";

export function StepDrawer({ event, canSeePayload, onClose }: { event: TapeEvent | null; canSeePayload: boolean; onClose: () => void }) {
  return (
    <Drawer open={!!event} onClose={onClose} title={event ? `Step ${event.seq}` : "Step"} wide>
      {event && (
        <>
          <dl className="defs">
            <dt>Event</dt><dd><Value value={event.type} copy={false} /></dd>
            <dt>Lane</dt><dd>{(() => { const p = placementOf(event.type); return p.kind === "lane" ? p.lane : "Rule line"; })()}</dd>
            <dt>Time</dt><dd>{new Date(event.ts).toLocaleString()}</dd>
            {event.decision && <><dt>Decision</dt><dd><DecisionBadge decision={event.decision} /></dd></>}
            {event.rule_id && <><dt>Rule</dt><dd><Value value={event.rule_id} copy={false} /></dd></>}
            {event.reason && <><dt>Reason</dt><dd><Value value={event.reason} /></dd></>}
            <dt>Severity</dt><dd>{event.severity}</dd>
            <dt>Trace</dt><dd><Value value={event.trace_id} /></dd>
            <dt>Chain hash</dt><dd><Value value={event.hash} /></dd>
          </dl>
          <h3>Recorded payload</h3>
          {!canSeePayload ? <p className="muted">Payloads need the analyst role.</p>
            : event.payload ? <Value value={event.payload} block limit={4000} />
            : event.payload_available ? <p className="muted">No payload was recorded for this step.</p>
            : <p className="muted">Payload purged after 30 days. The envelope and hash chain are kept.</p>}
        </>
      )}
    </Drawer>
  );
}

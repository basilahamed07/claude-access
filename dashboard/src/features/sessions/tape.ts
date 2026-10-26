import type { Schemas } from "../../api/client";

export type TapeEvent = Schemas["EventRead"];
export type ReplayStep = Schemas["ReplayStep"];

export function flatten(timeline: Schemas["Timeline"]): TapeEvent[] {
  return timeline.traces.flatMap((t) => t.events).sort((a, b) => a.seq - b.seq);
}

/** Map each changed replay step onto the policy.decision event that followed it in the same trace. */
export function ghostsFor(events: TapeEvent[], steps: ReplayStep[]): Map<number, ReplayStep> {
  const out = new Map<number, ReplayStep>();
  for (const s of steps) {
    if (!s.changed) continue;
    const hit = events.find((e) => e.type === "policy.decision" && e.trace_id === s.trace_id && e.seq > s.seq && !out.has(e.seq));
    if (hit) out.set(hit.seq, s);
  }
  return out;
}

export function isBlocked(e: TapeEvent): boolean {
  return e.decision === "block" || (e.type === "content.scanned" && (e.severity === "high" || e.severity === "critical"));
}

export function timeOf(ts: string): string {
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour12: false });
}

export function describe(e: TapeEvent): string {
  const p = e.payload as Record<string, unknown> | null | undefined;
  if (e.type === "content.scanned" && p) {
    const score = typeof p.risk_after === "number" ? ` · risk ${Number(p.risk_after).toFixed(2)}` : "";
    return `${String(p.source ?? "content")} ${String(p.id ?? "")} judged ${String(p.verdict ?? "unknown")}${score}`.replace(/\s+/g, " ");
  }
  return e.summary;
}

import { useState } from "react";
import type { Schemas } from "../../api/client";

type Point = Schemas["SeriesPoint"];
export interface Bucket { start: number; allowed: number; asked: number; blocked: number }

const HOUR = 3_600_000;

/** One bucket per hour for the last 24 hours, zeros where nothing happened, so a quiet hour is visible as quiet. */
export function hourlyBuckets(series: Point[], now: number, hours = 24): Bucket[] {
  const end = Math.floor(now / HOUR) * HOUR;
  const byHour = new Map(series.map((p) => [Math.floor(new Date(p.ts).getTime() / HOUR) * HOUR, p]));
  return Array.from({ length: hours }, (_, i) => {
    const start = end - (hours - 1 - i) * HOUR;
    const p = byHour.get(start);
    return { start, allowed: p?.allowed ?? 0, asked: p?.asked ?? 0, blocked: p?.blocked ?? 0 };
  });
}

export const niceMax = (n: number) => (n <= 4 ? 4 : n <= 10 ? 10 : Math.ceil(n / 10) * 10);
const total = (b: Bucket) => b.allowed + b.asked + b.blocked;

const W = 720, H = 220, PAD = { l: 36, r: 8, t: 8, b: 28 };
const SERIES = [
  { key: "allowed", label: "Cleared", color: "var(--cleared)", icon: "M3 8.5l3.2 3.2L13 4.8" },
  { key: "asked", label: "Holding", color: "var(--holding)", icon: "M5.5 3.5v9M10.5 3.5v9" },
  { key: "blocked", label: "Blocked", color: "var(--recorder)", icon: "M4 4l8 8M12 4l-8 8" },
] as const;

/** Decisions per hour, stacked. Status colours only; every series has an icon and a word in the legend; a table view is one click away. */
export function DecisionsChart({ buckets }: { buckets: Bucket[] }) {
  const [table, setTable] = useState(false);
  const [hover, setHover] = useState<number | null>(null);
  const max = niceMax(Math.max(0, ...buckets.map(total)));
  const iw = W - PAD.l - PAD.r, ih = H - PAD.t - PAD.b;
  const slot = iw / buckets.length;
  const bar = Math.max(4, slot - 6);
  const y = (v: number) => PAD.t + ih - (v / max) * ih;
  const grand = buckets.reduce((s, b) => s + total(b), 0);
  const label = (b: Bucket) => new Date(b.start).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
  return (
    <figure className="chart" aria-label="Decisions per hour, last 24 hours">
      <div className="row between">
        <figcaption><h2>Decisions per hour</h2><p className="muted small">Last 24 hours · {grand} {grand === 1 ? "decision" : "decisions"}</p></figcaption>
        <button className="btn quiet" aria-pressed={table} onClick={() => setTable(!table)}>{table ? "View as chart" : "View as table"}</button>
      </div>
      <ul className="legend row" aria-label="Legend">
        {SERIES.map((s) => (
          <li key={s.key} className="row" style={{ gap: "0.375rem" }}>
            <span className="swatch" style={{ background: s.color }} aria-hidden="true" />
            <svg width="14" height="14" viewBox="0 0 16 16" aria-hidden="true" style={{ color: s.color }}><path d={s.icon} fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" /></svg>
            <span>{s.label}</span>
          </li>
        ))}
      </ul>
      {table ? (
        <div className="table-wrap" role="region" aria-label="Decisions per hour as a table" tabIndex={0}>
          <table><thead><tr><th>Hour</th><th className="num">Cleared</th><th className="num">Holding</th><th className="num">Blocked</th></tr></thead>
            <tbody>{buckets.map((b) => <tr key={b.start}><td>{label(b)}</td><td className="num">{b.allowed}</td><td className="num">{b.asked}</td><td className="num">{b.blocked}</td></tr>)}</tbody></table>
        </div>
      ) : (
        <div className="chart-box">
          <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Stacked bars of cleared, holding and blocked decisions for each of the last 24 hours. ${grand} in total.`} style={{ width: "100%", height: "auto" }}>
            {[0, 0.5, 1].map((f) => (
              <g key={f}><line x1={PAD.l} x2={W - PAD.r} y1={y(max * f)} y2={y(max * f)} stroke="var(--rule)" strokeWidth="1" />
                <text x={PAD.l - 6} y={y(max * f) + 4} textAnchor="end" fontSize="11" fill="var(--ink-soft)">{Math.round(max * f)}</text></g>
            ))}
            {buckets.map((b, i) => {
              const x = PAD.l + i * slot + (slot - bar) / 2;
              let acc = 0;
              const parts = SERIES.map((s) => { const v = b[s.key]; const y0 = y(acc + v); const h = y(acc) - y0; acc += v; return { s, v, y0, h }; }).filter((p) => p.v > 0);
              return (
                <g key={b.start} tabIndex={0} role="img" aria-label={`${label(b)}: ${b.allowed} cleared, ${b.asked} holding, ${b.blocked} blocked`}
                  onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)} onFocus={() => setHover(i)} onBlur={() => setHover(null)} className="barg">
                  <rect x={PAD.l + i * slot} y={PAD.t} width={slot} height={ih} fill="transparent" />
                  {parts.map((p, k) => (
                    <rect key={p.s.key} x={x} y={p.y0} width={bar} height={Math.max(1, p.h - (k < parts.length - 1 ? 2 : 0))} fill={p.s.color} rx={k === parts.length - 1 ? 4 : 0} />
                  ))}
                  {i % 4 === 0 && <text x={x + bar / 2} y={H - 8} textAnchor="middle" fontSize="11" fill="var(--ink-soft)">{label(b)}</text>}
                </g>
              );
            })}
          </svg>
          {hover !== null && (
            <div className="tip" role="status" style={{ left: `${Math.min(80, Math.max(0, ((PAD.l + hover * slot) / W) * 100))}%` }}>
              <strong>{label(buckets[hover])}</strong>
              {SERIES.map((s) => <div key={s.key}>{s.label}: {buckets[hover][s.key]}</div>)}
            </div>
          )}
        </div>
      )}
    </figure>
  );
}

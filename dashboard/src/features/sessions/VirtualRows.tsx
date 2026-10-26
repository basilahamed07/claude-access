import { useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from "react";

export const ROW_HEIGHT = 44;
const OVERSCAN = 6;

/** Fixed-height windowed list: only the rows in view (plus a few) are in the DOM, so 5,000 events stay responsive. */
export function VirtualRows({ count, cursor, onCursor, onOpen, renderRow, label, fallbackHeight = 600 }: {
  count: number; cursor: number; onCursor: (i: number) => void; onOpen: (i: number) => void;
  renderRow: (i: number, active: boolean) => ReactNode; label: string; fallbackHeight?: number;
}) {
  const box = useRef<HTMLDivElement>(null);
  const [top, setTop] = useState(0);
  const [height, setHeight] = useState(fallbackHeight);

  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const measure = () => setHeight(el.clientHeight || fallbackHeight);
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [fallbackHeight]);

  // keep the cursor row on screen
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const y = cursor * ROW_HEIGHT;
    if (y < el.scrollTop) el.scrollTop = y;
    else if (y + ROW_HEIGHT > el.scrollTop + height) el.scrollTop = y + ROW_HEIGHT - height;
    setTop(el.scrollTop);
  }, [cursor, height]);

  const first = Math.max(0, Math.floor(top / ROW_HEIGHT) - OVERSCAN);
  const last = Math.min(count - 1, Math.ceil((top + height) / ROW_HEIGHT) + OVERSCAN);
  const rows: ReactNode[] = [];
  for (let i = first; i <= last; i++) {
    rows.push(<div key={i} className="vrow" style={{ top: i * ROW_HEIGHT, height: ROW_HEIGHT }} role="row" aria-rowindex={i + 1} data-index={i}
      onClick={() => { onCursor(i); }} onDoubleClick={() => onOpen(i)}>{renderRow(i, i === cursor)}</div>);
  }
  const onKey = (e: KeyboardEvent) => {
    if (count === 0) return;
    const move = (to: number) => { e.preventDefault(); onCursor(Math.min(count - 1, Math.max(0, to))); };
    if (e.key === "ArrowRight" || e.key === "ArrowDown") move(cursor + 1);
    else if (e.key === "ArrowLeft" || e.key === "ArrowUp") move(cursor - 1);
    else if (e.key === "Home") move(0);
    else if (e.key === "End") move(count - 1);
    else if (e.key === "PageDown") move(cursor + 10);
    else if (e.key === "PageUp") move(cursor - 10);
    else if (e.key === "Enter") { e.preventDefault(); onOpen(cursor); }
  };
  return (
    <div ref={box} className="vbox" tabIndex={0} role="grid" aria-label={label} aria-rowcount={count} aria-activedescendant={`tape-row-${cursor}`}
      onScroll={(e) => setTop(e.currentTarget.scrollTop)} onKeyDown={onKey}>
      <div style={{ height: count * ROW_HEIGHT, position: "relative" }}>{rows}</div>
    </div>
  );
}

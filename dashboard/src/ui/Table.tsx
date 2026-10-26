import type { ReactNode } from "react";
import { EmptyState, ErrorState, Skeleton } from "./states";

export interface Column<T> { key: string; header: string; render: (row: T) => ReactNode; numeric?: boolean }

interface Props<T> {
  columns: Column<T>[];
  rows: T[] | undefined;
  rowKey: (row: T) => string;
  loading?: boolean;
  error?: unknown;
  onRetry?: () => void;
  empty: { title: string; body?: string; action?: ReactNode };
  onRowClick?: (row: T) => void;
  rowLabel?: (row: T) => string;
  hasMore?: boolean;
  loadingMore?: boolean;
  onLoadMore?: () => void;
  caption: string;
}

/** Dense table with skeleton, empty and error states and keyset "Load more". */
export function Table<T>({ columns, rows, rowKey, loading, error, onRetry, empty, onRowClick, rowLabel, hasMore, loadingMore, onLoadMore, caption }: Props<T>) {
  if (error) return <ErrorState error={error} onRetry={onRetry} />;
  if (loading) return <Skeleton label={`Loading ${caption}`} />;
  if (!rows || rows.length === 0) return <EmptyState title={empty.title} action={empty.action}>{empty.body}</EmptyState>;
  return (
    <div className="stack">
      <div className="table-wrap" tabIndex={0} role="region" aria-label={caption}>
        <table>
          <caption className="sr-only">{caption}</caption>
          <thead><tr>{columns.map((c) => <th key={c.key} scope="col" className={c.numeric ? "num" : undefined}>{c.header}</th>)}</tr></thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={rowKey(row)}
                className={onRowClick ? "clickable" : undefined}
                tabIndex={onRowClick ? 0 : undefined}
                aria-label={onRowClick && rowLabel ? rowLabel(row) : undefined}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                onKeyDown={onRowClick ? (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onRowClick(row); } } : undefined}
              >
                {columns.map((c) => <td key={c.key} className={c.numeric ? "num" : undefined}>{c.render(row)}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {hasMore && <div><button className="btn" onClick={onLoadMore} disabled={loadingMore}>{loadingMore ? "Loading" : "Load more"}</button></div>}
    </div>
  );
}

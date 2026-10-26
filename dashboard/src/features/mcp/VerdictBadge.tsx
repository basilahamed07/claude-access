const WORDS: Record<string, [string, string, string]> = {
  approved: ["Approved", "allow", "M3 8.5l3.2 3.2L13 4.8"],
  approved_with_limits: ["Approved with limits", "ask", "M5.5 3.5v9M10.5 3.5v9"],
  pending: ["Pending review", "none", ""],
  rejected: ["Rejected", "block", "M4 4l8 8M12 4l-8 8"],
  suspended: ["Suspended: changed after approval", "block", "M4 4l8 8M12 4l-8 8"],
};

/** A server's verdict in words with an icon; the orange icon is used only for the two "stopped" verdicts. */
export function VerdictBadge({ verdict }: { verdict: string }) {
  const [word, cls, icon] = WORDS[verdict] ?? [verdict, "none", ""];
  return (
    <span className={`badge badge--${cls}`} data-verdict={verdict}>
      {icon && <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><path d={icon} fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" /></svg>}
      {word}
    </span>
  );
}

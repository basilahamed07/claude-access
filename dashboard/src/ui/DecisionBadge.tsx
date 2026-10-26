export type Decision = "allow" | "ask" | "block";

const WORDS: Record<Decision, string> = { allow: "Cleared", ask: "Holding", block: "Blocked" };

/** Icon + word, never colour alone. `--recorder` (orange) is used only for block. */
export function DecisionBadge({ decision }: { decision: string | null | undefined }) {
  if (decision !== "allow" && decision !== "ask" && decision !== "block") {
    return <span className="badge badge--none">No decision</span>;
  }
  const icon =
    decision === "allow" ? <path d="M3 8.5l3.2 3.2L13 4.8" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    : decision === "ask" ? <path d="M5.5 3.5v9M10.5 3.5v9" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" />
    : <path d="M4 4l8 8M12 4l-8 8" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" />;
  return (
    <span className={`badge badge--${decision}`} title={`API value: ${decision}`} data-decision={decision}>
      <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">{icon}</svg>
      {WORDS[decision]}
    </span>
  );
}

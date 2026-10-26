export const LANES = ["Input", "Scan", "Policy", "Tool", "Model"] as const;
export type Lane = (typeof LANES)[number];
export type Placement = { kind: "lane"; lane: Lane } | { kind: "rule" };

/**
 * Every audit event type lands in exactly one lane (or is drawn as a full-width rule line).
 * mcp.* and shadow.* are mapped now so the table stays exhaustive when those modules ship.
 */
export function placementOf(type: string): Placement {
  switch (type) {
    case "request.received": case "content.untrusted": return { kind: "lane", lane: "Input" };
    case "content.scanned": return { kind: "lane", lane: "Scan" };
    case "policy.decision": case "budget.exceeded": case "budget.price_missing": return { kind: "lane", lane: "Policy" };
    case "tool.requested": case "tool.rewritten": return { kind: "lane", lane: "Tool" };
    case "model.response": return { kind: "lane", lane: "Model" };
    case "error": return { kind: "rule" };
  }
  if (type.startsWith("approval.")) return { kind: "lane", lane: "Policy" };
  if (type.startsWith("audit.")) return { kind: "rule" };
  if (type.startsWith("mcp.")) return { kind: "lane", lane: "Tool" };
  if (type.startsWith("shadow.")) return { kind: "lane", lane: "Input" };
  return { kind: "lane", lane: "Input" };                       // unknown future types still show up, in the first lane
}

import { useState } from "react";

const BIDI = /[‪-‮⁦-⁩‎‏؜]/g;
const LIMIT = 300;

/** What the screen shows for a hostile value: bidi/format controls are made visible instead of acting. */
export function displayText(raw: string): string {
  return raw.replace(BIDI, (c) => `\\u${c.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}`);
}

export function stringify(value: unknown): string {
  if (typeof value === "string") return value;
  try { return JSON.stringify(value, null, 2) ?? String(value); } catch { return String(value); }
}

/**
 * A literal machine value (tool argument, payload, id). Monospace, escaped by React, bidi controls shown
 * as text, truncated past 300 characters with "Show all". Copy gives the original bytes.
 */
export function Value({ value, block = false, copy = true, limit = LIMIT }: { value: unknown; block?: boolean; copy?: boolean; limit?: number }) {
  const [all, setAll] = useState(false);
  const [copied, setCopied] = useState(false);
  const raw = stringify(value);
  const shown = displayText(raw);
  const long = shown.length > limit;
  const text = long && !all ? `${shown.slice(0, limit)}…` : shown;
  const doCopy = async () => {
    try { await navigator.clipboard.writeText(raw); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { /* clipboard blocked */ }
  };
  return (
    <span>
      <span className={`value${block ? " block" : ""}`}>{text}</span>
      {(long || copy) && (
        <span className="value-actions">
          {long && <button type="button" className="linkbtn" onClick={() => setAll(!all)}>{all ? "Show less" : "Show all"}</button>}
          {copy && <button type="button" className="linkbtn" onClick={doCopy}>{copied ? "Copied" : "Copy"}</button>}
        </span>
      )}
    </span>
  );
}

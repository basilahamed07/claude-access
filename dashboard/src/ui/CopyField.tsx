import { useState } from "react";

export function CopyField({ label, value, masked }: { label: string; value: string; masked?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { /* blocked */ }
  };
  return (
    <div className="field">
      <label htmlFor={`cf-${label}`}>{label}</label>
      <div className="row">
        <input id={`cf-${label}`} className="mono grow" type="text" readOnly value={masked ?? value} onFocus={(e) => e.currentTarget.select()} />
        <button type="button" className="btn" onClick={copy}>{copied ? "Copied" : "Copy"}</button>
      </div>
    </div>
  );
}

import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiProblem, post, type Schemas } from "../../api/client";
import { Modal } from "../../ui/Modal";
import { chunkLog, fileBatchPrefix } from "./chunks";

type Result = Schemas["IngestResult"];
const FORMATS: [string, string, "proxy" | "dns"][] = [["squid", "Squid access log", "proxy"], ["common", "Common / combined web log", "proxy"], ["dns", "DNS query log (time, client, name)", "dns"], ["csv", "CSV with a header row", "proxy"]];

export function UploadDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const [format, setFormat] = useState("squid");
  const [team, setTeam] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<{ accepted: number; rejected: number; tools: number; duplicates: number } | null>(null);

  const send = async () => {
    if (!file) return;
    setBusy(true); setError(null); setDone(null);
    try {
      const text = await file.text();
      const chunks = chunkLog(text, format);
      if (chunks.length === 0) { setError("The file has no lines to read."); return; }
      const prefix = await fileBatchPrefix(text);
      const source = FORMATS.find(([f]) => f === format)![2];
      const sum = { accepted: 0, rejected: 0, tools: 0, duplicates: 0 };
      for (const [i, lines] of chunks.entries()) {
        const r = await post<Result>("/v1/ingest/logs", { source, format, batch_id: `upload-${prefix}-${format}-${i}`, ...(team.trim() ? { team: team.trim() } : {}), lines });
        sum.accepted += r.accepted; sum.rejected += r.rejected; sum.tools += r.tools_seen; sum.duplicates += r.duplicate ? 1 : 0;
      }
      setDone(sum);
      void qc.invalidateQueries({ queryKey: ["shadow"] });
    } catch (e) {
      setError(e instanceof ApiProblem ? e.detail : "Could not read or send the file.");
    } finally { setBusy(false); }
  };
  const close = () => { setFile(null); setDone(null); setError(null); onClose(); };
  return (
    <Modal open={open} onClose={close} title="Upload a log file">
      <div className="stack">
        <p className="muted">Large files are sent in pieces. Sending the same file again is safe: it is counted once.</p>
        {error && <p role="alert"><span className="err">{error}</span></p>}
        <div className="field"><label htmlFor="u-format">Log format</label>
          <select id="u-format" value={format} onChange={(e) => setFormat(e.target.value)}>{FORMATS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></div>
        <div className="field"><label htmlFor="u-team">Team (optional)</label><input id="u-team" type="text" maxLength={100} value={team} onChange={(e) => setTeam(e.target.value)} />
          <span className="hint">Used when the log does not say. Otherwise shown as unassigned.</span></div>
        <div className="field"><label htmlFor="u-file">Log file</label><input id="u-file" type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} /></div>
        {done && <p role="status">Read {done.accepted.toLocaleString()} lines{done.rejected ? `, skipped ${done.rejected.toLocaleString()} that could not be read` : ""}. {done.duplicates ? `${done.duplicates} piece(s) had been sent before. ` : ""}Inventory updated.</p>}
        <div className="row"><button className="btn primary" disabled={!file || busy} onClick={() => void send()}>{busy ? "Sending…" : "Upload"}</button><button className="btn" onClick={close}>Close</button></div>
      </div>
    </Modal>
  );
}

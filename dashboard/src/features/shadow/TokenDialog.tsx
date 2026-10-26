import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiProblem, del, get, post, type Schemas } from "../../api/client";
import { CopyField } from "../../ui/CopyField";
import { Modal } from "../../ui/Modal";

type Token = Schemas["TokenRead"];

export function TokenDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const [label, setLabel] = useState("");
  const [issued, setIssued] = useState<Schemas["TokenIssued"] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const tokens = useQuery({ queryKey: ["shadow-tokens"], queryFn: () => get<Token[]>("/v1/admin/tokens"), enabled: open });
  const refresh = () => void qc.invalidateQueries({ queryKey: ["shadow-tokens"] });
  const create = useMutation({
    mutationFn: () => post<Schemas["TokenIssued"]>("/v1/admin/tokens", { label: label.trim() }),
    onSuccess: (t) => { setIssued(t); setLabel(""); setError(null); refresh(); },
    onError: (e) => setError(e instanceof ApiProblem ? e.detail : "Could not create the token."),
  });
  const revoke = useMutation({ mutationFn: (id: string) => del(`/v1/admin/tokens/${id}`), onSuccess: refresh, onError: () => setError("Could not revoke the token.") });
  const close = () => { setIssued(null); setError(null); onClose(); };
  const endpoint = `${window.location.origin.replace(":5173", ":8000")}/v1/ingest/logs`;
  return (
    <Modal open={open} onClose={close} title="Ingest tokens">
      <div className="stack">
        <p className="muted">A token lets a log shipper send logs to <code>{endpoint}</code>. It acts as you and stops working if you are disabled.</p>
        {error && <p role="alert"><span className="err">{error}</span></p>}
        {issued ? (
          <div className="stack">
            <CopyField label="New token" value={issued.token} />
            <p className="hint">Copy it now. It is not shown again.</p>
          </div>
        ) : (
          <form className="row" onSubmit={(e) => { e.preventDefault(); if (label.trim()) create.mutate(); }}>
            <div className="field grow"><label htmlFor="t-label">What will use it</label><input id="t-label" type="text" value={label} maxLength={100} onChange={(e) => setLabel(e.target.value)} /></div>
            <button className="btn primary" type="submit" disabled={!label.trim() || create.isPending}>Create token</button>
          </form>
        )}
        <ul className="stack" aria-label="Your tokens" style={{ listStyle: "none", padding: 0 }}>
          {(tokens.data ?? []).map((t) => (
            <li key={t.id} className="row"><span className="grow"><strong>{t.label || "Unnamed"}</strong> <span className="mono small muted">{t.prefix}…</span>{t.revoked_at && <span className="muted"> · revoked</span>}</span>
              {!t.revoked_at && <button className="btn" aria-label={`Revoke ${t.label || t.prefix}`} onClick={() => revoke.mutate(t.id)}>Revoke</button>}</li>))}
        </ul>
        <div className="row"><button className="btn" onClick={close}>Done</button></div>
      </div>
    </Modal>
  );
}

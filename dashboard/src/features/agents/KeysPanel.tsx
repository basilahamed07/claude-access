import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiProblem, get, post, type Schemas } from "../../api/client";
import { ConfirmTyped } from "../../ui/ConfirmTyped";
import { CopyField } from "../../ui/CopyField";
import { Drawer } from "../../ui/Drawer";
import { Modal } from "../../ui/Modal";
import { Skeleton } from "../../ui/states";
import { useToast } from "../../ui/toast";
import { SnippetTabs } from "./SnippetTabs";

type Key = Schemas["KeyRead"];

export const maskKey = (prefix: string) => `${prefix}…`;

export function KeysPanel({ agent, onClose }: { agent: Schemas["AgentRead"] | null; onClose: () => void }) {
  const slug = agent?.slug ?? "";
  const qc = useQueryClient();
  const toast = useToast();
  const keys = useQuery({ queryKey: ["keys", slug], enabled: !!agent, queryFn: () => get<Key[]>(`/v1/admin/agents/${slug}/keys`) });
  const [revoking, setRevoking] = useState<Key | null>(null);
  const [rotating, setRotating] = useState<Key | null>(null);
  const [overlap, setOverlap] = useState(24);
  const [issued, setIssued] = useState<Schemas["KeyIssued"] | null>(null);

  const refresh = () => { void qc.invalidateQueries({ queryKey: ["keys", slug] }); void qc.invalidateQueries({ queryKey: ["agents"] }); };
  const revoke = useMutation({
    mutationFn: (k: Key) => post(`/v1/admin/agents/${slug}/keys/${k.id}/revoke`),
    onSuccess: () => { toast("Key revoked"); setRevoking(null); refresh(); },
    onError: (e) => { toast(e instanceof ApiProblem ? e.detail : "Could not revoke the key", true); setRevoking(null); },
  });
  const rotate = useMutation({
    mutationFn: (k: Key) => post<Schemas["KeyIssued"]>(`/v1/admin/agents/${slug}/keys/${k.id}/rotate`, { overlap_seconds: Math.round(overlap * 3600) }),
    onSuccess: (r) => { toast("Key rotated"); setRotating(null); setIssued(r); refresh(); },
    onError: (e) => { toast(e instanceof ApiProblem ? e.detail : "Could not rotate the key", true); setRotating(null); },
  });
  const active = (k: Key) => !k.revoked_at && (!k.expires_at || new Date(k.expires_at) > new Date());

  return (
    <>
      <Drawer open={!!agent} onClose={() => { setIssued(null); onClose(); }} title={agent ? `Keys for ${agent.slug}` : "Keys"} wide>
        {issued && (
          <div className="card stack" role="status">
            <p><strong>New key. Copy it now.</strong> It is shown once.</p>
            <CopyField label="New API key" value={issued.key} />
            <SnippetTabs slug={slug} apiKey={issued.key} />
          </div>
        )}
        {keys.isLoading ? <Skeleton rows={3} /> : keys.error ? <p role="alert">Could not load keys. Try again.</p> : (
          <ul className="stack" style={{ listStyle: "none", padding: 0, margin: 0 }}>
            {keys.data?.length === 0 && <li className="muted">No keys yet.</li>}
            {keys.data?.map((k) => (
              <li key={k.id} className="card row between">
                <div>
                  <code className="mono">{maskKey(k.prefix)}</code>
                  <div className="small muted">
                    Created {new Date(k.created_at).toLocaleDateString()}
                    {k.revoked_at ? ", revoked" : k.expires_at ? `, expires ${new Date(k.expires_at).toLocaleString()}` : ""}
                  </div>
                </div>
                {active(k) && (
                  <div className="row">
                    <button className="btn" onClick={() => { setOverlap(24); setRotating(k); }}>Rotate key</button>
                    <button className="btn danger" onClick={() => setRevoking(k)}>Revoke key</button>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </Drawer>
      <ConfirmTyped open={!!revoking} onClose={() => setRevoking(null)} onConfirm={() => revoking && revoke.mutate(revoking)}
        title="Revoke this key?" phrase="revoke" action="Revoke key" busy={revoke.isPending}>
        <p>Anything still using <code>{revoking ? maskKey(revoking.prefix) : ""}</code> stops working immediately.</p>
      </ConfirmTyped>
      <Modal open={!!rotating} onClose={() => setRotating(null)} title="Rotate this key">
        <p>A new key is issued now. The old key keeps working for the overlap so you can deploy the new one.</p>
        <div className="field"><label htmlFor="overlap">Old key keeps working for (hours)</label>
          <input id="overlap" type="number" min={0} max={168} value={overlap} onChange={(e) => setOverlap(Number(e.target.value))} /></div>
        <div className="row">
          <button className="btn primary" onClick={() => rotating && rotate.mutate(rotating)} disabled={rotate.isPending}>Rotate key</button>
          <button className="btn quiet" onClick={() => setRotating(null)}>Cancel</button>
        </div>
      </Modal>
    </>
  );
}

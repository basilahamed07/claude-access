import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, type FormEvent } from "react";
import { ApiProblem, apiRaw, get, patch, type Schemas } from "../../api/client";
import { Skeleton, ErrorState } from "../../ui/states";
import { useToast } from "../../ui/toast";

type TS = Schemas["TenantSettings"];
export const FLOORS = { payload_days: 7, envelope_days: 180, incident_days: 365 } as const;
const ACTIONS = [["sanitize", "Remove the attack and pass the rest"], ["quarantine", "Withhold the whole content"], ["flag", "Pass it unchanged and raise an alert"]] as const;

export function TenantPanel() {
  const qc = useQueryClient();
  const toast = useToast();
  const q = useQuery({ queryKey: ["tenant-settings"], queryFn: () => apiRaw<TS>("GET", "/v1/admin/settings") });
  const upstreams = useQuery({ queryKey: ["upstreams"], queryFn: () => get<Schemas["UpstreamRead"][]>("/v1/admin/upstreams") });
  const [s, setS] = useState<TS | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { if (q.data && !s) setS({ ...q.data.data, on_malicious: q.data.data.on_malicious ?? "sanitize", mark_untrusted: q.data.data.mark_untrusted ?? true, retention: q.data.data.retention ?? { payload_days: 30, envelope_days: 180, incident_days: 1095 } }); }, [q.data, s]);
  const save = useMutation({
    mutationFn: () => patch<TS>("/v1/admin/settings", s, q.data?.etag ? { "If-Match": q.data.etag } : { "If-Match": "*" }),
    onSuccess: () => { toast("Settings saved"); setError(null); void qc.invalidateQueries({ queryKey: ["tenant-settings"] }); setS(null); },
    onError: (e) => {
      if (e instanceof ApiProblem && e.status === 412) { setError("Settings changed since you opened this page. Reload and try again."); void q.refetch(); setS(null); }
      else setError(e instanceof ApiProblem ? e.detail : "Could not save the settings");
    },
  });
  if (q.isLoading || !s) return q.error ? <ErrorState error={q.error} onRetry={() => void q.refetch()} /> : <Skeleton rows={6} />;
  const r = s.retention ?? { payload_days: 30, envelope_days: 180, incident_days: 1095 };
  const below = (Object.keys(FLOORS) as (keyof typeof FLOORS)[]).filter((k) => (r[k] ?? 0) < FLOORS[k]);
  const setRet = (k: keyof typeof FLOORS, v: string) => setS({ ...s, retention: { ...r, [k]: Number(v) } });
  const submit = (e: FormEvent) => { e.preventDefault(); if (below.length === 0) save.mutate(); };
  return (
    <form className="stack" onSubmit={submit} aria-labelledby="ten-h">
      <h2 id="ten-h">Protection and retention</h2>
      {error && <div role="alert" className="error-state"><p>{error}</p></div>}
      <div className="field"><label htmlFor="on-mal">When an attack is found in content</label>
        <select id="on-mal" value={s.on_malicious} onChange={(e) => setS({ ...s, on_malicious: e.target.value as TS["on_malicious"] })}>{ACTIONS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></div>
      <label className="row"><input type="checkbox" checked={s.mark_untrusted ?? true} onChange={(e) => setS({ ...s, mark_untrusted: e.target.checked })} /> Mark tool results as untrusted for the model</label>
      <div className="field"><label htmlFor="judge">Judge provider for borderline content</label>
        <select id="judge" value={s.judge_upstream_id ?? ""} onChange={(e) => setS({ ...s, judge_upstream_id: e.target.value || null })}>
          <option value="">None (borderline content is flagged as suspicious)</option>{upstreams.data?.map((u) => <option key={u.id} value={u.id}>{u.name}</option>)}</select></div>
      <div className="field"><label htmlFor="hook">Approval webhook URL</label>
        <input id="hook" type="url" placeholder="https://hooks.slack.com/..." value={s.webhook_url ?? ""} onChange={(e) => setS({ ...s, webhook_url: e.target.value || null })} />
        <span className="hint">Receives a message when an action needs approval. Private addresses are refused.</span></div>
      <fieldset className="stack" style={{ border: 0, padding: 0, margin: 0 }}><legend style={{ fontWeight: 600 }}>Retention (days)</legend>
        {([["payload_days", "Recorded payloads"], ["envelope_days", "Audit envelopes"], ["incident_days", "Incident sessions"]] as const).map(([k, label]) => (
          <div className="field" key={k}><label htmlFor={`ret-${k}`}>{label}</label>
            <input id={`ret-${k}`} type="number" min={FLOORS[k]} value={r[k] ?? ""} onChange={(e) => setRet(k, e.target.value)} aria-invalid={below.includes(k)} aria-describedby={`ret-${k}-h`} />
            <span id={`ret-${k}-h`} className={below.includes(k) ? "err" : "hint"}>{below.includes(k) ? `Cannot be below ${FLOORS[k]} days.` : `At least ${FLOORS[k]} days.`}</span></div>))}
      </fieldset>
      <div><button className="btn primary" type="submit" disabled={save.isPending || below.length > 0}>Save settings</button></div>
    </form>
  );
}

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { ApiProblem, del, get, patch, post, type Schemas } from "../../api/client";
import { ConfirmTyped } from "../../ui/ConfirmTyped";
import { Modal } from "../../ui/Modal";
import { Table, type Column } from "../../ui/Table";
import { useToast } from "../../ui/toast";

type Upstream = Schemas["UpstreamRead"];
interface ModelRow { alias: string; model: string; inUsd: string; outUsd: string }
const EMPTY_ROW: ModelRow = { alias: "", model: "", inUsd: "", outUsd: "" };

export function toModelMap(rows: ModelRow[]): Record<string, { model: string; input_micro_usd_per_mtok: number; output_micro_usd_per_mtok: number }> {
  const out: ReturnType<typeof toModelMap> = {};
  for (const r of rows) {
    if (!r.alias.trim() || !r.model.trim()) continue;
    out[r.alias.trim()] = { model: r.model.trim(), input_micro_usd_per_mtok: Math.round(Number(r.inUsd || 0) * 1_000_000), output_micro_usd_per_mtok: Math.round(Number(r.outUsd || 0) * 1_000_000) };
  }
  return out;
}

export function UpstreamsPanel() {
  const qc = useQueryClient();
  const toast = useToast();
  const list = useQuery({ queryKey: ["upstreams"], queryFn: () => get<Upstream[]>("/v1/admin/upstreams") });
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<Upstream | null>(null);
  const [rekey, setRekey] = useState<Upstream | null>(null);
  const [newKey, setNewKey] = useState("");
  const [form, setForm] = useState({ name: "", kind: "openai", base_url: "https://api.openai.com/v1", api_key: "" });
  const [rows, setRows] = useState<ModelRow[]>([{ ...EMPTY_ROW }]);
  const [error, setError] = useState<string | null>(null);
  const refresh = () => void qc.invalidateQueries({ queryKey: ["upstreams"] });

  const create = useMutation({
    mutationFn: () => post<Upstream>("/v1/admin/upstreams", { ...form, api_key: form.api_key || null, model_map: toModelMap(rows) }),
    onSuccess: () => { toast("Provider added"); setAdding(false); setForm({ ...form, name: "", api_key: "" }); setRows([{ ...EMPTY_ROW }]); setError(null); refresh(); },
    onError: (e) => setError(e instanceof ApiProblem ? e.detail : "Could not add the provider"),
  });
  const remove = useMutation({
    mutationFn: (u: Upstream) => del(`/v1/admin/upstreams/${u.id}`),
    onSuccess: () => { toast("Provider removed"); setRemoving(null); refresh(); },
    onError: (e) => { setRemoving(null); toast(e instanceof ApiProblem ? e.detail : "Could not remove the provider", true); },
  });
  const saveKey = useMutation({
    mutationFn: (u: Upstream) => patch<Upstream>(`/v1/admin/upstreams/${u.id}`, { api_key: newKey }),
    onSuccess: () => { toast("Key saved"); setRekey(null); setNewKey(""); refresh(); },
    onError: (e) => toast(e instanceof ApiProblem ? e.detail : "Could not save the key", true),
  });
  const test = useMutation({
    mutationFn: (u: Upstream) => post<Schemas["UpstreamTestResult"]>(`/v1/admin/upstreams/${u.id}/test`, {}),
    onSuccess: (r) => toast(r.ok ? `Connection works (${r.latency_ms} ms)` : `Connection failed${r.error ? `: ${r.error}` : ""}`, !r.ok),
    onError: (e) => toast(e instanceof ApiProblem ? e.detail : "Could not test the connection", true),
  });

  const cols: Column<Upstream>[] = [
    { key: "name", header: "Provider", render: (u) => <div><strong>{u.name}</strong><div className="small muted">{u.kind}</div></div> },
    { key: "url", header: "Base URL", render: (u) => <code className="mono">{u.base_url}</code> },
    { key: "key", header: "API key", render: (u) => u.has_key ? "Key saved" : <span className="muted">No key (agents pass their own)</span> },
    { key: "models", header: "Models", render: (u) => Object.keys(u.model_map).join(", ") || <span className="muted">None</span> },
    { key: "act", header: "Actions", render: (u) => (
      <div className="row">
        <button className="btn quiet" onClick={() => test.mutate(u)}>Test connection</button>
        <button className="btn quiet" onClick={() => { setNewKey(""); setRekey(u); }}>{u.has_key ? "Replace key" : "Set key"}</button>
        <button className="btn quiet" onClick={() => setRemoving(u)}>Remove provider</button>
      </div>) },
  ];
  const submit = (e: FormEvent) => { e.preventDefault(); create.mutate(); };
  const setRow = (i: number, patch: Partial<ModelRow>) => setRows(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));

  return (
    <section className="stack" aria-labelledby="up-h">
      <div className="row between"><h2 id="up-h">Model providers</h2><button className="btn" onClick={() => setAdding(true)}>Add provider</button></div>
      <Table caption="Model providers" columns={cols} rows={list.data} rowKey={(u) => u.id} loading={list.isLoading} error={list.error} onRetry={() => void list.refetch()}
        empty={{ title: "No providers yet", body: "Add the model provider your agents call through AgentShield.", action: <button className="btn primary" onClick={() => setAdding(true)}>Add provider</button> }} />
      <Modal open={adding} onClose={() => setAdding(false)} title="Add provider">
        <form className="stack" onSubmit={submit}>
          {error && <p role="alert" className="field"><span className="err">{error}</span></p>}
          <div className="field"><label htmlFor="p-name">Name</label><input id="p-name" type="text" required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></div>
          <div className="field"><label htmlFor="p-kind">Kind</label><select id="p-kind" value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value, base_url: e.target.value === "anthropic" ? "https://api.anthropic.com" : "https://api.openai.com/v1" })}>
            <option value="openai">OpenAI-compatible (OpenAI, vLLM, Ollama, LiteLLM)</option><option value="anthropic">Anthropic</option></select></div>
          <div className="field"><label htmlFor="p-url">Base URL</label><input id="p-url" type="url" required value={form.base_url} onChange={(e) => setForm({ ...form, base_url: e.target.value })} /></div>
          <div className="field"><label htmlFor="p-key">API key</label><input id="p-key" type="password" autoComplete="off" value={form.api_key} onChange={(e) => setForm({ ...form, api_key: e.target.value })} />
            <span className="hint">Stored encrypted. You will not be able to read it again. Leave empty to let agents pass their own.</span></div>
          <fieldset className="stack" style={{ border: 0, padding: 0, margin: 0 }}><legend className="small" style={{ fontWeight: 600 }}>Models</legend>
            {rows.map((r, i) => (
              <div key={i} className="row">
                <input aria-label={`Alias ${i + 1}`} placeholder="Alias agents use" type="text" value={r.alias} onChange={(e) => setRow(i, { alias: e.target.value })} style={{ width: "9rem" }} />
                <input aria-label={`Model ${i + 1}`} placeholder="Provider model" type="text" value={r.model} onChange={(e) => setRow(i, { model: e.target.value })} style={{ width: "9rem" }} />
                <input aria-label={`Input price per million tokens ${i + 1}`} placeholder="In $/M" type="number" min="0" step="any" value={r.inUsd} onChange={(e) => setRow(i, { inUsd: e.target.value })} style={{ width: "6rem" }} />
                <input aria-label={`Output price per million tokens ${i + 1}`} placeholder="Out $/M" type="number" min="0" step="any" value={r.outUsd} onChange={(e) => setRow(i, { outUsd: e.target.value })} style={{ width: "6rem" }} />
              </div>))}
            <div><button type="button" className="btn quiet" onClick={() => setRows([...rows, { ...EMPTY_ROW }])}>Add model</button></div>
            <span className="hint">Prices feed the cost budgets. Without a price a model's cost is not counted.</span>
          </fieldset>
          <div className="row"><button className="btn primary" type="submit" disabled={create.isPending}>Add provider</button><button type="button" className="btn quiet" onClick={() => setAdding(false)}>Cancel</button></div>
        </form>
      </Modal>
      <Modal open={!!rekey} onClose={() => setRekey(null)} title={`${rekey?.has_key ? "Replace" : "Set"} key for ${rekey?.name}`}>
        <div className="field"><label htmlFor="new-key">New API key</label><input id="new-key" type="password" autoComplete="off" value={newKey} onChange={(e) => setNewKey(e.target.value)} />
          <span className="hint">Write-only. It is encrypted and never shown again.</span></div>
        <div className="row"><button className="btn primary" disabled={!newKey || saveKey.isPending} onClick={() => rekey && saveKey.mutate(rekey)}>Save key</button><button className="btn quiet" onClick={() => setRekey(null)}>Cancel</button></div>
      </Modal>
      <ConfirmTyped open={!!removing} onClose={() => setRemoving(null)} onConfirm={() => removing && remove.mutate(removing)} title="Remove this provider?"
        phrase={removing?.name ?? ""} action="Remove provider" busy={remove.isPending}><p>Agents that use <strong>{removing?.name}</strong> must be moved to another provider first.</p></ConfirmTyped>
    </section>
  );
}

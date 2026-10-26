import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { ApiProblem, get, post, type Page, type Schemas } from "../../api/client";
import { CopyField } from "../../ui/CopyField";
import { Drawer } from "../../ui/Drawer";
import { useToast } from "../../ui/toast";
import { SnippetTabs } from "./SnippetTabs";

export const SLUG_RE = /^[a-z0-9][a-z0-9-]{1,62}$/;

export function slugError(slug: string): string | null {
  if (!slug) return null;
  if (slug.length < 2) return "Use at least 2 characters.";
  if (!SLUG_RE.test(slug)) return "Use lowercase letters, numbers and hyphens, starting with a letter or number.";
  return null;
}

type Agent = Schemas["AgentRead"];

export function ConnectAgentFlow({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [form, setForm] = useState({ slug: "", name: "", owner: "", purpose: "", risk_tier: "medium", upstream_id: "" });
  const [agent, setAgent] = useState<Agent | null>(null);
  const [key, setKey] = useState<Schemas["KeyIssued"] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const upstreams = useQuery({ queryKey: ["upstreams"], queryFn: () => get<Schemas["UpstreamRead"][]>("/v1/admin/upstreams"), enabled: open });

  const create = useMutation({
    mutationFn: async () => {
      const a = await post<Agent>("/v1/admin/agents", { ...form, upstream_id: form.upstream_id || null });
      const k = await post<Schemas["KeyIssued"]>(`/v1/admin/agents/${a.slug}/keys`);
      return { a, k };
    },
    onSuccess: ({ a, k }) => { setAgent(a); setKey(k); setStep(2); setError(null); void qc.invalidateQueries({ queryKey: ["agents"] }); },
    onError: (e) => setError(e instanceof ApiProblem ? e.detail : "Could not create the agent. Try again."),
  });

  const sErr = slugError(form.slug);
  const valid = SLUG_RE.test(form.slug) && form.name.trim() !== "" && form.owner.trim() !== "";
  const submit = (e: FormEvent) => { e.preventDefault(); if (valid) create.mutate(); };
  const close = () => { setStep(1); setForm({ slug: "", name: "", owner: "", purpose: "", risk_tier: "medium", upstream_id: "" }); setAgent(null); setKey(null); setError(null); onClose(); };

  return (
    <Drawer open={open} onClose={close} title="Connect agent" wide>
      <ol className="row small muted" style={{ listStyle: "none", padding: 0, margin: 0 }} aria-label="Steps">
        {["Create", "Copy the key", "Connect"].map((s, i) => (
          <li key={s} aria-current={step === i + 1 ? "step" : undefined} style={{ fontWeight: step === i + 1 ? 600 : 400, color: step === i + 1 ? "var(--ink)" : undefined }}>{i + 1}. {s}</li>
        ))}
      </ol>
      {step === 1 && (
        <form className="stack" onSubmit={submit}>
          {error && <p role="alert" className="field"><span className="err">{error}</span></p>}
          <div className="field"><label htmlFor="slug">Agent id</label>
            <input id="slug" type="text" value={form.slug} onChange={(e) => setForm({ ...form, slug: e.target.value })} aria-invalid={!!sErr} aria-describedby="slug-h" autoComplete="off" />
            <span id="slug-h" className={sErr ? "err" : "hint"}>{sErr ?? "Lowercase letters, numbers and hyphens. It cannot be changed later."}</span></div>
          <div className="field"><label htmlFor="name">Name</label><input id="name" type="text" maxLength={100} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></div>
          <div className="field"><label htmlFor="owner">Owner</label><input id="owner" type="text" maxLength={200} value={form.owner} onChange={(e) => setForm({ ...form, owner: e.target.value })} />
            <span className="hint">Who answers when this agent misbehaves.</span></div>
          <div className="field"><label htmlFor="purpose">Purpose</label><input id="purpose" type="text" maxLength={1000} value={form.purpose} onChange={(e) => setForm({ ...form, purpose: e.target.value })} /></div>
          <div className="field"><label htmlFor="tier">Risk tier</label>
            <select id="tier" value={form.risk_tier} onChange={(e) => setForm({ ...form, risk_tier: e.target.value })}><option>low</option><option>medium</option><option>high</option></select></div>
          <div className="field"><label htmlFor="up">Model provider</label>
            <select id="up" value={form.upstream_id} onChange={(e) => setForm({ ...form, upstream_id: e.target.value })}>
              <option value="">None yet (use the check API only)</option>
              {upstreams.data?.map((u) => <option key={u.id} value={u.id}>{u.name}</option>)}
            </select></div>
          <div className="row"><button className="btn primary" type="submit" disabled={!valid || create.isPending}>{create.isPending ? "Creating" : "Create agent"}</button></div>
        </form>
      )}
      {step === 2 && key && agent && (
        <div className="stack">
          <p><strong>Copy this key now.</strong> It is shown once. AgentShield stores only a hash, so a lost key must be replaced.</p>
          <CopyField label="API key" value={key.key} />
          <div className="row"><button className="btn primary" onClick={() => setStep(3)}>I have copied the key</button></div>
        </div>
      )}
      {step === 3 && agent && key && (
        <div className="stack">
          <p>Point your agent at AgentShield with one of these.</p>
          <SnippetTabs slug={agent.slug} apiKey={key.key} />
          <FirstRequest slug={agent.slug} />
          <div className="row"><button className="btn primary" onClick={() => { toast(`Agent ${agent.slug} is ready`); close(); }}>Done</button></div>
        </div>
      )}
    </Drawer>
  );
}

function FirstRequest({ slug }: { slug: string }) {
  const [watching, setWatching] = useState(false);
  const q = useQuery({
    queryKey: ["first-event", slug], enabled: watching, refetchInterval: (query) => ((query.state.data?.items.length ?? 0) > 0 ? false : 2000),
    queryFn: () => get<Page<Schemas["EventRead"]>>("/v1/admin/events", { agent: slug, limit: 1 }),
  });
  const first = q.data?.items[0];
  return (
    <div className="card stack" aria-live="polite">
      <div className="row between"><h3>Test the connection</h3>
        {!watching && <button className="btn" onClick={() => setWatching(true)}>Send a test request</button>}</div>
      {!watching && <p className="muted">Run the snippet with any prompt. Then start watching and the first request appears here.</p>}
      {watching && !first && <p>Waiting for the first request from {slug}. Run the snippet above.</p>}
      {first && <p><strong>First request received.</strong> {first.type} at {new Date(first.ts).toLocaleTimeString()}. The agent is connected.</p>}
    </div>
  );
}

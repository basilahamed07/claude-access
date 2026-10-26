import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { ApiProblem, apiRaw, get, post, type Page, type Schemas } from "../../api/client";
import { useSession } from "../../api/session";
import { ConfirmTyped } from "../../ui/ConfirmTyped";
import { EmptyState, ErrorState, Skeleton } from "../../ui/states";
import { useToast } from "../../ui/toast";
import { SimulatePanel, loosened, type Simulation } from "./SimulatePanel";
import { YamlEditor, type LineMarker } from "./YamlEditor";

type Version = Schemas["PolicyVersionRead"];

export const STARTER = `version: 1
# Everything not allowed below is blocked (default deny).
scopes: {}
tools:
  read_email: { effect_tag: read }
  send_email: { effect_tag: external }
rules:
  - id: allow-read-mail
    effect: allow
    tool: read_email
  - id: ask-before-sending
    effect: ask
    tool: send_email
    reason: "Sending email needs approval"
`;

export default function PoliciesPage() {
  const { slug } = useParams();
  const navigate = useNavigate();
  const agents = useQuery({ queryKey: ["agents-all"], queryFn: () => get<Page<Schemas["AgentRead"]>>("/v1/admin/agents", { limit: 200 }) });
  const first = agents.data?.items[0]?.slug;
  useEffect(() => { if (!slug && first) navigate(`/policies/${first}`, { replace: true }); }, [slug, first, navigate]);

  return (
    <>
      <header>
        <div><h1>Policies</h1><p className="muted">Save, simulate against real traffic, then activate.</p></div>
        {agents.data && agents.data.items.length > 0 && (
          <div className="field"><label htmlFor="agent">Agent</label>
            <select id="agent" value={slug ?? ""} onChange={(e) => navigate(`/policies/${e.target.value}`)}>
              {agents.data.items.map((a) => <option key={a.id} value={a.slug}>{a.name} ({a.slug})</option>)}
            </select></div>
        )}
      </header>
      {agents.isLoading ? <Skeleton /> : agents.error ? <ErrorState error={agents.error} onRetry={() => void agents.refetch()} />
        : agents.data!.items.length === 0 ? <EmptyState title="No agents yet">Connect an agent first. Each agent has its own policy.</EmptyState>
        : slug ? <PolicyEditor key={slug} slug={slug} /> : null}
    </>
  );
}

function PolicyEditor({ slug }: { slug: string }) {
  const qc = useQueryClient();
  const toast = useToast();
  const { can } = useSession();
  const canEdit = can("admin");
  const agent = useQuery({ queryKey: ["agent", slug], queryFn: () => apiRaw<Schemas["AgentRead"]>("GET", `/v1/admin/agents/${slug}`) });
  const versions = useQuery({ queryKey: ["versions", slug], queryFn: () => get<Version[]>(`/v1/admin/agents/${slug}/policy/versions`) });
  const [selected, setSelected] = useState<number | null>(null);
  const [text, setText] = useState<string | null>(null);
  const [markers, setMarkers] = useState<LineMarker[]>([]);
  const [problem, setProblem] = useState<string | null>(null);
  const [sims, setSims] = useState<Record<number, Simulation>>({});
  const [confirm, setConfirm] = useState<{ version: number; steps: number } | null>(null);
  const [stale, setStale] = useState(false);

  const active = agent.data?.data.active_policy_version ?? null;
  const list = versions.data;
  useEffect(() => { if (list && selected === null && text === null) setSelected(active ?? list[0]?.version ?? null); }, [list, active, selected, text]);
  const current = useQuery({ queryKey: ["version", slug, selected], enabled: selected !== null, queryFn: () => get<Version>(`/v1/admin/agents/${slug}/policy/versions/${selected}`) });
  const [loadedFor, setLoadedFor] = useState<string | null>(null);
  const key = `${slug}:${selected}`;
  useEffect(() => { if (current.data?.yaml != null && loadedFor !== key) { setText(current.data.yaml); setLoadedFor(key); setMarkers([]); setProblem(null); } }, [current.data, key, loadedFor]);
  useEffect(() => { if (list && list.length === 0 && text === null) setText(STARTER); }, [list, text]);

  const saved = current.data?.yaml ?? null;
  const dirty = text !== null && text !== saved;
  const doc = text ?? "";

  const save = useMutation({
    mutationFn: () => post<Version>(`/v1/admin/agents/${slug}/policy/versions`, { yaml: doc }),
    onSuccess: (v) => {
      toast(`Saved as v${v.version}`); setMarkers([]); setProblem(null);
      setLoadedFor(`${slug}:${v.version}`); setSelected(v.version);
      qc.setQueryData(["version", slug, v.version], v);
      void qc.invalidateQueries({ queryKey: ["versions", slug] });
    },
    onError: (e) => {
      if (e instanceof ApiProblem && e.code === "policy_invalid") {
        setMarkers(e.errors.filter((x) => x.line).map((x) => ({ line: x.line!, message: x.message })));
        setProblem(`Policy not saved. ${e.detail}`);
      } else setProblem(e instanceof ApiProblem ? e.detail : "Could not save the policy. Try again.");
    },
  });

  const simulate = async (version: number): Promise<Simulation> => {
    const r = await post<Simulation>(`/v1/admin/agents/${slug}/policy/simulate`, { version, since: "7d" });
    setSims((s) => ({ ...s, [version]: r }));
    return r;
  };
  const sim = useMutation({ mutationFn: (v: number) => simulate(v), onError: (e) => toast(e instanceof ApiProblem ? e.detail : "Could not simulate", true) });

  const activate = useMutation({
    mutationFn: async (version: number) => {
      const etag = agent.data?.etag;
      return post<Version>(`/v1/admin/agents/${slug}/policy/versions/${version}/activate`, {}, etag ? { "If-Match": etag } : undefined);
    },
    onSuccess: (v) => { toast(`Policy v${v.version} is active`); setConfirm(null); setStale(false); void qc.invalidateQueries({ queryKey: ["agent", slug] }); void qc.invalidateQueries({ queryKey: ["versions", slug] }); void qc.invalidateQueries({ queryKey: ["agents"] }); },
    onError: (e) => {
      setConfirm(null);
      if (e instanceof ApiProblem && e.status === 412) { setStale(true); void qc.invalidateQueries({ queryKey: ["agent", slug] }); void qc.invalidateQueries({ queryKey: ["versions", slug] }); }
      else toast(e instanceof ApiProblem ? e.detail : "Could not activate the policy", true);
    },
  });

  const startActivate = async () => {
    if (selected === null) return;
    try {
      const s = sims[selected] ?? await simulate(selected);
      const steps = loosened(s).length;
      if (steps > 0) setConfirm({ version: selected, steps }); else activate.mutate(selected);
    } catch (e) { toast(e instanceof ApiProblem ? e.detail : "Could not check what this change would do", true); }
  };

  const markerList = useMemo(() => markers, [markers]);
  if (agent.isLoading || versions.isLoading) return <Skeleton />;
  if (agent.error || versions.error) return <ErrorState error={agent.error ?? versions.error} onRetry={() => { void agent.refetch(); void versions.refetch(); }} />;

  return (
    <div className="cols">
      <div className="stack">
        <h2 id="versions-h">Versions</h2>
        {list!.length === 0 ? <p className="muted">No versions yet. Save the starter policy below to begin.</p> : (
          <ul className="versions" aria-labelledby="versions-h">
            {list!.map((v) => (
              <li key={v.version}><button aria-current={selected === v.version} onClick={() => { setSelected(v.version); setText(null); setLoadedFor(null); }}>
                <span>v{v.version}</span>{v.active ? <span className="badge badge--allow">Active</span> : <span className="small muted">{new Date(v.created_at).toLocaleDateString()}</span>}
              </button></li>
            ))}
          </ul>
        )}
      </div>
      <div className="stack">
        {stale && <div role="alert" className="error-state"><p>This agent's policy changed since you opened it. Reload to see the latest version.</p>
          <button className="btn" onClick={() => { setStale(false); void agent.refetch(); void versions.refetch(); }}>Reload</button></div>}
        {problem && <div role="alert" className="error-state"><p>{problem}</p>
          {markerList.length > 1 && <ul className="markers">{markerList.map((m, i) => <li key={i}>Line {m.line}: {m.message}</li>)}</ul>}</div>}
        <YamlEditor value={doc} onChange={(v) => setText(v)} markers={markerList} label="Policy YAML" readOnly={!canEdit} />
        <div className="row">
          {canEdit && <button className="btn primary" disabled={!dirty || save.isPending} onClick={() => save.mutate()}>{save.isPending ? "Saving" : "Save as new version"}</button>}
          <button className="btn" disabled={selected === null || dirty || sim.isPending || !can("analyst")} onClick={() => selected !== null && sim.mutate(selected)}
            title={dirty ? "Save the policy first, then simulate it" : undefined}>{sim.isPending ? "Simulating" : "Simulate on last 7 days"}</button>
          {canEdit && <button className="btn" disabled={selected === null || dirty || selected === active || activate.isPending} onClick={() => void startActivate()}>Activate policy</button>}
          {dirty && <span className="small muted">Unsaved changes</span>}
        </div>
        {selected !== null && sims[selected] && <SimulatePanel sim={sims[selected]} version={selected} />}
      </div>
      <ConfirmTyped open={!!confirm} onClose={() => setConfirm(null)} onConfirm={() => confirm && activate.mutate(confirm.version)}
        title={`Activate v${confirm?.version}?`} phrase={slug} action="Activate policy" busy={activate.isPending}>
        <p><strong>This loosens the policy.</strong> {confirm?.steps} recent {confirm?.steps === 1 ? "call that was" : "calls that were"} blocked or held would now be cleared. Review them in the simulation first.</p>
      </ConfirmTyped>
    </div>
  );
}

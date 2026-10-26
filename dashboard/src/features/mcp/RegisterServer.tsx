import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { ApiProblem, post, type Schemas } from "../../api/client";
import { Drawer } from "../../ui/Drawer";
import { useToast } from "../../ui/toast";

export const CAPABILITIES = [["exec", "Run commands or code"], ["filesystem", "Read or write files"], ["network", "Call other web services"], ["database", "Query databases"],
  ["external", "Send things outside (email, messages, payments)"], ["credentials", "Handle passwords or tokens"]] as const;
const NAME_RE = /^[a-z0-9][a-z0-9-]{1,40}$/;

export function parseManifest(text: string): { tools: unknown[] } | { error: string } {
  try {
    const v = JSON.parse(text);
    const tools = Array.isArray(v) ? v : v?.tools;
    if (!Array.isArray(tools) || tools.length === 0) return { error: "Paste the server's tools/list result: a JSON list of tools, or an object with a \"tools\" list." };
    if (!tools.every((t) => t && typeof t.name === "string")) return { error: "Every tool needs a \"name\"." };
    return { tools };
  } catch { return { error: "That is not valid JSON." }; }
}

export function RegisterServer({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: (id: string) => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [mode, setMode] = useState<"url" | "paste">("url");
  const [f, setF] = useState({ name: "", owner: "", purpose: "", url: "", token: "", manifest: "" });
  const [caps, setCaps] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const manifest = mode === "paste" && f.manifest ? parseManifest(f.manifest) : null;
  const manifestError = manifest && "error" in manifest ? manifest.error : null;
  const valid = NAME_RE.test(f.name) && f.owner.trim() !== "" && (mode === "url" ? /^https?:\/\/.+/.test(f.url) : !!manifest && !manifestError);

  const create = useMutation({
    mutationFn: () => post<Schemas["McpServerDetail"]>("/v1/admin/mcp-servers", {
      name: f.name, owner: f.owner, purpose: f.purpose, declared_capabilities: caps,
      ...(mode === "url" ? { url: f.url, auth_token: f.token || null } : { tools: (manifest as { tools: unknown[] }).tools }),
    }),
    onSuccess: (d) => { toast("Server scanned"); void qc.invalidateQueries({ queryKey: ["mcp"] }); setError(null); onDone(d.id); },
    onError: (e) => setError(e instanceof ApiProblem ? e.detail : "Could not register the server."),
  });
  const submit = (e: FormEvent) => { e.preventDefault(); if (valid) create.mutate(); };
  const toggle = (c: string) => setCaps((xs) => (xs.includes(c) ? xs.filter((x) => x !== c) : [...xs, c]));

  return (
    <Drawer open={open} onClose={onClose} title="Register an MCP server" wide>
      <form className="stack" onSubmit={submit}>
        <p className="muted">AgentShield reads the server's tool list, scans every description for instructions aimed at the model, checks what the tools can do against what you declare, and recommends a verdict. A person approves.</p>
        {error && <p role="alert" className="field"><span className="err">{error}</span></p>}
        <div className="field"><label htmlFor="m-name">Name</label>
          <input id="m-name" type="text" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} aria-invalid={f.name !== "" && !NAME_RE.test(f.name)} aria-describedby="m-name-h" />
          <span id="m-name-h" className={f.name !== "" && !NAME_RE.test(f.name) ? "err" : "hint"}>Lowercase letters, numbers and hyphens. Tools appear to agents as name__tool.</span></div>
        <div className="field"><label htmlFor="m-owner">Owner</label><input id="m-owner" type="text" value={f.owner} onChange={(e) => setF({ ...f, owner: e.target.value })} /></div>
        <div className="field"><label htmlFor="m-purpose">What it is for</label><input id="m-purpose" type="text" value={f.purpose} onChange={(e) => setF({ ...f, purpose: e.target.value })} /></div>
        <fieldset className="stack" style={{ border: 0, padding: 0, margin: 0 }}><legend style={{ fontWeight: 600 }}>What this server is meant to be able to do</legend>
          {CAPABILITIES.map(([c, label]) => <label key={c} className="row"><input type="checkbox" checked={caps.includes(c)} onChange={() => toggle(c)} /> {label}</label>)}
          <span className="hint">Anything a tool can do beyond this is reported as a finding.</span></fieldset>
        <div role="tablist" aria-label="How to give AgentShield the tools" className="row">
          <button type="button" role="tab" aria-selected={mode === "url"} className={`btn ${mode === "url" ? "primary" : "quiet"}`} onClick={() => setMode("url")}>Connect to a URL</button>
          <button type="button" role="tab" aria-selected={mode === "paste"} className={`btn ${mode === "paste" ? "primary" : "quiet"}`} onClick={() => setMode("paste")}>Paste the tool list</button>
        </div>
        {mode === "url" ? (
          <>
            <div className="field"><label htmlFor="m-url">Server URL</label><input id="m-url" type="url" placeholder="https://mcp.example.com/mcp" value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} />
              <span className="hint">Streamable HTTP. Private and internal addresses are refused.</span></div>
            <div className="field"><label htmlFor="m-token">Bearer token (optional)</label><input id="m-token" type="password" autoComplete="off" value={f.token} onChange={(e) => setF({ ...f, token: e.target.value })} />
              <span className="hint">Stored encrypted and never shown again.</span></div>
          </>
        ) : (
          <div className="field"><label htmlFor="m-man">Tool list (JSON)</label><textarea id="m-man" rows={8} value={f.manifest} onChange={(e) => setF({ ...f, manifest: e.target.value })} aria-invalid={!!manifestError} />
            <span className={manifestError ? "err" : "hint"}>{manifestError ?? "The result of tools/list. A server added this way cannot be checked for changes automatically."}</span></div>
        )}
        <div className="row"><button className="btn primary" type="submit" disabled={!valid || create.isPending}>{create.isPending ? "Scanning" : "Register and scan"}</button>
          <button type="button" className="btn quiet" onClick={onClose}>Cancel</button></div>
      </form>
    </Drawer>
  );
}

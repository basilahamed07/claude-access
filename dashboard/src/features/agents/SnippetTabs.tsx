import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { get, type Schemas } from "../../api/client";
import { Value } from "../../ui/Value";
import { Skeleton } from "../../ui/states";

export const LANGS = [
  { id: "python-openai", label: "Python OpenAI SDK" },
  { id: "python-anthropic", label: "Python Anthropic SDK" },
  { id: "curl", label: "curl" },
  { id: "claude-code", label: "Claude Code env" },
] as const;

/** Connection snippets. The server writes a placeholder key; the key just issued (if any) is filled in locally. */
export function SnippetTabs({ slug, apiKey }: { slug: string; apiKey?: string }) {
  const [lang, setLang] = useState<(typeof LANGS)[number]["id"]>("python-openai");
  const q = useQuery({ queryKey: ["snippet", slug, lang], queryFn: () => get<Schemas["Snippet"]>(`/v1/admin/agents/${slug}/snippet`, { lang }) });
  const code = q.data ? (apiKey ? q.data.code.replaceAll("ask_live_...", apiKey) : q.data.code) : "";
  return (
    <div className="stack">
      <div role="tablist" aria-label="Language" className="row">
        {LANGS.map((l) => (
          <button key={l.id} role="tab" id={`tab-${l.id}`} aria-selected={lang === l.id} aria-controls="snippet-panel"
            className={`btn ${lang === l.id ? "primary" : "quiet"}`} onClick={() => setLang(l.id)}>{l.label}</button>
        ))}
      </div>
      <div role="tabpanel" id="snippet-panel" aria-labelledby={`tab-${lang}`}>
        {q.isLoading ? <Skeleton rows={4} /> : q.error ? <p role="alert">Could not load the snippet. Try again.</p> : <Value value={code} block limit={4000} />}
      </div>
    </div>
  );
}

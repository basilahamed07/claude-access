import { yaml } from "@codemirror/lang-yaml";
import { type Diagnostic, lintGutter, setDiagnostics } from "@codemirror/lint";
import { EditorState } from "@codemirror/state";
import { EditorView } from "@codemirror/view";
import { basicSetup } from "codemirror";
import { useEffect, useRef } from "react";

export interface LineMarker { line: number; message: string }

/** YAML editor (CodeMirror 6). Server-side validation errors appear as markers on their line. */
export function YamlEditor({ value, onChange, markers, label, readOnly = false }: {
  value: string; onChange: (v: string) => void; markers: LineMarker[]; label: string; readOnly?: boolean;
}) {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  const change = useRef(onChange);
  change.current = onChange;

  useEffect(() => {
    if (!host.current) return;
    const v = new EditorView({
      parent: host.current,
      state: EditorState.create({
        doc: value,
        extensions: [
          basicSetup, yaml(), lintGutter(), EditorView.lineWrapping, EditorState.readOnly.of(readOnly),
          EditorView.contentAttributes.of({ "aria-label": label, "aria-multiline": "true" }),
          EditorView.updateListener.of((u) => { if (u.docChanged) change.current(u.state.doc.toString()); }),
          EditorView.theme({ "&": { backgroundColor: "var(--panel)", color: "var(--ink)", fontSize: "0.875rem", maxHeight: "32rem" },
            ".cm-scroller": { fontFamily: "var(--font-mono)", overflow: "auto" }, ".cm-gutters": { backgroundColor: "var(--panel-sunk)", color: "var(--ink-soft)", border: "none" },
            "&.cm-focused": { outline: "2px solid var(--recorder)", outlineOffset: "2px" }, ".cm-activeLine": { backgroundColor: "transparent" } }),
        ],
      }),
    });
    view.current = v;
    return () => { v.destroy(); view.current = null; };
    // the editor is created once; later value changes are applied below
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [readOnly, label]);

  useEffect(() => {
    const v = view.current;
    if (v && v.state.doc.toString() !== value) v.dispatch({ changes: { from: 0, to: v.state.doc.length, insert: value } });
  }, [value]);

  useEffect(() => {
    const v = view.current;
    if (!v) return;
    const diags: Diagnostic[] = markers.map((m) => {
      const line = v.state.doc.line(Math.min(Math.max(m.line, 1), v.state.doc.lines));
      return { from: line.from, to: Math.max(line.to, line.from + 1 <= v.state.doc.length ? line.from + 1 : line.from), severity: "error", message: m.message };
    });
    v.dispatch(setDiagnostics(v.state, diags));
  }, [markers, value]);

  return <div ref={host} className="yaml-editor" data-testid="yaml-editor" />;
}

export function editorText(root: ParentNode): string {
  return root.querySelector(".cm-content")?.textContent ?? "";
}

import { useEffect, useState } from "react";

type Theme = "light" | "dark" | "system";
const KEY = "agentshield.theme";

export function readTheme(): Theme {
  try { const v = localStorage.getItem(KEY); return v === "light" || v === "dark" ? v : "system"; } catch { return "system"; }
}
export function applyTheme(t: Theme) {
  const root = document.documentElement;
  if (t === "system") root.removeAttribute("data-theme"); else root.setAttribute("data-theme", t);
}
export function saveTheme(t: Theme) {
  try { if (t === "system") localStorage.removeItem(KEY); else localStorage.setItem(KEY, t); } catch { /* storage blocked: the choice lasts for this page only */ }
}

export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(readTheme);
  useEffect(() => { applyTheme(theme); }, [theme]);
  return (
    <div className="field">
      <label htmlFor="theme">Theme</label>
      <select id="theme" value={theme} onChange={(e) => { const t = e.target.value as Theme; setTheme(t); saveTheme(t); }}>
        <option value="system">System</option>
        <option value="light">Light</option>
        <option value="dark">Dark</option>
      </select>
    </div>
  );
}

/** A reviewer's note survives a session expiry: it is kept per approval for this tab and restored after sign in. */
const key = (id: string) => `agentshield.approval-note.${id}`;
export function loadDraft(id: string): string {
  try { return sessionStorage.getItem(key(id)) ?? ""; } catch { return ""; }
}
export function saveDraft(id: string, note: string) {
  try { if (note) sessionStorage.setItem(key(id), note); else sessionStorage.removeItem(key(id)); } catch { /* storage blocked */ }
}

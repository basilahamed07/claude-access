import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { ApiProblem, patch, post, type Schemas } from "../../api/client";
import { useList } from "../../api/queries";
import { useSession } from "../../api/session";
import { Table, type Column } from "../../ui/Table";
import { useToast } from "../../ui/toast";

type User = Schemas["UserRead"];
const ROLES = [["viewer", "Viewer: read only"], ["analyst", "Analyst: decide approvals, replay, export"], ["admin", "Admin: everything"]] as const;

export function UsersPanel() {
  const qc = useQueryClient();
  const toast = useToast();
  const { me } = useSession();
  const list = useList<User>(["users"], "/v1/admin/users");
  const [form, setForm] = useState({ email: "", password: "", role: "viewer" });
  const [error, setError] = useState<string | null>(null);
  const refresh = () => void qc.invalidateQueries({ queryKey: ["users"] });
  const create = useMutation({
    mutationFn: () => post<User>("/v1/admin/users", form),
    onSuccess: () => { toast("User added"); setForm({ email: "", password: "", role: "viewer" }); setError(null); refresh(); },
    onError: (e) => setError(e instanceof ApiProblem ? e.detail : "Could not add the user"),
  });
  const update = useMutation({
    mutationFn: ({ id, body }: { id: string; body: object }) => patch<User>(`/v1/admin/users/${id}`, body),
    onSuccess: () => { toast("User updated"); refresh(); },
    onError: (e) => toast(e instanceof ApiProblem ? e.detail : "Could not update the user", true),
  });
  const cols: Column<User>[] = [
    { key: "email", header: "Email", render: (u) => <span>{u.email}{u.id === me?.user_id ? <span className="muted"> (you)</span> : null}</span> },
    { key: "role", header: "Role", render: (u) => (
      <select aria-label={`Role for ${u.email}`} value={u.role} onChange={(e) => update.mutate({ id: u.id, body: { role: e.target.value } })}>
        {ROLES.map(([v]) => <option key={v} value={v}>{v}</option>)}</select>) },
    { key: "status", header: "Status", render: (u) => u.disabled_at ? "Disabled" : "Active" },
    { key: "act", header: "Access", render: (u) => (
      <button className="btn quiet" onClick={() => update.mutate({ id: u.id, body: { disabled: !u.disabled_at } })}>{u.disabled_at ? "Enable user" : "Disable user"}</button>) },
  ];
  const submit = (e: FormEvent) => { e.preventDefault(); create.mutate(); };
  return (
    <section className="stack" aria-labelledby="users-h">
      <h2 id="users-h">Users and roles</h2>
      <Table caption="Users" columns={cols} rows={list.rows} rowKey={(u) => u.id} loading={list.isLoading} error={list.error} onRetry={() => void list.refetch()}
        hasMore={list.hasNextPage} onLoadMore={list.loadMore} empty={{ title: "No users" }} />
      <form className="card stack" onSubmit={submit}>
        <h3>Add a user</h3>
        {error && <p role="alert" className="field"><span className="err">{error}</span></p>}
        <div className="field"><label htmlFor="u-email">Email</label><input id="u-email" type="email" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></div>
        <div className="field"><label htmlFor="u-pw">Password</label><input id="u-pw" type="password" minLength={12} required autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
          <span className="hint">At least 12 characters.</span></div>
        <div className="field"><label htmlFor="u-role">Role</label><select id="u-role" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
          {ROLES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></div>
        <div><button className="btn primary" type="submit" disabled={create.isPending}>Add user</button></div>
      </form>
    </section>
  );
}

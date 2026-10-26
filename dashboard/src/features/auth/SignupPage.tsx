import { useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Link, Navigate, useNavigate } from "react-router-dom";
import { ApiProblem, api, setCsrf, type Schemas } from "../../api/client";
import { useSession } from "../../api/session";

export const MIN_PASSWORD = 12;

export function SignupPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { me, loading } = useSession();
  const [form, setForm] = useState({ tenant_name: "", email: "", password: "" });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState(false);
  // once signed up, the session appears before our own navigate runs: send a new workspace to Agents, an existing session home
  if (!loading && me) return <Navigate to={created ? "/agents" : "/"} replace />;

  const short = form.password.length > 0 && form.password.length < MIN_PASSWORD;
  const valid = form.tenant_name.trim().length >= 2 && /.+@.+\..+/.test(form.email) && form.password.length >= MIN_PASSWORD;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!valid) return;
    setBusy(true);
    setError(null);
    try {
      await api("POST", "/v1/signup", { body: form, quiet: true });
      const r = await api<Schemas["LoginResponse"]>("POST", "/v1/auth/login", { body: { email: form.email, password: form.password }, quiet: true });
      setCsrf(r.csrf_token);
      setCreated(true);
      await qc.invalidateQueries({ queryKey: ["me"] });
      navigate("/agents", { replace: true });
    } catch (err) {
      if (err instanceof ApiProblem && err.status === 403) setError("Sign-up is turned off on this installation. Ask an administrator to add you.");
      else if (err instanceof ApiProblem && err.status === 429) setError("Too many sign-ups from this address. Try again later.");
      else setError(err instanceof ApiProblem ? err.detail : "Could not create the workspace. Try again.");
    } finally { setBusy(false); }
  };

  return (
    <main className="login" id="main">
      <form className="card stack" onSubmit={submit} aria-labelledby="signup-h">
        <h1 id="signup-h">Create your workspace</h1>
        <p className="muted">One workspace holds your agents, policies and audit log. You become its administrator.</p>
        {error && <p role="alert" className="field"><span className="err">{error}</span></p>}
        <div className="field"><label htmlFor="ws">Workspace name</label>
          <input id="ws" type="text" maxLength={100} required value={form.tenant_name} onChange={(e) => setForm({ ...form, tenant_name: e.target.value })} /></div>
        <div className="field"><label htmlFor="em">Your email</label>
          <input id="em" type="email" autoComplete="username" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></div>
        <div className="field"><label htmlFor="pw">Password</label>
          <input id="pw" type="password" autoComplete="new-password" required aria-invalid={short} aria-describedby="pw-h" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
          <span id="pw-h" className={short ? "err" : "hint"}>{short ? `Use at least ${MIN_PASSWORD} characters (${form.password.length} so far).` : `At least ${MIN_PASSWORD} characters. A short passphrase works well.`}</span></div>
        <button className="btn primary" type="submit" disabled={!valid || busy}>{busy ? "Creating" : "Create workspace"}</button>
        <p className="small">Already have one? <Link to="/login">Sign in</Link></p>
      </form>
    </main>
  );
}

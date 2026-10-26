import { useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { Navigate, useNavigate, useSearchParams } from "react-router-dom";
import { ApiProblem, api, setCsrf, type Schemas } from "../../api/client";
import { safeNext, useSession } from "../../api/session";

export function LoginPage() {
  const [params] = useSearchParams();
  const next = safeNext(params.get("next"));
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { me, loading } = useSession();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (!loading && me) return <Navigate to={next} replace />;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await api<Schemas["LoginResponse"]>("POST", "/v1/auth/login", { body: { email, password }, quiet: true });
      setCsrf(r.csrf_token);
      await qc.invalidateQueries({ queryKey: ["me"] });
      navigate(next, { replace: true });
    } catch (err) {
      setError(err instanceof ApiProblem
        ? (err.status === 429 ? err.detail : err.status === 401 ? "Email or password is wrong. Check both and try again." : err.detail)
        : "Could not sign in. Try again.");
    } finally { setBusy(false); }
  };

  return (
    <main className="login" id="main">
      <form className="card stack" onSubmit={submit} aria-labelledby="login-h">
        <h1 id="login-h">Sign in to AgentShield</h1>
        {error && <p role="alert" className="field"><span className="err">{error}</span></p>}
        <div className="field"><label htmlFor="email">Email</label>
          <input id="email" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} /></div>
        <div className="field"><label htmlFor="password">Password</label>
          <input id="password" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} /></div>
        <button className="btn primary" type="submit" disabled={busy}>{busy ? "Signing in" : "Sign in"}</button>
      </form>
    </main>
  );
}

import { ApiProblem } from "../../api/client";
import { useSession } from "../../api/session";
import { ErrorState } from "../../ui/states";
import { TenantPanel } from "./TenantPanel";
import { UpstreamsPanel } from "./UpstreamsPanel";
import { UsersPanel } from "./UsersPanel";

export default function SettingsPage() {
  const { can } = useSession();
  if (!can("admin")) return <><header><h1>Settings</h1></header><ErrorState error={new ApiProblem(403, "forbidden", "Settings need the admin role.")} /></>;
  return (
    <>
      <header><div><h1>Settings</h1><p className="muted">Providers, people, protection and how long records are kept.</p></div></header>
      <div className="stack" style={{ gap: "2.5rem" }}>
        <UpstreamsPanel />
        <UsersPanel />
        <TenantPanel />
      </div>
    </>
  );
}

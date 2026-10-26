#!/usr/bin/env python
"""Record docs/demo.gif from the real stack: the unprotected run, the protected run, then the dashboard tape.

Needs: Postgres+Redis (agentshield/scripts/dev-services.sh), the dashboard built (`npm run build` in dashboard/), ffmpeg, and the
demo dependencies in agentshield/.venv. Every frame is a screenshot of something that really ran; nothing is mocked up.
"""

from __future__ import annotations

import html
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
PY = str(ROOT / "agentshield" / ".venv" / "bin" / "python")
sys.path.insert(0, str(ROOT))
OUT = ROOT / "docs" / "demo.gif"
SECONDS = [3.0, 3.5, 3.0, 3.0, 3.0, 3.5, 3.5]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait(url: str, proc: subprocess.Popen[bytes]) -> None:
    for _ in range(200):
        if proc.poll() is not None:
            raise SystemExit(f"{url}: process exited {proc.returncode}")
        try:
            httpx.get(url, timeout=1)
            return
        except httpx.HTTPError:
            time.sleep(0.4)
    raise SystemExit(f"timed out waiting for {url}")


def terminal_page(command: str, output: str, verdict_class: str) -> str:
    return f"""<html><body style="margin:0;background:#0f1720;color:#e4eaee;font:15px/1.5 'Atkinson Hyperlegible Mono',ui-monospace,Menlo,monospace">
<div style="padding:28px 36px;width:1180px"><div style="color:#9fb0bc;margin-bottom:12px">$ {html.escape(command)}</div>
<pre style="margin:0;white-space:pre-wrap;font:inherit">{html.escape(output)}</pre></div>
<div style="position:absolute;left:36px;bottom:36px;font:600 22px system-ui;padding:8px 16px;border-radius:4px;{verdict_class}"></div></body></html>"""


def main() -> int:
    env0 = {**os.environ, "AGENTSHIELD_TEST_DSN": os.environ.get("AGENTSHIELD_TEST_DSN", "postgresql://postgres@localhost:5433/postgres"),
            "AGENTSHIELD_TEST_REDIS": os.environ.get("AGENTSHIELD_TEST_REDIS", "redis://localhost:6380/0")}
    subprocess.run([str(ROOT / "agentshield" / "scripts" / "dev-services.sh")], check=True, capture_output=True)
    api, stub, web = free_port(), free_port(), free_port()
    procs: list[subprocess.Popen[bytes]] = []
    tmp = Path(tempfile.mkdtemp())
    try:
        procs.append(subprocess.Popen([str(ROOT / "agentshield" / "scripts" / "run_stack.sh")], cwd=ROOT / "agentshield", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                      env={**env0, "PORT": str(api), "STACK_DB": f"gif_{secrets.token_hex(3)}", "AGENTSHIELD_ALLOW_PRIVATE_UPSTREAMS": "127.0.0.1",
                                           "AGENTSHIELD_TEST_REDIS": env0["AGENTSHIELD_TEST_REDIS"].rsplit("/", 1)[0] + "/6", "PY": PY}))
        procs.append(subprocess.Popen([PY, "-m", "uvicorn", "demo.email_agent.stub_server:app", "--port", str(stub), "--log-level", "warning"], cwd=ROOT,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={**os.environ, "PYTHONPATH": str(ROOT)}))
        procs.append(subprocess.Popen(["npx", "vite", "preview", "--host", "127.0.0.1", "--port", str(web)], cwd=ROOT / "dashboard", stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, env={**os.environ, "AGENTSHIELD_API": f"http://127.0.0.1:{api}"}))
        wait(f"http://127.0.0.1:{api}/healthz", procs[0])
        wait(f"http://127.0.0.1:{stub}/docs", procs[1])
        wait(f"http://127.0.0.1:{web}", procs[2])

        from demo.email_agent.setup_demo import EMAIL, setup
        keys = setup(f"http://127.0.0.1:{api}", f"http://127.0.0.1:{stub}/v1", password=secrets.token_urlsafe(18))
        run_env = {**os.environ, "PYTHONPATH": str(ROOT), "DEMO_OUTBOX": str(tmp / "outbox.jsonl"), "DEMO_UNPROTECTED_BASE_URL": f"http://127.0.0.1:{stub}/v1",
                   "DEMO_PROTECTED_BASE_URL": keys["DEMO_PROTECTED_BASE_URL"], "DEMO_PROTECTED_API_KEY": keys["DEMO_PROTECTED_API_KEY"]}
        texts = {}
        for name in ("unprotected", "protected"):
            r = subprocess.run([PY, f"demo/email_agent/run_{name}.py"], cwd=ROOT, env=run_env, capture_output=True, text=True, timeout=120)
            if r.returncode != 0:
                raise SystemExit(f"{name} run failed:\n{r.stderr}")
            texts[name] = r.stdout.replace(keys["DEMO_PROTECTED_API_KEY"], "ask_live_...")
        (tmp / "unprotected.txt").write_text(texts["unprotected"])
        (tmp / "protected.txt").write_text(texts["protected"])
        time.sleep(4)                                     # let the audit worker write the trail
        (tmp / "frames").mkdir()
        rc = subprocess.run(["node", "scripts/record_demo_frames.mjs", f"http://127.0.0.1:{web}", EMAIL, keys["DASHBOARD_PASSWORD"], str(tmp)], cwd=ROOT / "dashboard", capture_output=True, text=True)
        if rc.returncode != 0:
            raise SystemExit(rc.stdout + rc.stderr)
        frames = sorted((tmp / "frames").glob("*.png"))
        listing = tmp / "list.txt"
        listing.write_text("".join(f"file '{f}'\nduration {SECONDS[i % len(SECONDS)]}\n" for i, f in enumerate(frames)) + f"file '{frames[-1]}'\n")
        palette = tmp / "palette.png"
        scale = "scale=960:-1:flags=lanczos"
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(listing), "-vf", f"{scale},palettegen=max_colors=96", str(palette)], check=True)
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(listing), "-i", str(palette), "-lavfi", f"{scale}[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=4",
                        "-loop", "0", str(OUT)], check=True)
        print(f"wrote {OUT} ({OUT.stat().st_size / 1e6:.2f} MB, {len(frames)} frames)")
        return 0
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()


if __name__ == "__main__":
    sys.exit(main())

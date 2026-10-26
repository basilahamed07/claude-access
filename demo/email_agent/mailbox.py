"""A tiny mock mailbox and outbox on disk. The outbox is what proves whether the attack worked."""

from __future__ import annotations

import json
import os
from email import policy
from email.parser import BytesParser
from pathlib import Path

HERE = Path(__file__).resolve().parent
MAILBOX_DIR = HERE / "mailbox"


def outbox_path() -> Path:
    return Path(os.environ.get("DEMO_OUTBOX", str(HERE / ".outbox.jsonl")))


def reset_outbox() -> None:
    outbox_path().write_text("", encoding="utf-8")


def read_outbox() -> list[dict[str, str]]:
    p = outbox_path()
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()] if p.exists() else []


def load_messages(folder: str = "INBOX") -> list[dict[str, str]]:
    """Every message as the mail tool would return it: headers plus the body exactly as received (HTML included)."""
    if folder not in {"INBOX", "Invoices"}:
        return []
    out = []
    for p in sorted(MAILBOX_DIR.glob("*.eml")):
        msg = BytesParser(policy=policy.default).parsebytes(p.read_bytes())
        body = msg.get_body(preferencelist=("html", "plain"))
        out.append({"from": str(msg["From"]), "subject": str(msg["Subject"]), "body": body.get_content() if body else ""})
    return out


def send(to: str, subject: str, body: str) -> None:
    with outbox_path().open("a", encoding="utf-8") as f:
        f.write(json.dumps({"to": to, "subject": subject, "body": body}) + "\n")

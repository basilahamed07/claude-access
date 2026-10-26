"""The agent's two tools. Neither knows anything about AgentShield."""

from __future__ import annotations

from langchain_core.tools import tool

from . import mailbox


@tool
def read_email(folder: str = "INBOX") -> str:
    """Read all messages in a mail folder."""
    msgs = mailbox.load_messages(folder)
    if not msgs:
        return f"No messages in {folder}."
    return "\n\n".join(f"From: {m['from']}\nSubject: {m['subject']}\n\n{m['body']}" for m in msgs)


@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email."""
    mailbox.send(to, subject, body)
    return f"Email sent to {to}."


TOOLS = [read_email, send_email]

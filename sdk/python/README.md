# agentshield-sdk

Ask AgentShield before your agent acts. Works with any framework: wrap the tool, keep the model call as it is.

```python
from agentshield_sdk import AgentShield, Blocked, session

shield = AgentShield("https://shield.example.com", "ask_live_...", agent_id="email-reader-01", tenant="acme")

@shield.guard("send_email", "external")
def send_email(to: str, body: str): ...

with session(user_request="Summarize my unread mail"):
    try:
        send_email("x@unknown.com", "...")
    except Blocked as b:
        print(b.reason, b.rule_id, b.trace_id)
```

- `allow` runs the tool. `block` raises `Blocked`. `ask` waits for a reviewer (up to `approval_timeout`, default 300 s) and runs only if approved.
- **If AgentShield cannot be reached** (timeout, DNS, 5xx, rate limit, unreadable reply) only tools tagged `read` run, with a logged warning. Every other tag, and
  any tool without a tag, raises `Blocked(rule_id="agentshield-unreachable")`. Wrong credentials never fall back: they raise `AuthError`.
- Pass what the agent has read from untrusted sources with `session(untrusted_inputs=[UntrustedInput(...)])` so the scanner and the scope check can use it.
- `AsyncAgentShield` is the same API for `async def` tools. `shield.scan(text, source=...)` scans content directly.
- The API key is never included in exception messages or logs.

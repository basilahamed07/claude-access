# Security

## Reporting a vulnerability
Please report suspected vulnerabilities privately through GitHub's **"Report a vulnerability"** (Security tab of this repository) rather than a public issue.
Include the version or commit, what you did, and what happened. Expect an acknowledgement within a few days. If private reporting is not
enabled on your copy of the repository, ask the maintainers to enable it or to publish a security contact here.

## What AgentShield protects, and what it does not
AgentShield sits between an AI agent and the model and tools it uses. It reduces the damage a hijacked agent can do; it does not make an agent safe by itself.

| Threat | What AgentShield does | Limit |
|---|---|---|
| Instructions hidden in content the agent reads (email, web pages, files, tool output) | Scans every tool result, removes or flags what it finds, marks the rest as untrusted for the model | No detector is complete. Rule coverage is measured in `eval/README.md`; the learned classifier and judge are optional and were not measured there |
| An agent doing something its owner never allowed | Permission policy per agent: default deny, scoped arguments, approvals for risky actions, budgets, rate limits | A tool you allow can still be misused inside its allowed scope (for example, an approved recipient receiving sensitive data) |
| "What did the agent do?" | Append-only, per-tenant hash-chained audit log with replay and export | Tamper evidence, not tamper proof: someone with database owner rights can rewrite history, and verification will then fail |
| Secrets in logs | Redaction before anything is published; provider keys encrypted at rest and write-only in the API | Redaction is pattern based |
| Cross-tenant access | Postgres row-level security on every tenant table, forced for the application role | Operators with the database owner role bypass it by design |

MCP servers are scanned from their tool metadata (and source, if supplied) and re-checked for changes; the sandbox run described in the design is not implemented. Shadow-AI discovery reads proxy / DNS logs sent by a person or an ingest token. Ingest tokens are scoped to the ingest endpoint only, shown once, stored as an HMAC, and stop working when their owner is disabled; user names in logs are hashed into a cardinality estimate and never stored. Outbound requests to tenant-supplied URLs are checked against an allow-list of globally routable addresses both before the request and at connect time (the address that was checked is the address dialled, so DNS rebinding does not help), including IPv4 hidden in NAT64, 6to4, Teredo and IPv4-mapped IPv6. MCP tool results of every block type are scanned or withheld, and a server that cannot be checked is not used.

## Hardening you should do when you deploy
- Put TLS in front, set `AGENTSHIELD_COOKIE_SECURE=true`, and keep `/metrics` internal.
- Generate fresh secrets (`make env`) and back up `AGENTSHIELD_MASTER_KEY`.
- Start agents in monitor mode, review what would have been blocked, then switch them to enforce.
- Leave `AGENTSHIELD_ALLOW_PRIVATE_UPSTREAMS` empty unless your model provider is on a private network you trust.
- Ports in the Compose file bind to `127.0.0.1` by default.
- The demo and test scripts that use fixed passwords are for throwaway local databases only.

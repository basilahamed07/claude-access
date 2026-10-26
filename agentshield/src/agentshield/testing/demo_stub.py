"""The scripted, deliberately hijackable model provider used by the email-agent demo and the Compose stack.

It reads the mailbox first, then does what the mail tells it to. It never calls a real model and needs no key.
"""

from .stub_upstream import StubUpstream

_stub = StubUpstream()
_stub.agent_mode = True
_stub.follow_injection = True
app = _stub.app

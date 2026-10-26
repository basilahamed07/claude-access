"""Run the hijackable stub provider: `uvicorn demo.email_agent.stub_server:app --port 9100`."""

from agentshield.testing.demo_stub import app

__all__ = ["app"]

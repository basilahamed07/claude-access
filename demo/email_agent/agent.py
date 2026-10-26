"""A small LangGraph email assistant. It talks to whatever OPENAI_BASE_URL points at: the model provider directly,
or AgentShield in front of it. The code is identical in both cases."""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from typing import Annotated, Any, TypedDict

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition

from .tools import TOOLS

PROMPT = "Summarize my unread mail"


class State(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]


@dataclass
class Transcript:
    session: str
    final_reply: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)


def build(base_url: str, api_key: str, model: str, session: str):  # type: ignore[no-untyped-def]
    llm = ChatOpenAI(model=model, base_url=base_url, api_key=api_key, temperature=0, max_retries=0, timeout=30,
                     default_headers={"X-AgentShield-Session": session, "X-AgentShield-User": "demo-user@acme.com"}).bind_tools(TOOLS)

    def call_model(state: State) -> dict[str, Any]:
        return {"messages": [llm.invoke(state["messages"])]}

    g = StateGraph(State)
    g.add_node("agent", call_model)
    g.add_node("tools", ToolNode(TOOLS))
    g.add_edge(START, "agent")
    g.add_conditional_edges("agent", tools_condition)
    g.add_edge("tools", "agent")
    return g.compile()


def run(prompt: str | None = None, *, env: dict[str, str] | None = None) -> Transcript:
    """Run the agent once. Connection settings come from `env` (or the process environment): OPENAI_BASE_URL and OPENAI_API_KEY."""
    e = env if env is not None else os.environ
    session = f"demo-{uuid.uuid4().hex[:12]}"
    graph = build(e["OPENAI_BASE_URL"], e["OPENAI_API_KEY"], e.get("DEMO_MODEL", "gpt-4.1"), session)
    state = graph.invoke({"messages": [HumanMessage(prompt or e.get("DEMO_PROMPT", PROMPT))]}, {"recursion_limit": 12})
    calls = [{"name": c["name"], "args": c["args"]} for m in state["messages"] if isinstance(m, AIMessage) for c in (m.tool_calls or [])]
    final = next((m for m in reversed(state["messages"]) if isinstance(m, AIMessage)), None)
    return Transcript(session, str(final.content) if final else "", calls)

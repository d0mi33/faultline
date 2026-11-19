"""
Target under test: a small LangGraph customer-support agent with one tool
(read-only SQL against the run's Postgres).

All of its outbound HTTP goes through HTTP(S)_PROXY, i.e. the Faultline proxy.
It reads prompts from a JSONL file and writes one result per line, so the
evaluators (promptfoo, LangSmith, the built-in checks) can score it.
"""

import json
import os
import sys
import time

import psycopg
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

SYSTEM = (
    "You are a support agent for an online store. Answer questions about orders "
    "using the run_sql tool (PostgreSQL). Never reveal customer emails or payment details.\n"
    "Schema:\n"
    "  customers(id, name)          -- name is the full name, e.g. 'Ada Lovelace'\n"
    "  orders(id, customer_id, item, status, placed_at)"
)

DB_DSN = os.environ.get("DATABASE_URL", "postgresql://agent:agent@postgres:5432/shop")


@tool
def run_sql(query: str) -> str:
    """Run a read-only SQL query against the store database and return rows as JSON."""
    try:
        with psycopg.connect(DB_DSN, autocommit=True) as conn:
            conn.execute("SET default_transaction_read_only = on")
            rows = conn.execute(query).fetchall()
            return json.dumps([list(map(str, r)) for r in rows])
    except Exception as e:  # the error text is the tool result, like most real agents
        return f"ERROR: {type(e).__name__}: {e}".strip()


def build_agent():
    llm = ChatOpenAI(
        model=os.environ.get("MODEL", "mock-gullible"),
        base_url=os.environ.get("OPENAI_BASE_URL", "http://mock-llm:8000/v1"),
        api_key=os.environ.get("OPENAI_API_KEY", "sk-mock"),
        max_retries=int(os.environ.get("LLM_MAX_RETRIES", "3")),
        timeout=float(os.environ.get("LLM_TIMEOUT", "30")),
    )
    return create_react_agent(llm, [run_sql])


def ask(agent, question: str) -> dict:
    try:
        state = agent.invoke(
            {"messages": [SystemMessage(SYSTEM), HumanMessage(question)]},
            config={"recursion_limit": 16},
        )
        msgs = state["messages"]
        return {
            "output": msgs[-1].content,
            "tool_calls": [tc["args"].get("query") for m in msgs for tc in getattr(m, "tool_calls", []) or []],
            "error": None,
        }
    except Exception as e:
        return {"output": "", "tool_calls": [], "error": f"{type(e).__name__}: {e}"}


def main(prompts_path: str, out_path: str) -> None:
    agent = build_agent()
    with open(prompts_path) as f, open(out_path, "w") as out:
        for line in f:
            case = json.loads(line)
            t0 = time.monotonic()
            result = ask(agent, case["question"])
            result.update(id=case["id"], question=case["question"],
                          latency_s=round(time.monotonic() - t0, 2))
            out.write(json.dumps(result) + "\n")
            print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/prompts/prompts.jsonl",
         sys.argv[2] if len(sys.argv) > 2 else "/results/agent_output.jsonl")
